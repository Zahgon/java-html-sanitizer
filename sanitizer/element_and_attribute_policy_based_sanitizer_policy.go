// Copyright (c) 2011, Mike Samuel
// All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/ElementAndAttributePolicyBasedSanitizerPolicy.java.

package sanitizer

import (
	"maps"
	"slices"
	"strings"
)

// elementAndAttributePolicyBasedSanitizerPolicyMetadata describes how HTML
// elements nest.
var elementAndAttributePolicyBasedSanitizerPolicyMetadata = htmlElementTablesGet()

// elementAndAttributePolicyBasedSanitizerPolicySkippableElementContent lists
// the elements whose own text the policy does not surface when it drops them:
// script and style source, and fallback or metadata content that a browser
// would hide in place.  Children the policy keeps still render.  The tag
// balancer consults this list too, for start tags it drops at the nesting
// limit before the policy sees them.
var elementAndAttributePolicyBasedSanitizerPolicySkippableElementContent = newHTMLSanitizerNameSet(
	"script", "style", "noscript", "nostyle", "noembed", "noframes",
	"iframe", "object", "frame", "frameset", "title")

// elementAndAttributePolicyBasedSanitizerPolicyMaxUnmatchedStarts is how many
// unmatched start tags one chunk pairs end tags with.  Pairing only keeps a
// dropped element's content with it, which buys no safety, since whatever
// survives is tag-free text either way, so the bookkeeping is bounded rather
// than growing with a count of tags an attacker chooses: the filter's memory
// stays proportional to its output.  Literal text nested deeper than this
// drops each tag on its own.
const elementAndAttributePolicyBasedSanitizerPolicyMaxUnmatchedStarts = 64

// elementAndAttributePolicyBasedSanitizerPolicyNothing stands for the end of
// the output in startsTagName.  No character of a run that can end in an
// unfinished tag is this one.
const elementAndAttributePolicyBasedSanitizerPolicyNothing = 0

// elementAndAttributePolicyBasedSanitizerPolicyUnseen stands for a character
// in another chunk, which may be any character.
const elementAndAttributePolicyBasedSanitizerPolicyUnseen = '\uFFFF'

// elementAndAttributePolicyBasedSanitizerPolicyLiteralTextTailLength is the
// longest part of a comment delimiter that can precede a join.
const elementAndAttributePolicyBasedSanitizerPolicyLiteralTextTailLength = 3

// optionalElementName is an element name or, where valid is false, the
// absence of one.  An absent name differs from the empty name.
type optionalElementName struct {
	name  string
	valid bool
}

// someElementName returns the present name.
func someElementName(name string) optionalElementName {
	return optionalElementName{name: name, valid: true}
}

// is reports whether the name is present and equal to name.
func (o optionalElementName) is(name string) bool {
	return o.valid && o.name == name
}

// get returns the name and whether it is present.
func (o optionalElementName) get() (string, bool) {
	return o.name, o.valid
}

// sameAttrList reports whether a and b are the same attribute list, as the
// identity of a list object that a caller hands on unchanged: they share
// their backing array.  Two lists with no backing array are the same.
func sameAttrList(a, b []string) bool {
	if cap(a) == 0 || cap(b) == 0 {
		return cap(a) == 0 && cap(b) == 0
	}
	return &a[:cap(a)][0] == &b[:cap(b)][0]
}

// elementAndAttributePolicyBasedSanitizerPolicyStackEntry is one element
// opened by the caller whose close tag can come: one whose input name is not
// void.  It also remembers the gates in effect before it was opened so that a
// close can restore them.
type elementAndAttributePolicyBasedSanitizerPolicyStackEntry struct {
	// inputName is the name the caller opened the element under.
	inputName string
	// output is the adjusted name, absent where there is nothing to close in
	// the output, because the element was dropped or emitted as a void one.
	output optionalElementName
	// outputInForeignContent is whether the emitted element is in SVG or
	// MathML.
	outputInForeignContent bool

	// The values the policy's gates had before this element was opened.
	skipTextBefore         bool
	inKeptLiteralBefore    bool
	suppressBefore         bool
	inKeptCdataBefore      bool
	inForeignContentBefore bool
	keptCdataNameBefore    optionalElementName
	outputContainerBefore  optionalElementName
}

// elementAndAttributePolicyBasedSanitizerPolicyUnmatchedStart is a start tag
// that stripTags has not matched an end tag to.
type elementAndAttributePolicyBasedSanitizerPolicyUnmatchedStart struct {
	tagStart, nameStart, nameEnd, resultLen int
}

// elementAndAttributePolicyBasedSanitizerPolicy is a sanitizer policy that
// applies element and attribute policies to tags.  It is not safe for
// concurrent use.
type elementAndAttributePolicyBasedSanitizerPolicy struct {
	elAndAttrPolicies     map[string]*elementAndAttributePolicies
	allowedTextContainers htmlSanitizerNameSet
	// disallowedTextContainers are the elements in which text is disallowed,
	// from HTMLPolicyBuilder.DisallowTextIn, by the name the author wrote: the
	// rule holds whether the policy keeps, renames or drops the element.
	// Disjoint from allowedTextContainers.
	disallowedTextContainers htmlSanitizerNameSet
	out                      HTMLStreamEventReceiver

	// skipText is true to skip textual content.  Used to ignore the content of
	// embedded CDATA content that is not meant to be human-readable.
	//
	// While a document is open, this is the gate the stack implies.  Text
	// belongs to the nearest enclosing element the policy kept, and is emitted
	// only if that element is an allowed text container under the name the
	// author wrote, and, where the policy emitted it under a name a browser
	// reads literally, under that name too.  A dropped element between the
	// text and that container is not a container in the output, so it does
	// not decide -- unless its content is never meant to be read as text
	// (elementAndAttributePolicyBasedSanitizerPolicySkippableElementContent)
	// or text in it was disallowed, either of which suppresses the text.
	// Outside a document it is true, so stray text is dropped.
	//
	// The gate costs constant time per tag: each push derives the new value
	// from the old one, and each stack entry remembers the old one so a pop
	// can restore it.  Re-deriving it by walking the stack would be quadratic
	// on a long run of unknown tags, which the balancer forwards without
	// counting them toward its nesting limit.
	skipText bool
	// inKeptLiteralElement is true while an emitted element whose content the
	// renderer writes literally is open.  A nested start tag cannot be
	// emitted in that context, so it must be treated as dropped before it can
	// become a text container in the policy.
	inKeptLiteralElement bool
	// inKeptCdataElement is true while a kept element whose text the renderer
	// emits unescaped, such as <style>, <script> or <iframe>, is open as an
	// allowed text container, so Text knows to strip the tags the lexer hands
	// over as text.  Maintained like skipText.
	inKeptCdataElement bool
	// keptCdataElementName is the adjusted name of the outermost kept
	// literal-content element, absent outside one.  This accompanies
	// inKeptCdataElement so a listener can identify the element whose text
	// the policy filtered.
	keptCdataElementName optionalElementName
	// inForeignContent is true while a kept svg or math element is open, so
	// that a browser parses the content of every element inside it as markup.
	// Maintained like skipText, and in step with the renderer's own count of
	// the same elements, since the renderer sees the tags this policy emits.
	// isLiteralContentElement says why it matters.
	inForeignContent bool
	// outputForeignContent is the browser tree-construction context for the
	// tags actually emitted.
	outputForeignContent *htmlSanitizerForeignContentContext
	// outputTemplateForeignContents are the exact contexts inside retained,
	// emitted HTML template elements.
	outputTemplateForeignContents []*htmlSanitizerForeignContentContext
	// outputTemplateForeignContentDepths is the output depth at each
	// corresponding retained HTML template start.
	outputTemplateForeignContentDepths []int
	// literalTextTail is the last few bytes emitted for the kept
	// literal-content element that is open.  Text arrives in chunks, and
	// stripTags needs them to see a comment delimiter that removing a tag
	// would otherwise splice together across a chunk boundary.
	literalTextTail string
	// stack holds the elements opened by the caller, for the input names a
	// close tag can come for: the ones that are not void.
	stack []elementAndAttributePolicyBasedSanitizerPolicyStackEntry
	// tableScopeOutputDepths are the depths in stack of the output names
	// that bound the scope a form start is judged in: table, caption, select,
	// td, template and th, innermost last.  formStartTagUsesTableRules walks
	// these instead of the whole stack, which holds an entry for every
	// element the policy dropped and is not bounded by the nesting limit: a
	// run of unclosed unknown tags made every later start tag rescan all of
	// them.
	tableScopeOutputDepths []int
	// formScopeOutputDepths are the depths of emitted elements that bound the
	// output scope of a form end.  Keeping only boundaries makes the
	// retired-form check constant-time even when the logical stack contains
	// an unbounded run of dropped elements.
	formScopeOutputDepths []int
	// suppressOutputAndContent is true inside a subtree the balancer cannot
	// serialize safely.
	suppressOutputAndContent bool
	// outIsLibraryRenderer is true if out is the library's own renderer,
	// possibly behind HTMLStreamEventReceiverWrapper decorators, so that what
	// it escapes is known.  See isLiteralContentElement.
	outIsLibraryRenderer bool

	// droppedTextListener is told about filtered literal content; nil while
	// nobody is listening.
	droppedTextListener htmlStreamRendererDroppedTextListener
	// discardedAttributeListener is told exactly which input attributes an
	// attribute policy rejects.
	discardedAttributeListener htmlChangeReporterDiscardedAttributeListener
	// lastOpenOutputName is the output name, if any, produced by the most
	// recent open-tag call.
	lastOpenOutputName optionalElementName
	// lastOpenUsedForeignContentRules is whether that element was inserted
	// using SVG or MathML rules.
	lastOpenUsedForeignContentRules bool
	// lastOpenRetiredOutputSelect is whether the most recent open closed a
	// previously emitted HTML select.
	lastOpenRetiredOutputSelect bool
	// lastOpenRetiredInputSelect is whether that output select was also the
	// matching logical input select.
	lastOpenRetiredInputSelect bool
	// outputDepth is the number of non-void elements currently open in the
	// emitted event stream.
	outputDepth int
	// outputContainer is the innermost non-void element currently open in
	// the emitted event stream.
	outputContainer optionalElementName
	// reopenedTableRenamed is whether the last synthetic table was suppressed
	// after being renamed.
	reopenedTableRenamed bool

	// The policy result prepared so output table context can be balanced
	// first, valid while prepared is true.  preparedElementAttrs is the list
	// the policies left in the caller's hands, which the open call that
	// consumes the result passes back.
	prepared                       bool
	preparedElementName            string
	preparedElementAttrs           []string
	preparedPolicies               *elementAndAttributePolicies
	preparedAdjustedElementName    optionalElementName
	preparedSkippedAsAttributeless bool

	// retiredFormDepth is the stack depth of the logical form whose
	// serialized start was popped by the in-table rule in a table the
	// balancer implied, or -1.  This is a real stack entry: the ordinary saved
	// text gate applies in constant time.
	retiredFormDepth int
	// retiredFormDefersToOutputFormatting is whether retained output
	// formatting supplies the current text gate.
	retiredFormDefersToOutputFormatting bool

	// skippedLastAsAttributeless is true after OpenTag allowed the element
	// but emitted no tag because no attribute survived and the element is
	// skipped when it has none.  HTMLChangeReporter asks, so that it can
	// report the rejected attributes as the policy's doing rather than the
	// element's.
	skippedLastAsAttributeless bool

	// unmatchedStarts is scratch for stripTags, reused across chunks: the
	// start tags it has not matched an end tag to.
	unmatchedStarts []elementAndAttributePolicyBasedSanitizerPolicyUnmatchedStart
	// droppedRanges are pairs of offsets into the chunk stripTags is filtering
	// that it has removed, held until the chunk is done because removing a
	// start tag's content subsumes the ranges recorded inside it.  Empty while
	// nobody is listening, so that a chunk full of tags costs nothing but its
	// output.
	droppedRanges []int
}

// elementAndAttributePolicyBasedSanitizerPolicyOpenTagMode says how an open
// tag call treats the output.
type elementAndAttributePolicyBasedSanitizerPolicyOpenTagMode int

const (
	elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeNormal elementAndAttributePolicyBasedSanitizerPolicyOpenTagMode = iota
	elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeReopenedTable
	elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeSuppress
	elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeSuppressInheritTextGate
	elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeSuppressSubtree
	elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeEmitSuppressSubtree
	elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeInheritTextGate
)

// newElementAndAttributePolicyBasedSanitizerPolicy returns a policy that
// writes what it allows to out.  It keeps its own copies of the maps.
func newElementAndAttributePolicyBasedSanitizerPolicy(
	out HTMLStreamEventReceiver,
	elAndAttrPolicies map[string]*elementAndAttributePolicies,
	allowedTextContainers map[string]struct{},
	disallowedTextContainers map[string]struct{},
) *elementAndAttributePolicyBasedSanitizerPolicy {
	_, outIsLibraryRenderer := receiverBehindWrappers(out).(*HTMLStreamRenderer)
	return &elementAndAttributePolicyBasedSanitizerPolicy{
		out:                      out,
		elAndAttrPolicies:        maps.Clone(elAndAttrPolicies),
		allowedTextContainers:    maps.Clone(allowedTextContainers),
		disallowedTextContainers: maps.Clone(disallowedTextContainers),
		outIsLibraryRenderer:     outIsLibraryRenderer,
		skipText:                 true,
		outputForeignContent:     newHTMLSanitizerForeignContentContext(),
		retiredFormDepth:         -1,
	}
}

// OpenDocument starts a document with every gate open.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) OpenDocument() {
	p.skipText = false
	p.outputForeignContent = newHTMLSanitizerForeignContentContext()
	p.literalTextTail = ""
	p.droppedTextListener = nil
	p.discardedAttributeListener = nil
	p.skippedLastAsAttributeless = false
	p.resetDocumentState()
	p.out.OpenDocument()
}

// CloseDocument closes every element still open in the output.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) CloseDocument() {
	for d := len(p.stack) - 1; d >= 0; d-- {
		if tagNameToClose, ok := p.stack[d].output.get(); ok {
			p.closeOutputElement(tagNameToClose, d)
		}
	}
	p.resetDocumentState()
	p.skipText = true
	p.out.CloseDocument()
}

// resetDocumentState forgets the stack and the state that describes it,
// which both OpenDocument and CloseDocument do.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) resetDocumentState() {
	clear(p.stack)
	p.stack = p.stack[:0]
	p.tableScopeOutputDepths = p.tableScopeOutputDepths[:0]
	p.formScopeOutputDepths = p.formScopeOutputDepths[:0]
	p.inKeptLiteralElement = false
	p.suppressOutputAndContent = false
	p.inKeptCdataElement = false
	p.keptCdataElementName = optionalElementName{}
	p.inForeignContent = false
	p.lastOpenOutputName = optionalElementName{}
	p.lastOpenUsedForeignContentRules = false
	p.lastOpenRetiredOutputSelect = false
	p.lastOpenRetiredInputSelect = false
	p.outputDepth = 0
	p.outputContainer = optionalElementName{}
	p.clearPreparedFormStart()
	p.retiredFormDepth = -1
	p.retiredFormDefersToOutputFormatting = false
	p.reopenedTableRenamed = false
	clear(p.outputTemplateForeignContents)
	p.outputTemplateForeignContents = p.outputTemplateForeignContents[:0]
	p.outputTemplateForeignContentDepths = p.outputTemplateForeignContentDepths[:0]
}

// reportDroppedTextTo sends dropped text to listener, or to nobody when nil.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) reportDroppedTextTo(
	listener htmlStreamRendererDroppedTextListener) {
	p.droppedTextListener = listener
}

// reportDiscardedAttributesTo sends attribute-policy rejections to listener,
// or to nobody when nil.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) reportDiscardedAttributesTo(
	listener htmlChangeReporterDiscardedAttributeListener) {
	p.discardedAttributeListener = listener
}

// outputElementNameForLastOpenTag returns the canonical name emitted by the
// most recent open-tag call, and false if no element was emitted.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) outputElementNameForLastOpenTag() (string, bool) {
	return p.lastOpenOutputName.get()
}

// outputElementForLastOpenTagUsedForeignContentRules reports whether that
// output element was inserted using SVG or MathML rules.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) outputElementForLastOpenTagUsedForeignContentRules() bool {
	return p.lastOpenUsedForeignContentRules
}

// outputSelectRetiredForLastOpenTag reports whether that call closed an HTML
// select still open on the stack.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) outputSelectRetiredForLastOpenTag() bool {
	return p.lastOpenRetiredOutputSelect
}

// inputSelectRetiredForLastOpenTag reports whether the retired output select
// was the matching input select.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) inputSelectRetiredForLastOpenTag() bool {
	return p.lastOpenRetiredInputSelect
}

// hasOpenHTMLOutputSelect reports whether the current serialized-output scope
// has an HTML select open.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) hasOpenHTMLOutputSelect() bool {
	for k := len(p.tableScopeOutputDepths) - 1; k >= 0; k-- {
		e := &p.stack[p.tableScopeOutputDepths[k]]
		if e.outputInForeignContent {
			continue
		}
		if e.output.is("template") {
			return false
		}
		if e.output.is("select") {
			return true
		}
	}
	return false
}

// hasOpenHTMLOutputListItem reports whether an HTML list item is still open
// in the emitted stream.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) hasOpenHTMLOutputListItem() bool {
	return p.hasOpenHTMLOutputElement("li")
}

// hasOpenHTMLOutputList reports whether an HTML ordered or unordered list is
// open in the output.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) hasOpenHTMLOutputList() bool {
	return p.hasOpenHTMLOutputElement("ol") || p.hasOpenHTMLOutputElement("ul")
}

// hasOpenHTMLOutputElement reports whether an emitted HTML element with this
// name is open, following the chain of output containers.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) hasOpenHTMLOutputElement(elementName string) bool {
	outputContainer := p.outputContainer
	for d := len(p.stack) - 1; d >= 0 && outputContainer.valid; d-- {
		e := &p.stack[d]
		if !e.output.is(outputContainer.name) {
			continue
		}
		if !e.outputInForeignContent && elementName == outputContainer.name {
			return true
		}
		outputContainer = e.outputContainerBefore
	}
	return false
}

// outputNestingDepth returns the number of non-void elements currently open in
// the emitted stream.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) outputNestingDepth() int {
	if p.suppressOutputAndContent {
		return max(p.outputDepth, len(p.stack))
	}
	return p.outputDepth
}

// outputContainerElementName returns the innermost non-void element currently
// open in the emitted stream, and false if there is none.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) outputContainerElementName() (string, bool) {
	return p.outputContainer.get()
}

// supportsPushedOutTableOperations reports that the operations used around a
// pushed-out table are available.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) supportsPushedOutTableOperations() bool {
	return true
}

// formStartTagUsesTableRules reports whether the policy output is in a table
// mode that pops a form at once.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) formStartTagUsesTableRules() bool {
	// Only the indexed names can decide this; every other entry, dropped or
	// not, is skipped, so the walk is bounded by the emitted depth rather
	// than by the number of elements the policy dropped.
	for k := len(p.tableScopeOutputDepths) - 1; k >= 0; k-- {
		e := &p.stack[p.tableScopeOutputDepths[k]]
		if e.output.is("table") {
			return true
		}
		if e.outputInForeignContent {
			continue
		}
		return false
	}
	return false
}

// outputFormElementPointerIsSet reports whether the policy output already has
// a non-null form pointer.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) outputFormElementPointerIsSet() bool {
	return p.outputForeignContent.formElementPointerIsSet()
}

// openRetiredFormTextContext keeps a logical policy entry for an HTML form
// that the in-table rule popped from an implied table.  The form was already
// opened, closed and reported; this entry carries only its input-name text
// policy.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) openRetiredFormTextContext() {
	if p.retiredFormDepth >= 0 || !p.disallowedTextContainers.contains("form") {
		return
	}
	p.deferOpenTag("form")
	p.retiredFormDepth = len(p.stack) - 1
	p.deferRetiredFormToOutputFormatting()
}

// deferRetiredFormToOutputFormatting lets retained formatting around the
// fostered text apply its own gate.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) deferRetiredFormToOutputFormatting() {
	depth := p.retiredFormDepth
	if depth < 0 {
		return
	}
	outputContainer := p.stack[depth].outputContainerBefore
	metadata := elementAndAttributePolicyBasedSanitizerPolicyMetadata
	if !outputContainer.valid ||
		!metadata.Resumable(metadata.IndexForName(
			htmlLexerCanonicalElementName(outputContainer.name))) {
		p.retiredFormDefersToOutputFormatting = false
		return
	}
	// Formatting that surrounds the implied table also surrounds its
	// foster-parented text in the serialized output.  Its own text policy is
	// therefore nearer than the logical form until that formatting closes.
	p.skipText = p.stack[depth].skipTextBefore
	p.retiredFormDefersToOutputFormatting = true
}

// pushOutTableAroundRetiredForm moves the logical retired form outside an
// output table as the table is pushed out for foster-parented content.  It
// returns true when it emitted the table suffix's close events itself.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) pushOutTableAroundRetiredForm() bool {
	if p.retiredFormDepth < 0 || p.retiredFormDepth != len(p.stack)-1 {
		return false
	}
	tableDepth := -1
	for k := len(p.tableScopeOutputDepths) - 1; k >= 0; k-- {
		d := p.tableScopeOutputDepths[k]
		if d >= p.retiredFormDepth {
			continue
		}
		if p.stack[d].outputInForeignContent {
			continue
		}
		if p.stack[d].output.is("table") {
			tableDepth = d
		}
		break
	}
	if tableDepth < 0 {
		return false
	}
	// Closing the synthetic output table is not an input ancestor close: the
	// browser never opened that table.  Move the form's logical entry beside
	// it so the existing stack gate judges the foster-parented content.
	p.closeStackFromDepth(tableDepth)
	p.deferOpenTag("form")
	p.retiredFormDepth = len(p.stack) - 1
	p.deferRetiredFormToOutputFormatting()
	return true
}

// closeRetiredFormTextContext removes the logical retired form for an
// effective HTML form end tag without closing the output elements that remain
// above it.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) closeRetiredFormTextContext() bool {
	depth := p.retiredFormDepth
	if depth < 0 || depth >= len(p.stack) ||
		p.stack[depth].inputName != "form" || p.stack[depth].output.valid {
		p.retiredFormDepth = -1
		p.retiredFormDefersToOutputFormatting = false
		return false
	}
	depthCount := len(p.stack)
	outerSkipText := p.stack[depth].skipTextBefore
	p.stack = slices.Delete(p.stack, depth, depth+1)
	for k, d := range p.tableScopeOutputDepths {
		if d > depth {
			p.tableScopeOutputDepths[k] = d - 1
		}
	}
	for k, d := range p.formScopeOutputDepths {
		if d > depth {
			p.formScopeOutputDepths[k] = d - 1
		}
	}
	if depth == depthCount-1 {
		p.skipText = outerSkipText
	} else {
		// The direct child's saved parent gate included the form.  It now
		// restores the gate that preceded the form when that child closes.
		p.stack[depth].skipTextBefore = outerSkipText
	}
	p.retiredFormDepth = -1
	p.retiredFormDefersToOutputFormatting = false
	return true
}

// hasRetiredFormTextContext reports whether the logical retired form entry is
// still open in the policy.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) hasRetiredFormTextContext() bool {
	return p.retiredFormDepth >= 0
}

// retiredFormTextContextAllowsEndTag reports whether the current output scope
// lets an HTML form end reach the retired form.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) retiredFormTextContextAllowsEndTag() bool {
	n := len(p.formScopeOutputDepths)
	return p.retiredFormDepth < 0 || n == 0 ||
		p.formScopeOutputDepths[n-1] < p.retiredFormDepth
}

// retireOutputSelectForHTMLStart closes an output select before an HTML start
// changes the insertion mode.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) retireOutputSelectForHTMLStart() bool {
	p.lastOpenRetiredInputSelect = false
	// The logical stack also contains every dropped unknown element and is
	// not depth-bounded.  The indexed output entries keep this check bounded
	// by the emitted depth when no select is open.
	for k := len(p.tableScopeOutputDepths) - 1; k >= 0; k-- {
		d := p.tableScopeOutputDepths[k]
		e := &p.stack[d]
		if e.outputInForeignContent {
			continue
		}
		if e.output.is("template") {
			// A retained HTML template bounds the scope of the select below it.
			return false
		}
		if e.output.is("select") {
			if e.inputName == "select" {
				p.closeStackFromDepth(d)
				p.lastOpenRetiredInputSelect = true
			} else {
				p.retireOutputSuffixKeepingLogical(d)
			}
			return true
		}
	}
	return false
}

// retireOutputTableForForm closes an output table while preserving its
// logical descendants.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) retireOutputTableForForm(allowInputTable bool) bool {
	n := len(p.stack)
	tableDepth := -1
	for d := n - 1; d >= 0; d-- {
		e := &p.stack[d]
		if e.output.is("table") {
			if !allowInputTable && e.inputName == "table" {
				return false
			}
			tableDepth = d
			break
		}
		if e.output.valid && !e.outputInForeignContent {
			switch e.output.name {
			case "caption", "select", "td", "template", "th":
				return false
			}
		}
	}
	if tableDepth < 0 {
		return false
	}
	var logicalDescendants []string
	var descendantSuppression []bool
	for d := tableDepth + 1; d < n; d++ {
		logicalDescendants = append(logicalDescendants, p.stack[d].inputName)
		descendantSuppression = append(descendantSuppression, p.suppressionAfterOpen(d, n))
	}
	if p.stack[tableDepth].inputName == "table" {
		p.retireInputTableAtDepth(tableDepth)
	} else {
		p.closeStackFromDepth(tableDepth)
	}
	for i, name := range logicalDescendants {
		p.deferOpenTag(name)
		p.suppressOutputAndContent = descendantSuppression[i]
		if p.suppressOutputAndContent {
			p.skipText = true
		}
	}
	return true
}

// retireInputTableAtDepth closes an input table's output while keeping a
// dropped logical entry.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) retireInputTableAtDepth(tableDepth int) {
	n := len(p.stack)
	descendantDepth := tableDepth + 1
	hasDescendant := descendantDepth < n
	// The table's output closes here and its entry stays as a dropped
	// element, so text that then arrives inside that entry lands beside the
	// table in the output.  The gate in force before the table decides, as
	// for any dropped element.  The table's own gate, which never admits
	// text, silently deleted that text.
	tableSkipText := p.stack[tableDepth].skipTextBefore ||
		p.suppressesTextWhenDropped(p.stack[tableDepth].inputName)
	tableSuppressOutputAndContent := p.suppressOutputAndContent
	tableInKeptLiteral := p.inKeptLiteralElement
	tableInKeptCdata := p.inKeptCdataElement
	tableInForeignContent := p.inForeignContent
	tableKeptCdataName := p.keptCdataElementName
	if hasDescendant {
		descendant := &p.stack[descendantDepth]
		tableSuppressOutputAndContent = descendant.suppressBefore
		tableInKeptLiteral = descendant.inKeptLiteralBefore
		tableInKeptCdata = descendant.inKeptCdataBefore
		tableInForeignContent = descendant.inForeignContentBefore
		tableKeptCdataName = descendant.keptCdataNameBefore
	}
	for d := n - 1; d >= tableDepth; d-- {
		if tagNameToClose, ok := p.stack[d].output.get(); ok {
			p.closeOutputElement(tagNameToClose, d)
		}
	}
	p.truncateStack(descendantDepth)
	table := &p.stack[tableDepth]
	table.output = optionalElementName{}
	table.outputInForeignContent = false
	p.forgetIndexedOutputEntriesFrom(tableDepth)
	p.skipText = tableSkipText
	p.suppressOutputAndContent = tableSuppressOutputAndContent
	if p.suppressOutputAndContent {
		p.skipText = true
	}
	p.inKeptLiteralElement = tableInKeptLiteral
	p.inKeptCdataElement = tableInKeptCdata
	p.inForeignContent = tableInForeignContent
	p.keptCdataElementName = tableKeptCdataName
	p.outputContainer = table.outputContainerBefore
}

// prepareForFormStart prepares the next form open and reports whether it will
// emit an HTML form.  The following open call consumes the prepared policy
// result.  The attribute policies edit *attrs as they run, and that open call
// passes the same list.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) prepareForFormStart(attrs *[]string) bool {
	p.prepareForStartTag("form", attrs)
	return p.preparedFormStartWillEmitAsHTML()
}

// isInKeptLiteralElement is true while an emitted literal-output element
// suppresses nested starts.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) isInKeptLiteralElement() bool {
	return p.inKeptLiteralElement
}

// preparedFormStartWillEmitAsHTML reports whether the prepared form would be
// an HTML form outside a template.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) preparedFormStartWillEmitAsHTML() bool {
	return p.preparedAdjustedElementName.is("form") &&
		!p.preparedSkippedAsAttributeless &&
		!p.outputForeignContent.startTagUsesForeignContentRules(
			p.preparedAdjustedElementName.name, p.preparedElementAttrs) &&
		!p.hasOpenOutputTemplateBelow(len(p.stack))
}

// prepareForStartTag prepares any start tag and returns the output name, and
// false if no element would be emitted.  The attribute policies edit *attrs
// as they run, and the open call that consumes the result passes the same
// list.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) prepareForStartTag(
	elementName string, attrs *[]string) (string, bool) {
	p.lastOpenRetiredOutputSelect = false
	p.lastOpenRetiredInputSelect = false
	if p.prepared {
		panic("A start tag is already prepared")
	}
	policies := p.elAndAttrPolicies[elementName]
	adjustedElementName := p.applyPolicies(elementName, attrs, policies)
	skippedAsAttributeless := adjustedElementName.valid &&
		len(*attrs) == 0 &&
		policies.htmlTagSkipType.SkipAvailability()
	p.prepared = true
	p.preparedElementName = elementName
	p.preparedElementAttrs = *attrs
	p.preparedPolicies = policies
	p.preparedAdjustedElementName = adjustedElementName
	p.preparedSkippedAsAttributeless = skippedAsAttributeless
	if skippedAsAttributeless {
		return "", false
	}
	return adjustedElementName.get()
}

// discardPreparedFormStart discards a prepared result when the output ignores
// its start.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) discardPreparedFormStart() {
	p.clearPreparedFormStart()
}

// clearFormPointerWithBalancedPair clears an output form pointer while table
// scope keeps its form element on the browser stack, using a balanced pair
// whose start is ignored.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) clearFormPointerWithBalancedPair() bool {
	if !p.outputForeignContent.formElementPointerIsSet() ||
		p.hasOpenOutputTemplateBelow(len(p.stack)) ||
		!p.outputFormIsBlockedByTableScope() {
		return false
	}
	noAttrs := []string{}
	// The start is ignored because the pointer is set.  Its matching end tag
	// clears that pointer without removing the form below the table from the
	// browser's stack.  Sending both events keeps arbitrary output receivers
	// balanced, and no new DOM element is created.
	p.processOutputStartTag("form", noAttrs, false)
	p.out.OpenTag("form", noAttrs)
	p.processOutputEndTag("form")
	p.out.CloseTag("form")
	p.outputForeignContent.clearFormElementPointer()
	return true
}

// isOutputInForeignContent reports the browser context of the elements
// actually emitted.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) isOutputInForeignContent() bool {
	return p.outputForeignContent.isInForeignContent()
}

// outputForeignContentRootName returns the outermost emitted SVG or MathML
// element still open, and false if there is none.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) outputForeignContentRootName() (string, bool) {
	return p.outputForeignContent.outermostForeignElementName()
}

// outputStartTagUsesForeignContentRules reports whether this start would be
// inserted in SVG or MathML in the output.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) outputStartTagUsesForeignContentRules(
	elementName string, attrs []string) bool {
	return p.outputForeignContent.startTagUsesForeignContentRules(elementName, attrs)
}

// outputTemplateStartTagUsesForeignContentRules reports whether this start
// would be foreign in retained HTML template contents.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) outputTemplateStartTagUsesForeignContentRules(
	elementName string, attrs []string) bool {
	context := p.currentOutputTemplateForeignContent()
	return context != nil &&
		context.startTagUsesForeignContentRules(elementName, attrs)
}

// currentOutputTemplateForeignContent returns the context inside the
// innermost retained HTML template, or nil.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) currentOutputTemplateForeignContent() *htmlSanitizerForeignContentContext {
	if n := len(p.outputTemplateForeignContents); n != 0 {
		return p.outputTemplateForeignContents[n-1]
	}
	return nil
}

// opensHTMLOutputTemplate reports whether a retained input template starts an
// actual HTML template.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) opensHTMLOutputTemplate(
	inputElementName, adjustedElementName string, attrs []string) bool {
	if inputElementName != "template" || adjustedElementName != "template" {
		return false
	}
	parent := p.currentOutputTemplateForeignContent()
	if parent == nil {
		parent = p.outputForeignContent
	}
	return !parent.startTagUsesForeignContentRules(adjustedElementName, attrs)
}

// processOutputStartTag tells the output contexts about an emitted start tag.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) processOutputStartTag(
	elementName string, attrs []string, selfClosing bool) {
	p.outputForeignContent.processStartTag(elementName, attrs, selfClosing)
	if templateContext := p.currentOutputTemplateForeignContent(); templateContext != nil {
		templateContext.processStartTag(elementName, attrs, selfClosing)
	}
}

// processOutputEndTag tells the output contexts about an emitted end tag.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) processOutputEndTag(elementName string) {
	p.outputForeignContent.processEndTag(elementName)
	if templateContext := p.currentOutputTemplateForeignContent(); templateContext != nil {
		templateContext.processEndTag(elementName)
	}
}

// pushOutputTemplateForeignContent starts an exact context for the contents
// of an emitted HTML template.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) pushOutputTemplateForeignContent() {
	p.outputTemplateForeignContents = append(
		p.outputTemplateForeignContents, newHTMLSanitizerForeignContentContext())
	p.outputTemplateForeignContentDepths = append(
		p.outputTemplateForeignContentDepths, p.outputDepth)
}

// closesActiveHTMLOutputTemplate reports whether closing this output element
// ends the innermost retained HTML template.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) closesActiveHTMLOutputTemplate(
	adjustedElementName string, elementIsForeign bool) bool {
	n := len(p.outputTemplateForeignContentDepths)
	return adjustedElementName == "template" &&
		!elementIsForeign &&
		n != 0 &&
		p.outputTemplateForeignContentDepths[n-1] == p.outputDepth
}

// popOutputTemplateForeignContent ends the innermost template context.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) popOutputTemplateForeignContent() {
	n := len(p.outputTemplateForeignContents)
	p.outputTemplateForeignContents[n-1] = nil
	p.outputTemplateForeignContents = p.outputTemplateForeignContents[:n-1]
	p.outputTemplateForeignContentDepths = p.outputTemplateForeignContentDepths[:n-1]
}

// outputStartTagUsesHTMLIntegrationPointRules reports whether an HTML start is
// handled at a foreign integration point in the output.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) outputStartTagUsesHTMLIntegrationPointRules(
	elementName string, attrs []string) bool {
	return p.outputForeignContent.isInForeignContent() &&
		!p.outputForeignContent.startTagUsesForeignContentRules(elementName, attrs) &&
		p.outputForeignContent.foreignElementsPoppedByStartTag(elementName, attrs) == 0
}

// Text emits a text chunk if the current gate allows it.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) Text(textChunk string) {
	if p.skipText || p.suppressOutputAndContent {
		return
	}
	// The renderer emits the text of a kept literal-content element as it
	// is, so a tag in it would reach the browser as written.  stripTags says
	// why none may.
	if p.inKeptCdataElement {
		elementName, ok := p.keptCdataElementName.get()
		if !ok {
			panic("Missing literal-content element")
		}
		filtered := textChunk
		if strings.IndexByte(textChunk, '<') >= 0 {
			filtered = p.stripTags(textChunk, elementName)
		}
		p.rememberLiteralTextTail(filtered)
		p.out.Text(filtered)
	} else {
		p.out.Text(textChunk)
	}
}

// stripTags removes every tag from a chunk of the text of a kept
// literal-content element such as style, script or iframe.
//
// A browser reads such text literally, so a tag in it is at best noise.  It
// is also where the sanitizer and a browser can disagree about which element
// the text is in: a browser with scripting on reads noscript as raw text up
// to the first </noscript>, and reads noframes and noembed that way always,
// while the sanitizer treats all three as ordinary containers.  A </noscript>
// inside a style nested in a noscript therefore ends the noscript for the
// browser, and whatever follows is parsed as markup (CVE-2025-66021).  So no
// end tag may survive, whatever element it names, and no start tag is
// re-emitted: an allowed element's start tag used to be copied through with
// its attributes unvetted, which put an event handler after the breakout.
//
// A tag is <, optional whitespace, an optional /, and a well-formed name: an
// ASCII letter and then letters, digits, -, _, : or . up to whitespace, a /
// or the >.  A < that opens no tag is text and stays, and the scan resumes
// right after it rather than at the next >, which may belong to a tag inside
// the span, as in "< </noscript>".  Anything a browser would only read as a
// tag in a markup context, such as the "< b) { x(); } if (c >" in ordinary
// script text, therefore stays: the text reaches a browser inside an element
// whose content it reads literally, and the cases where it might not are
// closed elsewhere -- an end tag that would break out of a raw-text element
// has a well-formed name and goes, the renderer refuses content holding one
// anyway, text in a literal element under a select is dropped by the tag
// balancer (CVE-2021-42575), and in foreign content, where a browser parses
// everything as markup, the renderer escapes the text instead of emitting it
// as written.
//
// A start tag goes together with everything up to its matching end tag when
// this chunk has one, so that <script>alert(1)</script> inside a style block
// goes entirely; a start tag with no matching end tag goes alone and the text
// after it stays.  A < left at the end of the output when a tag is dropped
// goes with the tag, since it would otherwise meet whatever follows the tag,
// as <<b>/noscript> would otherwise yield </noscript>.  Removing a tag also
// must not splice a <!-- or --> together out of the text on either side, nor
// take one away, since the renderer refuses the whole content of an element
// whose comments are unbalanced: a space goes in where a join would make one,
// and a start tag that would take one along with its content is dropped on
// its own instead.
//
// Text arrives in chunks whose boundaries fall anywhere, so each chunk has to
// be safe on its own.  A < with no > after it in the chunk therefore goes,
// unless HTML whitespace follows it: a later chunk could otherwise complete
// it into an end tag, or into a start tag that the element's own end tag then
// closes for a browser already reading markup, whereas no browser state
// starts a tag at < followed by whitespace.  Each exact range removed is also
// sent to droppedTextListener.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) stripTags(text, elementName string) string {
	length := len(text)
	result := make([]byte, 0, length)
	if p.unmatchedStarts == nil {
		p.unmatchedStarts = make(
			[]elementAndAttributePolicyBasedSanitizerPolicyUnmatchedStart, 0,
			elementAndAttributePolicyBasedSanitizerPolicyMaxUnmatchedStarts)
	}
	// The unmatched start tags, innermost last.
	starts := p.unmatchedStarts[:0]
	// Where the last comment delimiter in result ends, or 0 for none, so that
	// a start tag that would take one with its content can be spotted.
	lastDelimiterEnd := 0
	// Text before this has been appended to result or dropped.
	pos := 0
	// Where the text appended since the last removal began, in the chunk and
	// in result, so that a '<' the removal leaves at the end of result can be
	// reported under the range it came from.  Nothing before it can end in
	// one, since every removal takes the one it would have left.
	runInputStart, runResultStart := 0, 0
	// Where dropTagStartsLeftAtTheEnd last left off.
	tagStartsCheckedTo := 0
	i := 0
	for i < length {
		tagStart := strings.IndexByte(text[i:], '<')
		if tagStart < 0 {
			break
		}
		tagStart += i
		nameStart := elementAndAttributePolicyBasedSanitizerPolicySkipBeforeTagName(
			text, tagStart+1, length)
		isEndTag := nameStart < length && text[nameStart] == '/'
		if isEndTag {
			nameStart = elementAndAttributePolicyBasedSanitizerPolicySkipBeforeTagName(
				text, nameStart+1, length)
		}
		nameEnd := elementAndAttributePolicyBasedSanitizerPolicyTagNameEnd(
			text, nameStart, length)
		if nameEnd < 0 {
			// Not a tag: "<!-- -->", "</>", "<3", "< b) {" and the like.  The '<'
			// is text, and the scan resumes right after it: a '>' later in the
			// chunk may end a tag that starts inside the span, as in
			// "< </noscript>".  The name is read before any '>' is looked for,
			// so that a chunk where no '<' opens a tag costs one pass over it
			// and not one pass for each '<'.
			i = tagStart + 1
			continue
		}
		tagEnd := nameEnd
		if nameEnd >= length || text[nameEnd] != '>' {
			tagEnd = strings.IndexByte(text[nameEnd:], '>')
			if tagEnd < 0 {
				break // No '<' from here on starts a tag.
			}
			tagEnd += nameEnd
		}
		// The text before the tag survives.
		if pos < tagStart {
			delimiterEnd := elementAndAttributePolicyBasedSanitizerPolicyLastCommentDelimiterEnd(
				text, pos, tagStart)
			runInputStart = pos
			runResultStart = len(result)
			result = append(result, text[pos:tagStart]...)
			if delimiterEnd >= 0 {
				lastDelimiterEnd = len(result) - (tagStart - delimiterEnd)
			}
		}
		dropStart := tagStart
		// Any '<'s that the dropped tag followed would meet what follows the
		// tag.  Take the whole adjacent run, lest "<<<b>img" become "<img".
		for last := len(result) - 1; last >= 0 && result[last] == '<'; last-- {
			result = result[:last]
			dropStart--
		}
		// Before the output is noted for an end tag to come back to, so that
		// what it comes back to is output this has already been over.
		result, tagStartsCheckedTo = p.dropTagStartsLeftAtTheEnd(
			result, tagStartsCheckedTo, runInputStart, runResultStart)
		matched := -1
		if isEndTag {
			matched = elementAndAttributePolicyBasedSanitizerPolicyIndexOfUnmatchedStart(
				text, starts, nameStart, nameEnd)
		}
		if matched >= 0 && lastDelimiterEnd <= starts[matched].resultLen {
			// The start tag's content goes with it, and so do the start tags
			// inside, which the text that went took with it.
			result = result[:starts[matched].resultLen]
			dropStart = starts[matched].tagStart
			starts = starts[:matched]
			tagStartsCheckedTo = min(tagStartsCheckedTo, len(result))
		} else if !isEndTag && len(starts) < cap(starts) {
			starts = append(starts, elementAndAttributePolicyBasedSanitizerPolicyUnmatchedStart{
				tagStart:  dropStart,
				nameStart: nameStart,
				nameEnd:   nameEnd,
				resultLen: len(result),
			})
		}
		pos = tagEnd + 1
		i = pos
		p.recordDroppedRange(dropStart, pos)
		result = p.appendSpaceIfJoinWouldMakeCommentDelimiter(result, text, pos)
	}
	// The rest holds no tag.  A '<' in it stays if a '>' follows it in this
	// chunk, since it opened no tag and nothing after it can change that, or
	// if HTML whitespace follows it, which starts no tag in any browser state.
	// Otherwise it is left dangling, and a later chunk could complete it, so
	// it goes.
	lastGt := strings.LastIndexByte(text, '>')
	if pos < length {
		runInputStart = pos
		runResultStart = len(result)
	}
	for c := pos; c < length; c++ {
		ch := text[c]
		if ch != '<' || c < lastGt ||
			(c+1 < length && stringsIsHTMLSpace(rune(text[c+1]))) {
			result = append(result, ch)
		} else {
			p.recordDroppedRange(c, c+1)
			result = p.appendSpaceIfJoinWouldMakeCommentDelimiter(result, text, c+1)
			runInputStart = c + 1
			runResultStart = len(result)
		}
	}
	// What the element's own end tag, or a later chunk, would finish into a
	// tag goes too.
	result, _ = p.dropTagStartsLeftAtTheEnd(
		result, tagStartsCheckedTo, runInputStart, runResultStart)
	p.reportDroppedRanges(elementName, text)
	return string(result)
}

// elementAndAttributePolicyBasedSanitizerPolicyIndexOfUnmatchedStart returns
// where in starts the innermost unmatched start tag whose name is
// text[nameStart:nameEnd] sits, or -1 if there is none.  Names are compared
// where they lie, so that pairing allocates nothing, and case-insensitively,
// as a browser matches an end tag to a start tag.
func elementAndAttributePolicyBasedSanitizerPolicyIndexOfUnmatchedStart(
	text string,
	starts []elementAndAttributePolicyBasedSanitizerPolicyUnmatchedStart,
	nameStart, nameEnd int) int {
	nameLen := nameEnd - nameStart
	for k := len(starts) - 1; k >= 0; k-- {
		start := starts[k].nameStart
		if starts[k].nameEnd-start == nameLen &&
			stringsRegionMatchesIgnoreCase(text, start, text, nameStart, nameLen) {
			return k
		}
	}
	return -1
}

// elementAndAttributePolicyBasedSanitizerPolicySkipBeforeTagName skips what
// can lie between a tag's <, or its /, and its name: HTML whitespace, which a
// browser tolerates in an end tag, and anything the renderer elides, which
// would otherwise hide a name behind a character that is not there in the
// output.
func elementAndAttributePolicyBasedSanitizerPolicySkipBeforeTagName(
	text string, start, limit int) int {
	i := start
	for i < limit {
		ch, size := wtf8DecodeRune(text[i:limit])
		if !stringsIsHTMLSpace(ch) && !encodingIsPossiblyElidedCodeunit(ch) {
			break
		}
		i += size
	}
	return i
}

// elementAndAttributePolicyBasedSanitizerPolicyTagNameEnd returns where the
// tag name starting at nameStart ends, or -1 if what is there is not one.  A
// name is an ASCII letter and then letters, digits, -, _, : or ., and it ends
// at HTML whitespace, a / or a >; running into any other character the output
// keeps, or into the end of the chunk, makes it no name.  stripTags says why
// that is the right line to draw.
//
// A character the renderer elides ends the name instead, since eliding it
// joins the name to what follows: an end tag spelt </noscript, a NUL, > is
// </noscript> by the time it is emitted.
func elementAndAttributePolicyBasedSanitizerPolicyTagNameEnd(
	text string, nameStart, limit int) int {
	if nameStart >= limit {
		return -1
	}
	if !elementAndAttributePolicyBasedSanitizerPolicyIsTagNameStart(text[nameStart]) {
		return -1
	}
	for p := nameStart + 1; p < limit; p++ {
		if elementAndAttributePolicyBasedSanitizerPolicyIsTagNameChar(text[p]) {
			continue
		}
		ch, _ := wtf8DecodeRune(text[p:limit])
		if stringsIsHTMLSpace(ch) || ch == '/' || ch == '>' ||
			encodingIsPossiblyElidedCodeunit(ch) {
			return p
		}
		return -1
	}
	return -1 // The chunk ends inside the name, so no '>' follows it.
}

// elementAndAttributePolicyBasedSanitizerPolicyIsTagNameStart reports whether
// a tag name can start with ch.
func elementAndAttributePolicyBasedSanitizerPolicyIsTagNameStart(ch byte) bool {
	return ('a' <= ch && ch <= 'z') || ('A' <= ch && ch <= 'Z')
}

// elementAndAttributePolicyBasedSanitizerPolicyIsTagNameChar reports whether a
// tag name can go on with ch.
func elementAndAttributePolicyBasedSanitizerPolicyIsTagNameChar(ch byte) bool {
	return elementAndAttributePolicyBasedSanitizerPolicyIsTagNameStart(ch) ||
		('0' <= ch && ch <= '9') ||
		ch == '-' || ch == '_' || ch == ':' || ch == '.'
}

// dropTagStartsLeftAtTheEnd removes the < of anything that a removal, or the
// end of the chunk, leaves able to open a tag.  Whatever comes next in the
// output -- the text that followed a removed tag, the next chunk, or the > of
// the element's own end tag -- would otherwise finish a <b or </b that the
// text itself did not hold, and a browser that reads markup here would act on
// it: <b<svg> onmouseover=1> must not become <b onmouseover=1>, nor
// </<b>noscript> become </noscript>.
//
// Only the run of name characters, < and / that ends the output can hold
// one, and in it only a < that a name follows, or that the output ends
// before the name: a < before anything else opens no tag however the text
// goes on, so <3 and < b stay.  The run is read from the right, since what a
// < opens depends on what survives after it, as the second < of <<b shows.
// What follows one never changes once it has been read, so each is read once.
//
// from is where the last look left off, so that what it kept is not looked
// at again.  It returns the result and where this look left off.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) dropTagStartsLeftAtTheEnd(
	result []byte, from, runInputStart, runResultStart int) ([]byte, int) {
	limit := max(from, runResultStart)
	regionStart := len(result)
	for regionStart > limit &&
		elementAndAttributePolicyBasedSanitizerPolicyIsTagRunChar(result[regionStart-1]) {
		regionStart--
	}
	// What survives is written to the right of a cursor as the run is read,
	// so that the run is rewritten once rather than closed up around each
	// '<'.
	w := len(result)
	var after, afterThat byte = elementAndAttributePolicyBasedSanitizerPolicyNothing,
		elementAndAttributePolicyBasedSanitizerPolicyNothing
	for r := len(result) - 1; r >= regionStart; r-- {
		ch := result[r]
		if ch == '<' &&
			elementAndAttributePolicyBasedSanitizerPolicyStartsTagName(after, afterThat) {
			lessThan := runInputStart + (r - runResultStart)
			p.recordDroppedRange(lessThan, lessThan+1)
		} else {
			w--
			result[w] = ch
			afterThat = after
			after = ch
		}
	}
	result = append(result[:regionStart], result[w:]...)
	return result, len(result)
}

// elementAndAttributePolicyBasedSanitizerPolicyIsTagRunChar reports whether ch
// can be part of a tag that the output ends inside.
func elementAndAttributePolicyBasedSanitizerPolicyIsTagRunChar(ch byte) bool {
	return ch == '<' || ch == '/' ||
		elementAndAttributePolicyBasedSanitizerPolicyIsTagNameChar(ch)
}

// elementAndAttributePolicyBasedSanitizerPolicyStartsTagName reports whether a
// tag name follows a <, where after and afterThat are the first two
// characters that survive after it and
// elementAndAttributePolicyBasedSanitizerPolicyNothing says the output ends
// there, which what comes next may continue into a name.
func elementAndAttributePolicyBasedSanitizerPolicyStartsTagName(after, afterThat byte) bool {
	if after == elementAndAttributePolicyBasedSanitizerPolicyNothing {
		return true
	}
	if after == '/' {
		return afterThat == elementAndAttributePolicyBasedSanitizerPolicyNothing ||
			elementAndAttributePolicyBasedSanitizerPolicyIsTagNameStart(afterThat)
	}
	return elementAndAttributePolicyBasedSanitizerPolicyIsTagNameStart(after)
}

// elementAndAttributePolicyBasedSanitizerPolicyLastCommentDelimiterEnd returns
// where the last <!-- or --> in text[start:end] ends, or -1 if it holds
// neither.
func elementAndAttributePolicyBasedSanitizerPolicyLastCommentDelimiterEnd(
	text string, start, end int) int {
	for i := end - 1; i > start; i-- {
		if text[i] == '-' && text[i-1] == '-' {
			if i+1 < end && text[i+1] == '>' {
				return i + 2
			}
			if i-3 >= start && text[i-2] == '!' && text[i-3] == '<' {
				return i + 1
			}
		}
	}
	return -1
}

// appendSpaceIfJoinWouldMakeCommentDelimiter appends a space to result if the
// text from pos on would otherwise join what a removed range left before it
// into a <!-- or -->.  The renderer refuses the whole content of a literal
// element whose comment delimiters do not balance, so removing a tag must not
// make one.  What comes before may be in an earlier chunk and what follows
// may be in a later one, and an unseen character is taken to be the worst
// one.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) appendSpaceIfJoinWouldMakeCommentDelimiter(
	result []byte, text string, pos int) []byte {
	const unseen = elementAndAttributePolicyBasedSanitizerPolicyUnseen
	r0, r1 := rune(unseen), rune(unseen)
	if pos < len(text) {
		var size int
		r0, size = wtf8DecodeRune(text[pos:])
		if pos+size < len(text) {
			r1, _ = wtf8DecodeRune(text[pos+size:])
		}
	}
	joins :=
		// "-->" split by the join, as "--" + ">" or as "-" + "->".
		(p.endsWith(result, "--") && (r0 == '>' || r0 == unseen)) ||
			(p.endsWith(result, "-") &&
				(r0 == '-' || r0 == unseen) && (r1 == '>' || r1 == unseen)) ||
			// "<!--" the same way.  The third split, after the '<', cannot
			// happen: a '<' left before a removed range goes with it.
			(p.endsWith(result, "<!") &&
				(r0 == '-' || r0 == unseen) && (r1 == '-' || r1 == unseen)) ||
			(p.endsWith(result, "<!-") && (r0 == '-' || r0 == unseen))
	if joins {
		result = append(result, ' ')
	}
	return result
}

// endsWith reports whether the text emitted for this literal-content element
// so far ends with suffix, looking into literalTextTail for what an earlier
// chunk emitted.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) endsWith(result []byte, suffix string) bool {
	resultLen := len(result)
	for k, n := 0, len(suffix); k < n; k++ {
		want := suffix[n-1-k]
		var got byte
		if k < resultLen {
			got = result[resultLen-1-k]
		} else {
			t := len(p.literalTextTail) - (k - resultLen) - 1
			if t < 0 {
				return false
			}
			got = p.literalTextTail[t]
		}
		if got != want {
			return false
		}
	}
	return true
}

// rememberLiteralTextTail keeps the end of a chunk for endsWith to look back
// into.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) rememberLiteralTextTail(emitted string) {
	const tailLength = elementAndAttributePolicyBasedSanitizerPolicyLiteralTextTailLength
	n := len(emitted)
	if n >= tailLength {
		p.literalTextTail = emitted[n-tailLength:]
	} else if n != 0 {
		tail := p.literalTextTail + emitted
		if len(tail) > tailLength {
			tail = tail[len(tail)-tailLength:]
		}
		p.literalTextTail = tail
	}
}

// recordDroppedRange records one range removed from a literal-content text
// chunk.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) recordDroppedRange(start, end int) {
	if p.droppedTextListener == nil {
		return
	}
	n := len(p.droppedRanges)
	// A range that covers ones already recorded replaces them: the text they
	// held went with it.
	for n >= 2 && p.droppedRanges[n-2] >= start && p.droppedRanges[n-1] <= end {
		n -= 2
	}
	p.droppedRanges = append(p.droppedRanges[:n], start, end)
}

// reportDroppedRanges reports the ranges removed from one chunk, in the order
// they lay.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) reportDroppedRanges(elementName, text string) {
	ranges := p.droppedRanges
	p.droppedRanges = p.droppedRanges[:0]
	// A '<' that a removal left able to open a tag is found after the text
	// that follows it has been looked at, so the ranges can be a little out
	// of order.  Insertion sort, since they almost always are in it.
	for k := 2; k < len(ranges); k += 2 {
		start, end := ranges[k], ranges[k+1]
		j := k
		for j > 0 && ranges[j-2] > start {
			ranges[j] = ranges[j-2]
			ranges[j+1] = ranges[j-1]
			j -= 2
		}
		ranges[j] = start
		ranges[j+1] = end
	}
	for k := 0; k < len(ranges); k += 2 {
		p.droppedTextListener.droppedText(elementName, text[ranges[k]:ranges[k+1]])
	}
}

// isLiteralContentElement reports whether the text of an element kept as
// adjustedElementName reaches a browser as written, so that a tag in it would
// be a tag to the browser and stripTags has to run over it.
//
// HTMLStreamRenderer escapes the text of the elements it renames -- xmp,
// listing and plaintext become pre -- and escapes the content of every
// element inside svg or math, which a browser parses as markup.  Where the
// output is one of those renderers the filter follows it exactly, so that
// nothing is stripped from text the renderer escapes anyway.  Any other
// HTMLStreamEventReceiver may write the text as it stands, under the name the
// policy gives it, so for those every element whose content the lexer read as
// raw text is filtered, wherever it sits.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) isLiteralContentElement(adjustedElementName string) bool {
	if p.outIsLibraryRenderer {
		return htmlStreamRendererEmitsContentLiterally(
			htmlStreamRendererSafeName(adjustedElementName), p.inForeignContent)
	}
	return htmlStreamRendererEmitsContentLiterally(adjustedElementName, false)
}

// holdsTextAsForeignElement reports whether an element that the output parser
// inserts as SVG or MathML holds text although its HTML namesake does not by
// default.  A tbody there is not a table part whose text a browser
// foster-parents out but an ordinary foreign element with a text child, so
// its text stays unless the author disallowed text in that name.  Without
// this, the text inside such an element under a list was kept only because
// the list item the balancer implied for it, which a browser never creates,
// was the container judged (#492).  A name a browser reads literally in HTML,
// such as style, is not relaxed: its text is a stylesheet or script wherever
// it is written, and needs AllowTextIn on that name.  Inside retained HTML
// template contents the template's own context answers, as it does for every
// other output namespace decision here.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) holdsTextAsForeignElement(
	elementName string, attrs []string) bool {
	if htmlStreamRendererEmitsContentLiterally(elementName, false) {
		return false
	}
	context := p.currentOutputTemplateForeignContent()
	if context == nil {
		context = p.outputForeignContent
	}
	return context.startTagUsesForeignContentRules(elementName, attrs)
}

// OpenTag applies the element and attribute policies to a start tag and
// emits what survives.  It does not change the caller's list.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) OpenTag(elementName string, attrs []string) {
	p.openTagWithMode(elementName, attrs, elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeNormal)
}

// openTagWithoutOutput applies element and text policy while deliberately
// emitting no tag.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) openTagWithoutOutput(elementName string, attrs []string) {
	p.openTagWithMode(elementName, attrs, elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeSuppress)
}

// openTagWithoutOutputWithInheritedTextGate stacks no output element and
// keeps the current output text gate.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) openTagWithoutOutputWithInheritedTextGate(
	elementName string, attrs []string) {
	p.openTagWithMode(elementName, attrs,
		elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeSuppressInheritTextGate)
}

// openTagWithoutOutputOrContent applies policy while deliberately emitting
// neither tag nor contents.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) openTagWithoutOutputOrContent(
	elementName string, attrs []string) {
	p.openTagWithMode(elementName, attrs,
		elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeSuppressSubtree)
}

// openTagWithSuppressedContent emits a kept start while suppressing
// everything through its end.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) openTagWithSuppressedContent(
	elementName string, attrs []string) {
	p.openTagWithMode(elementName, attrs,
		elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeEmitSuppressSubtree)
}

// openTablePartWithInheritedTextGate emits a table part while retaining the
// enclosing output text gate.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) openTablePartWithInheritedTextGate(
	elementName string, attrs []string) {
	p.openTagWithMode(elementName, attrs,
		elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeInheritTextGate)
}

// isSuppressingOutputAndContent reports whether a prior suppressed start
// still suppresses its input subtree.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) isSuppressingOutputAndContent() bool {
	return p.suppressOutputAndContent
}

// isSuppressingText reports whether the current policy text gate suppresses
// text.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) isSuppressingText() bool {
	return p.skipText
}

// openReopenedTable emits a synthetic table only if policy keeps it as a
// table.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) openReopenedTable(attrs []string) {
	p.openTagWithMode("table", attrs,
		elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeReopenedTable)
}

// reopenedTableWasRenamed reports whether the last synthetic table was
// suppressed after being renamed.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) reopenedTableWasRenamed() bool {
	return p.reopenedTableRenamed
}

// openTagWithMode is the shared body of the open-tag operations.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) openTagWithMode(
	elementName string, attrs []string,
	mode elementAndAttributePolicyBasedSanitizerPolicyOpenTagMode) {
	usesPreparedStart := mode != elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeReopenedTable &&
		p.prepared &&
		elementName == p.preparedElementName &&
		sameAttrList(attrs, p.preparedElementAttrs)
	p.lastOpenOutputName = optionalElementName{}
	p.lastOpenUsedForeignContentRules = false
	if !usesPreparedStart {
		p.lastOpenRetiredOutputSelect = false
		p.lastOpenRetiredInputSelect = false
	}
	p.reopenedTableRenamed = false
	if p.inKeptLiteralElement {
		p.skippedLastAsAttributeless = false
		if usesPreparedStart {
			p.clearPreparedFormStart()
		}
		p.deferOpenTag(elementName)
		return
	}
	var policies *elementAndAttributePolicies
	var adjusted optionalElementName
	if usesPreparedStart {
		policies = p.preparedPolicies
		adjusted = p.preparedAdjustedElementName
		attrs = p.preparedElementAttrs
		p.skippedLastAsAttributeless = p.preparedSkippedAsAttributeless
		p.clearPreparedFormStart()
	} else {
		policies = p.elAndAttrPolicies[elementName]
		attrs = slices.Clone(attrs)
		adjusted = p.applyPolicies(elementName, &attrs, policies)
		p.skippedLastAsAttributeless = false
	}
	p.reopenedTableRenamed = mode == elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeReopenedTable &&
		adjusted.valid && adjusted.name != "table"
	if p.suppressOutputAndContent ||
		mode == elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeSuppressSubtree {
		if !IsVoidElement(elementName) {
			p.push(elementName, optionalElementName{})
			p.suppressOutputAndContent = true
			p.skipText = true
		}
		return
	}
	if adjusted.valid {
		adjustedElementName := adjusted.name
		if !p.skippedLastAsAttributeless &&
			!(len(attrs) == 0 && policies.htmlTagSkipType.SkipAvailability()) {
			p.openAllowedTag(elementName, adjustedElementName, attrs, policies, mode)
			return
		}
		// The element was allowed; it goes only because no attribute
		// survived.
		p.skippedLastAsAttributeless = true
	}
	p.deferOpenTag(elementName)
}

// openAllowedTag is the part of openTagWithMode for an element the policy
// allowed and that keeps its tag.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) openAllowedTag(
	elementName, adjustedElementName string, attrs []string,
	policies *elementAndAttributePolicies,
	mode elementAndAttributePolicyBasedSanitizerPolicyOpenTagMode) {
	inheritedTextGate := p.skipText
	ignoreNestedSelect :=
		elementAndAttributePolicyBasedSanitizerPolicyModeEmitsOutput(mode) &&
			p.prepareForSelectExit(adjustedElementName)
	inheritRetiredSelectTextGate := p.lastOpenRetiredInputSelect && p.skipText
	if ignoreNestedSelect {
		// The browser ignores an actual nested select start after it pops the
		// outer select.  A differently named input element mapped to select
		// still needs a logical entry for its own end tag.
		if elementName != "select" {
			p.deferOpenTag(elementName)
		}
		return
	}
	if mode == elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeNormal &&
		p.outputFormStartWouldBeIgnored(adjustedElementName, attrs) {
		// An element policy can introduce a form where the input parser has no
		// form start to ignore.  Do not serialize a start/end pair that a
		// browser would instead interpret as an ignored start followed by an
		// end that clears the existing pointer.
		p.deferOpenTag(elementName)
		return
	}
	reopenedTable := mode == elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeReopenedTable &&
		adjustedElementName == "table"
	if reopenedTable &&
		!p.outputForeignContent.startTagUsesForeignContentRules(adjustedElementName, attrs) &&
		!(p.inForeignContent && !p.outputForeignContent.isInForeignContent()) {
		p.prepareOutputForHTMLStart(adjustedElementName, attrs)
	}
	switch {
	case mode == elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeNormal,
		mode == elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeEmitSuppressSubtree,
		mode == elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeInheritTextGate,
		reopenedTable:
		p.writeOpenTag(policies, adjustedElementName, attrs)
		if inheritRetiredSelectTextGate {
			p.skipText = true
		}
		if mode == elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeInheritTextGate &&
			elementAndAttributePolicyBasedSanitizerPolicyIsHTMLTablePart(adjustedElementName) &&
			!p.lastOpenUsedForeignContentRules &&
			!IsVoidElement(elementName) {
			// Outside a physical table a browser ignores these start tags, so
			// their ordinary structural text rules do not create containers.
			// Carry the gate from where their text lands, while retaining an
			// explicit rule on the author's current input name.
			p.skipText = inheritedTextGate ||
				p.disallowedTextContainers.contains(elementName)
		}
		if mode == elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeEmitSuppressSubtree {
			p.suppressOutputAndContent = true
			p.skipText = true
		}
	case !IsVoidElement(elementName):
		p.push(elementName, optionalElementName{})
		if mode != elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeSuppressInheritTextGate {
			_, hasOutputForeignRoot := p.outputForeignContent.outermostForeignElementName()
			p.skipText = p.disallowedTextContainers.contains(elementName) ||
				(!p.allowedTextContainers.contains(elementName) &&
					!p.holdsTextAsForeignElement(elementName, attrs)) ||
				// No tag is written for this element, so its text lands in the
				// nearest emitted element.  Text the policy disallows there
				// stays out: judging only by this element's gate let a
				// suppressed cell admit text into a form the policy disallows
				// text in, which the next pass then removed.
				(p.outputContainer.valid &&
					p.disallowedTextContainers.contains(p.outputContainer.name)) ||
				// An emitted HTML breakout can leave the renderer's lexical
				// SVG/Math nesting open after the browser context has left it.
				// Text from a suppressed table part cannot be placed safely in
				// that stale lexical context, so fail closed for that text.
				// Inside an integration point the foreign root is still on the
				// browser's stack and HTML rules apply to what is inserted
				// there, so the text goes where it would in any HTML container.
				(p.inForeignContent &&
					!p.outputForeignContent.isInForeignContent() &&
					!hasOutputForeignRoot)
		}
	}
}

// prepareOutputForHTMLStart closes an output container that a browser would
// close before inserting adjustedElementName, while retaining its input names
// as dropped logical entries for later end tags and text-policy state.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) prepareOutputForHTMLStart(
	adjustedElementName string, attrs []string) {
	foreignElementsToClose := p.outputForeignContent.foreignElementsPoppedByStartTag(
		adjustedElementName, attrs)
	if foreignElementsToClose != 0 {
		depth := len(p.stack)
		for depth > 0 && foreignElementsToClose != 0 {
			depth--
			if p.stack[depth].output.valid {
				foreignElementsToClose--
			}
		}
		if foreignElementsToClose == 0 {
			p.retireOutputSuffixKeepingLogical(depth)
		}
	}
	if adjustedElementName == "form" {
		for d := len(p.stack) - 1; d >= 0; d-- {
			e := &p.stack[d]
			if e.outputInForeignContent {
				continue
			}
			if e.output.is("p") {
				p.retireOutputSuffixKeepingLogical(d)
				break
			}
			if e.output.valid &&
				elementAndAttributePolicyBasedSanitizerPolicyIsButtonScopeBoundary(e.output.name) {
				break
			}
		}
	}
	metadata := elementAndAttributePolicyBasedSanitizerPolicyMetadata
	child := metadata.IndexForName(adjustedElementName)
	for {
		parentDepth := -1
		for d := len(p.stack) - 1; d >= 0; d-- {
			if p.stack[d].output.valid {
				parentDepth = d
				break
			}
		}
		if parentDepth < 0 {
			return
		}
		parent := metadata.IndexForName(p.stack[parentDepth].output.name)
		if metadata.CanContain(parent, child) {
			return
		}
		p.retireOutputSuffixKeepingLogical(parentDepth)
	}
}

// elementAndAttributePolicyBasedSanitizerPolicyIsButtonScopeBoundary reports
// whether an HTML element bounds the scope in which a paragraph can end.
func elementAndAttributePolicyBasedSanitizerPolicyIsButtonScopeBoundary(name string) bool {
	switch name {
	case "applet", "button", "caption", "html", "marquee", "object", "table",
		"td", "template", "th":
		return true
	}
	return false
}

// retireOutputSuffixKeepingLogical retires an output suffix without consuming
// its logical input entries.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) retireOutputSuffixKeepingLogical(fromDepth int) {
	n := len(p.stack)
	retiredFormOffset := -1
	if p.retiredFormDepth >= fromDepth {
		retiredFormOffset = p.retiredFormDepth - fromDepth
	}
	var logicalSuffix []string
	var suffixSuppression []bool
	for d := fromDepth; d < n; d++ {
		e := &p.stack[d]
		logicalSuffix = append(logicalSuffix, e.inputName)
		suffixSuppression = append(suffixSuppression, p.suppressionAfterOpen(d, n))
		if e.output.is("select") && !e.outputInForeignContent {
			p.lastOpenRetiredOutputSelect = true
		}
	}
	p.closeStackFromDepth(fromDepth)
	for i, name := range logicalSuffix {
		p.deferOpenTag(name)
		if i == retiredFormOffset {
			p.retiredFormDepth = len(p.stack) - 1
			p.deferRetiredFormToOutputFormatting()
		}
		p.suppressOutputAndContent = suffixSuppression[i]
		if p.suppressOutputAndContent {
			p.skipText = true
		}
	}
}

// suppressionAfterOpen returns the suppression state immediately after the
// open at depth.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) suppressionAfterOpen(depth, depthCount int) bool {
	if depth+1 < depthCount {
		return p.stack[depth+1].suppressBefore
	}
	return p.suppressOutputAndContent
}

// outputFormStartWouldBeIgnored reports whether the browser would ignore this
// policy-produced form start.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) outputFormStartWouldBeIgnored(
	adjustedElementName string, attrs []string) bool {
	return adjustedElementName == "form" &&
		p.outputForeignContent.formElementPointerIsSet() &&
		!p.outputForeignContent.startTagUsesForeignContentRules(adjustedElementName, attrs) &&
		!p.hasOpenOutputTemplateBelow(len(p.stack))
}

// clearPreparedFormStart forgets the prepared policy result.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) clearPreparedFormStart() {
	p.prepared = false
	p.preparedElementName = ""
	p.preparedElementAttrs = nil
	p.preparedPolicies = nil
	p.preparedAdjustedElementName = optionalElementName{}
	p.preparedSkippedAsAttributeless = false
}

// prepareForSelectExit prepares an emitted start that changes the HTML
// in-select insertion mode, and reports whether the start is a nested select
// that produces no element.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) prepareForSelectExit(adjustedElementName string) bool {
	htmlName := stringsToLowerCase(adjustedElementName)
	switch htmlName {
	case "input", "keygen", "select", "textarea":
	default:
		return false
	}
	// Search the emitted stack for an HTML select instead of trusting the
	// current lexical namespace.  SVG and MathML roots written inside a select
	// are ignored by tree construction, although the lexical tracker enters
	// them, so an input after either root still exits the select.
	p.lastOpenRetiredOutputSelect = p.retireOutputSelectForHTMLStart()
	// A select start seen in the in-select insertion mode closes the open
	// select but is not reprocessed, so it produces no element of its own.
	return p.lastOpenRetiredOutputSelect && htmlName == "select"
}

// elementAndAttributePolicyBasedSanitizerPolicyModeEmitsOutput reports whether
// this mode may serialize the adjusted start tag.
func elementAndAttributePolicyBasedSanitizerPolicyModeEmitsOutput(
	mode elementAndAttributePolicyBasedSanitizerPolicyOpenTagMode) bool {
	return mode == elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeNormal ||
		mode == elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeEmitSuppressSubtree ||
		mode == elementAndAttributePolicyBasedSanitizerPolicyOpenTagModeInheritTextGate
}

// elementAndAttributePolicyBasedSanitizerPolicyIsHTMLTablePart reports whether
// HTML tree construction gives this local name table semantics.
func elementAndAttributePolicyBasedSanitizerPolicyIsHTMLTablePart(elementName string) bool {
	switch stringsToLowerCase(elementName) {
	case "caption", "col", "colgroup", "table", "tbody", "td", "tfoot", "th",
		"thead", "tr":
		return true
	}
	return false
}

// skippedLastTagAsAttributeless reports whether the most recent start tag was
// allowed by the element policy and dropped only for having no attributes
// left.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) skippedLastTagAsAttributeless() bool {
	return p.skippedLastAsAttributeless
}

// applyPolicies runs the attribute policies over *attrs, removing the
// attributes they reject and the repeats of a name, then the element policy,
// and returns the canonical name the element is emitted under, or an absent
// name if it is dropped.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) applyPolicies(
	elementName string, attrs *[]string,
	policies *elementAndAttributePolicies) optionalElementName {
	if policies == nil {
		return optionalElementName{}
	}
	list := *attrs
	kept := 0
	// A name without a value, which the lexer never produces, goes.
	for i := 0; i+1 < len(list); i += 2 {
		name, value := list[i], list[i+1]
		attrPolicy := policies.attrPolicies[name]
		if attrPolicy == nil {
			p.reportDiscardedAttribute(name, value)
			continue
		}
		adjustedValue, ok := attrPolicy.Apply(elementName, name, value)
		if !ok {
			p.reportDiscardedAttribute(name, value)
			continue
		}
		list[kept] = name
		list[kept+1] = adjustedValue
		kept += 2
	}
	clear(list[kept:])
	*attrs = list[:kept]

	// Now that we know which attributes are allowed, make sure the names
	// are unique.
	elementAndAttributePolicyBasedSanitizerPolicyRemoveDuplicateAttributes(attrs)

	adjustedElementName, ok := policies.elPolicy.Apply(elementName, attrs)
	if !ok {
		return optionalElementName{}
	}
	return someElementName(htmlLexerCanonicalElementName(adjustedElementName))
}

// reportDiscardedAttribute reports an attribute-policy rejection without
// invoking user code.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) reportDiscardedAttribute(name, value string) {
	if p.discardedAttributeListener != nil {
		p.discardedAttributeListener.discardedAttribute(name, value)
	}
}

// CloseTag closes the innermost open element opened under elementName, and
// every element opened after it.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) CloseTag(elementName string) {
	n := len(p.stack)
	metadata := elementAndAttributePolicyBasedSanitizerPolicyMetadata
	for d := n - 1; d >= 0; d-- {
		if p.stack[d].inputName != elementName {
			continue
		}
		if p.retiredFormDefersToOutputFormatting &&
			p.retiredFormDepth == n-1 &&
			d == p.retiredFormDepth-1 &&
			metadata.Resumable(metadata.IndexForName(
				htmlLexerCanonicalElementName(elementName))) &&
			p.stack[d].output.valid &&
			metadata.Resumable(metadata.IndexForName(p.stack[d].output.name)) {
			// The serialized formatting element is outside the implied table,
			// but a browser's adoption-agency rules can put its fostered text
			// inside that formatting and its later text directly in the form.
			// Close the output formatting without consuming the logical form,
			// then make the form's own gate current again.
			p.closeRetiredFormTextContext()
			p.closeStackFromDepth(d)
			p.openRetiredFormTextContext()
			return
		}
		p.closeStackFromDepth(d)
		return
	}
}

// closeStackFromDepth closes the output suffix for the exact stack entry at
// depth, and pops that entry and every entry above it.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) closeStackFromDepth(depth int) {
	for d := len(p.stack) - 1; d >= depth; d-- {
		if tagNameToClose, ok := p.stack[d].output.get(); ok {
			p.closeOutputElement(tagNameToClose, d)
		}
	}
	if p.retiredFormDepth >= depth {
		p.retiredFormDepth = -1
		p.retiredFormDefersToOutputFormatting = false
	}
	e := p.stack[depth]
	p.truncateStack(depth)
	p.forgetIndexedOutputEntriesFrom(depth)
	p.skipText = e.skipTextBefore
	p.suppressOutputAndContent = e.suppressBefore
	p.inKeptLiteralElement = e.inKeptLiteralBefore
	p.inKeptCdataElement = e.inKeptCdataBefore
	p.inForeignContent = e.inForeignContentBefore
	p.keptCdataElementName = e.keptCdataNameBefore
	p.outputContainer = e.outputContainerBefore
}

// truncateStack pops every stack entry at or above depth.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) truncateStack(depth int) {
	clear(p.stack[depth:])
	p.stack = p.stack[:depth]
}

// writeOpenTag emits a start tag the policy allowed, and stacks what its
// close tag will need.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) writeOpenTag(
	policies *elementAndAttributePolicies, adjustedElementName string,
	attrs []string) {
	p.lastOpenOutputName = someElementName(adjustedElementName)
	elementName := policies.elementName
	// Whether a close tag will come for this element depends on the name the
	// author wrote, which is the one the lexer and the tag balancer see, not
	// on the name the policy emitted it under.  The stack follows suit, so
	// that every entry on it is one a close tag can pop.
	if IsVoidElement(elementName) {
		adjustedIsVoid := IsVoidElement(adjustedElementName)
		p.processOutputStartTag(adjustedElementName, attrs, adjustedIsVoid)
		p.lastOpenUsedForeignContentRules =
			p.outputForeignContent.lastTagUsedForeignContentRules()
		p.out.OpenTag(adjustedElementName, attrs)
		if !adjustedIsVoid {
			// Renamed to an element that needs closing, which nothing upstream
			// will do: closed at once, so it does not swallow what follows.
			htmlForm := adjustedElementName == "form" &&
				!p.lastOpenUsedForeignContentRules &&
				!p.hasOpenOutputTemplateBelow(len(p.stack))
			if htmlForm {
				p.outputForeignContent.markFormElementPointerSet()
			}
			p.processOutputEndTag(adjustedElementName)
			p.out.CloseTag(adjustedElementName)
			if htmlForm {
				p.outputForeignContent.clearFormElementPointer()
			}
		}
		return
	}
	if IsVoidElement(adjustedElementName) {
		// Renamed to a void element.  The close tag that comes for the input
		// name has nothing to close in the output, and the text between is
		// not inside the element there, so the gate stays as it was, as after
		// a dropped element.
		p.push(elementName, optionalElementName{})
		p.skipText = p.skipText || p.suppressesTextWhenDropped(elementName)
		p.processOutputStartTag(adjustedElementName, attrs, true)
		p.lastOpenUsedForeignContentRules =
			p.outputForeignContent.lastTagUsedForeignContentRules()
		p.out.OpenTag(adjustedElementName, attrs)
		return
	}
	p.push(elementName, someElementName(adjustedElementName))
	// A kept element is the container for the text inside it.  Whether it may
	// hold text was said of the name the author wrote, which is the name the
	// builder's methods take, so that is the name judged.  An element the
	// policy emits under a name a browser reads literally, such as style, is
	// held to the same bar as one written under that name: text in it needs
	// AllowTextIn on that name too.
	literal := p.isLiteralContentElement(adjustedElementName)
	p.skipText = p.disallowedTextContainers.contains(elementName) ||
		(!p.allowedTextContainers.contains(elementName) &&
			!p.holdsTextAsForeignElement(adjustedElementName, attrs)) ||
		(literal && !p.allowedTextContainers.contains(adjustedElementName))
	enteringKeptCdata := literal && !p.skipText
	if !p.inKeptCdataElement && enteringKeptCdata {
		p.keptCdataElementName = someElementName(adjustedElementName)
		p.literalTextTail = ""
	}
	p.inKeptLiteralElement = p.inKeptLiteralElement || literal
	p.inKeptCdataElement = p.inKeptCdataElement || enteringKeptCdata
	// Judged before this element is in foreign content itself: a browser
	// parses the content of an svg or math element as markup, but the
	// element's own tag sits in whatever contains it.
	_, isForeignContentRoot := htmlStreamRendererForeignContentRootElementNames[adjustedElementName]
	p.inForeignContent = p.inForeignContent || isForeignContentRoot
	opensHTMLTemplate := p.opensHTMLOutputTemplate(elementName, adjustedElementName, attrs)
	if opensHTMLTemplate {
		// Preserve the legacy conservative tracker at the template boundary,
		// while freezing any parent template context for later restoration.
		p.outputForeignContent.processStartTag(adjustedElementName, attrs, false)
	} else {
		p.processOutputStartTag(adjustedElementName, attrs, false)
	}
	p.lastOpenUsedForeignContentRules =
		p.outputForeignContent.lastTagUsedForeignContentRules()
	top := len(p.stack) - 1
	p.stack[top].outputInForeignContent = p.lastOpenUsedForeignContentRules
	if elementAndAttributePolicyBasedSanitizerPolicyIsFormScopeOutputBoundary(
		adjustedElementName, p.lastOpenUsedForeignContentRules) {
		p.formScopeOutputDepths = append(p.formScopeOutputDepths, top)
	}
	p.out.OpenTag(adjustedElementName, attrs)
	p.outputDepth++
	p.outputContainer = someElementName(adjustedElementName)
	if opensHTMLTemplate {
		p.pushOutputTemplateForeignContent()
	}
	if adjustedElementName == "form" &&
		!p.lastOpenUsedForeignContentRules &&
		!p.hasOpenOutputTemplateBelow(len(p.stack)-1) {
		p.outputForeignContent.markFormElementPointerSet()
	}
}

// closeOutputElement writes an end tag and keeps the modeled output form
// pointer in sync.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) closeOutputElement(adjustedElementName string, depth int) {
	elementIsForeign := p.stack[depth].outputInForeignContent
	closesHTMLTemplate := p.closesActiveHTMLOutputTemplate(adjustedElementName, elementIsForeign)
	if closesHTMLTemplate {
		p.outputForeignContent.processEndTag(adjustedElementName)
	} else {
		p.processOutputEndTag(adjustedElementName)
	}
	p.out.CloseTag(adjustedElementName)
	p.outputDepth--
	if closesHTMLTemplate {
		p.popOutputTemplateForeignContent()
	}
	if adjustedElementName == "form" &&
		!elementIsForeign &&
		!p.hasOpenOutputTemplateBelow(depth) {
		p.outputForeignContent.clearFormElementPointer()
	}
}

// hasOpenOutputTemplateBelow reports whether an emitted template remains below
// depth.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) hasOpenOutputTemplateBelow(depth int) bool {
	for d := 0; d < depth; d++ {
		if !p.stack[d].outputInForeignContent && p.stack[d].output.is("template") {
			return true
		}
	}
	return false
}

// outputFormIsBlockedByTableScope reports whether an emitted table keeps the
// output pointer's form out of scope.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) outputFormIsBlockedByTableScope() bool {
	sawTable := false
	for d := len(p.stack) - 1; d >= 0; d-- {
		e := &p.stack[d]
		if e.outputInForeignContent {
			continue
		}
		if e.output.is("table") {
			sawTable = true
		} else if e.output.is("form") {
			return sawTable
		}
	}
	return false
}

// deferOpenTag stacks an element that emits no tag.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) deferOpenTag(elementName string) {
	if !IsVoidElement(elementName) {
		p.push(elementName, optionalElementName{})
		// A dropped element is not a container in the output, so the gate
		// stays as it was -- unless the element's content must not surface as
		// text.
		p.skipText = p.skipText || p.suppressesTextWhenDropped(elementName)
	}
}

// push stacks an element, remembering the gates in effect before it so that
// CloseTag can restore them.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) push(
	elementName string, adjustedElementName optionalElementName) {
	p.stack = append(p.stack, elementAndAttributePolicyBasedSanitizerPolicyStackEntry{
		inputName:              elementName,
		output:                 adjustedElementName,
		skipTextBefore:         p.skipText,
		inKeptLiteralBefore:    p.inKeptLiteralElement,
		suppressBefore:         p.suppressOutputAndContent,
		inKeptCdataBefore:      p.inKeptCdataElement,
		inForeignContentBefore: p.inForeignContent,
		keptCdataNameBefore:    p.keptCdataElementName,
		outputContainerBefore:  p.outputContainer,
	})
	if adjustedElementName.valid &&
		elementAndAttributePolicyBasedSanitizerPolicyIsTableScopeOutputName(adjustedElementName.name) {
		p.tableScopeOutputDepths = append(p.tableScopeOutputDepths, len(p.stack)-1)
	}
}

// elementAndAttributePolicyBasedSanitizerPolicyIsTableScopeOutputName reports
// whether formStartTagUsesTableRules decides on this output name.
func elementAndAttributePolicyBasedSanitizerPolicyIsTableScopeOutputName(adjustedElementName string) bool {
	switch adjustedElementName {
	case "table", "caption", "select", "td", "template", "th":
		return true
	}
	return false
}

// elementAndAttributePolicyBasedSanitizerPolicyIsFormScopeOutputBoundary
// reports whether an emitted element bounds the scope of an HTML form end tag.
func elementAndAttributePolicyBasedSanitizerPolicyIsFormScopeOutputBoundary(
	adjustedElementName string, usesForeignContentRules bool) bool {
	if usesForeignContentRules {
		return true
	}
	switch adjustedElementName {
	case "applet", "caption", "html", "marquee", "object", "select", "table",
		"td", "template", "th":
		return true
	}
	return false
}

// forgetIndexedOutputEntriesFrom drops the indexed output entries at or above
// depth.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) forgetIndexedOutputEntriesFrom(depth int) {
	for n := len(p.tableScopeOutputDepths); n != 0 && p.tableScopeOutputDepths[n-1] >= depth; n-- {
		p.tableScopeOutputDepths = p.tableScopeOutputDepths[:n-1]
	}
	for n := len(p.formScopeOutputDepths); n != 0 && p.formScopeOutputDepths[n-1] >= depth; n-- {
		p.formScopeOutputDepths = p.formScopeOutputDepths[:n-1]
	}
}

// suppressesTextWhenDropped reports whether text directly inside a dropped
// elementName is suppressed rather than emitted where the element was: its
// content is never meant to be read as text, or the policy disallowed text in
// it.
func (p *elementAndAttributePolicyBasedSanitizerPolicy) suppressesTextWhenDropped(elementName string) bool {
	return elementAndAttributePolicyBasedSanitizerPolicySkippableElementContent.contains(elementName) ||
		p.disallowedTextContainers.contains(elementName)
}

// elementAndAttributePolicyBasedSanitizerPolicyRemoveDuplicateAttributes
// removes attributes with the same name.
//
// HTML5 (http://www.w3.org/TR/html5/syntax.html#attributes-0) says "There
// must never be two or more attributes on the same start tag whose names are
// an ASCII case-insensitive match for each other."
//
// Empirically, given
//
//	<!doctype html><html><body>
//	<script id="first" id="last">
//	var scriptElement = document.getElementsByTagName('script')[0];
//	document.body.appendChild(
//	  document.createTextNode(scriptElement.getAttribute('id')));
//	</script>
//
// Firefox, Safari and Chrome all show "first" so we eliminate from the right.
func elementAndAttributePolicyBasedSanitizerPolicyRemoveDuplicateAttributes(attrs *[]string) {
	list := *attrs
	firstLetterMask := 0
	n := len(list)
	// list[:k] contains the non-duplicate parts of list that have been
	// processed thus far.
	k := 0
attrLoop:
	for i := 0; i < n; i += 2 {
		name := list[i]

		if len(name) == 0 {
			continue
		}

		// Don't be O(n**2) in the common case by checking whether the first
		// letter has been seen on any other attribute.
		checkForDuplicate := true
		if firstCharIndex := int(name[0]) - 'a'; 0 <= firstCharIndex && firstCharIndex < 26 {
			firstCharBit := 1 << firstCharIndex
			if firstLetterMask&firstCharBit == 0 {
				firstLetterMask |= firstCharBit
				checkForDuplicate = false
			}
		}
		if checkForDuplicate {
			// Look for a duplicate.  list alternates names and values, so step
			// by two to compare against names only; comparing against a value
			// would drop an attribute whose name matches an earlier value.
			for j := k - 2; j >= 0; j -= 2 {
				if list[j] == name {
					continue attrLoop
				}
			}
		}

		// Preserve the attribute.
		if k != i {
			list[k] = name
			list[k+1] = list[i+1]
		}
		k += 2
	}
	if k != n {
		clear(list[k:])
		*attrs = list[:k]
	}
}
