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
// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/TagBalancingHtmlStreamEventReceiver.java.

package sanitizer

import (
	"fmt"
	"math"
	"math/bits"
	"slices"
)

// TagBalancingHTMLStreamEventReceiver wraps an HTML stream event receiver to
// fill in missing close tags.  If the balancer is given the HTML <p>1<p>2,
// the wrapped receiver will see events equivalent to <p>1</p><p>2</p>.
type TagBalancingHTMLStreamEventReceiver struct {
	underlying HTMLStreamEventReceiver

	// The optional interfaces underlying implements, or nil.
	nestingLimitListener  tagBalancingHTMLStreamEventReceiverNestingLimitListener
	textSuppressionPolicy tagBalancingHTMLStreamEventReceiverTextSuppressionPolicy
	openTagOutputPolicy   tagBalancingHTMLStreamEventReceiverOpenTagOutputPolicy
	tablePolicy           tagBalancingHTMLStreamEventReceiverPushedOutTablePolicy
	formPointerPolicy     tagBalancingHTMLStreamEventReceiverFormPointerPolicy

	nestingLimit   int
	foreignContent *htmlSanitizerForeignContentContext
	// foreignRootPendingTableReturn is the input name whose rendered foreign
	// root closes before the table reopens, or nil.
	foreignRootPendingTableReturn *string
	// pendingUnrecognizedHTMLTextElement is an unrecognized input name
	// emitted as HTML textarea, or nil.  The input lexer does not enter
	// RCDATA for that case-sensitive foreign name, but a browser reparsing
	// the output does.  Keep text in it, and close it before forwarding the
	// next tag event so markup cannot turn into RCDATA.
	pendingUnrecognizedHTMLTextElement *string

	// policyOnlyTableMayBeOpen is whether an unrecognized input may have
	// produced a table known only downstream.
	policyOnlyTableMayBeOpen bool
	// preparingPreparedPolicyStart prevents nested balancing from replacing a
	// prepared policy result.
	preparingPreparedPolicyStart bool
	// insertionPointIsInForeignContent is whether the tag or text being
	// balanced is inserted under SVG or MathML rules below.  A browser
	// reconstructs its active formatting elements only where it inserts HTML
	// content, and an HTML formatting start tag in foreign content would
	// instead pop the foreign root, so no queued formatting is resumed there.
	insertionPointIsInForeignContent bool
	// outputlessTablePartsMayBeOpen is whether emitted bare parts may keep a
	// browser-implied table open.
	outputlessTablePartsMayBeOpen bool
	// outputlessTablePartsOpenedAtEvent is the public open-tag event in which
	// detached state first became true.
	outputlessTablePartsOpenedAtEvent int32
	openTagEvent                      int32
	// outputlessTablesWithEmittedParts marks outputless logical tables into
	// whose browser-implied table parts emitted.
	outputlessTablesWithEmittedParts stackFlags
	// outputlessImpliedListAfterEmittedItem is the outputless inferred list
	// left directly above its last emitted item.
	outputlessImpliedListAfterEmittedItem int
	// outputSelectHasText is whether non-whitespace text was seen in the open
	// HTML output select.
	outputSelectHasText bool
	// outputSelectWasOpen is the output-select state observed before the
	// preceding public event.
	outputSelectWasOpen bool
	// outputListItemAfterClosedSelect is a free output item that remains
	// open after an output select closes.
	outputListItemAfterClosedSelect int
	// htmlInputSelectIsOpen is whether the input parser is in an HTML select
	// outside template contents.  This is parser context, not an output text
	// gate: the containment stack may remove a dropped select while browsers
	// keep using its insertion mode.
	htmlInputSelectIsOpen bool
	// pushedMappedTemplateOutputOpen marks pushed logical tables whose mapped
	// template remains physically open.
	pushedMappedTemplateOutputOpen stackFlags
	// suppressedMappedForeignSubtrees marks logical roots whose mapped
	// foreign output has suppressed contents.
	suppressedMappedForeignSubtrees stackFlags
	// suppressedMappedForeignTableResumeDepth is the formatting-queue depth
	// before the active suppressed table started.
	suppressedMappedForeignTableResumeDepth int
	openElements                            []int
	// inputElementSerials holds, for each entry in openElements, the opaque
	// identity that foreignContent gave the browser tree-construction node
	// pushed by the same start tag, or zero for an entry that was implied,
	// resumed, or not tracked there.  A foreign end tag pops nodes, and the
	// entries it closes are found by this identity rather than by local
	// name, which a dropped or already closed element with the same name
	// could alias.
	inputElementSerials []int
	// passthroughNames are the elements forwarded to the receiver below with
	// no entry in openElements: names outside the containment metadata, such
	// as svg or a custom element, and table parts forwarded directly into SVG
	// or MathML output.  The receiver keeps each open until its end tag.
	// Each records the size of openElements when it was forwarded, so every
	// entry added after it is known to be inside it, and the identity of the
	// tree-construction node its start tag pushed, or zero.  An end tag is
	// forwarded only for an element still listed here, after everything
	// inside it has been closed, and a stray end tag closes nothing.
	//
	// Every name here is canonical: each is forwarded under the name the
	// policy is asked about.  passthroughIndicesByName indexes them, so an
	// end tag finds its element without scanning the list, which a long run
	// of forwarded elements would otherwise make quadratic.
	//
	// A forwarded element counts toward the nesting limit only where it is
	// known to nest the output: see effectiveNestingDepth.
	passthroughNames []string
	// passthroughSpecialTextModeDepth is the number of forwarded elements
	// whose content this lexer reads as text.
	passthroughSpecialTextModeDepth int
	// passthroughIndicesByName holds indices into passthroughNames,
	// innermost last, by name.
	passthroughIndicesByName map[string][]int
	passthroughDepths        []int
	passthroughSerials       []int
	// passthroughOutputForeign is whether the policy emitted each forwarded
	// element as an SVG or MathML element, by index into passthroughNames,
	// and passthroughForeignRoots the indices of the forwarded SVG and
	// MathML roots, innermost last.  Together they say whether the output
	// entered the input's current foreign region: a root the policy dropped,
	// or renamed to an HTML element, leaves the elements inside it as
	// ordinary HTML in the output.
	passthroughOutputForeign stackFlags
	passthroughForeignRoots  []int
	// outputElements holds the element each entry in openElements became
	// after policy application, or noOutputElement when the policy dropped
	// it or the entry is an implied list item a browser would ignore, which
	// is never sent.  When the receiver below cannot report that, the input
	// name is used.
	outputElements []int
	// sentToUnderlying has bit i set when the open event for entry i of
	// openElements was sent to underlying.  Resumed formatting and returned
	// table entries can remain on the logical stack at or beyond the nesting
	// limit without an open event, and the limit may later change.
	// Browser-ignored implied list items are kept on the logical stack only.
	sentToUnderlying stackFlags
	// inputElementsInForeignContent has bit i set when the input element at
	// i was inserted using SVG or MathML rules.  Local names such as form
	// and table do not have their HTML scope behavior there.
	inputElementsInForeignContent stackFlags
	// outputElementsInForeignContent is the corresponding namespace
	// information for the element policy emitted.
	outputElementsInForeignContent stackFlags
	// outputElementsStartForeignContent is whether the policy output at this
	// logical index starts SVG or MathML.
	outputElementsStartForeignContent stackFlags
	// formPointerTargets marks the stacked HTML form, if any, that the input
	// form pointer names.  A form inserted directly in table structure is
	// popped at once and has no marked stack entry even though the pointer
	// remains set.
	formPointerTargets stackFlags
	// clearedFormPointerTargets marks stacked output forms whose form pointer
	// was cleared without popping.
	clearedFormPointerTargets stackFlags
	// staleOutputFormPointerTargets is a subset of clearedFormPointerTargets
	// whose corresponding output pointer could not yet be cleared without
	// changing the output tree.
	staleOutputFormPointerTargets stackFlags
	toResumeInReverse             []int
	// resumeOnlyOutsideRawText holds parallel flags: formatting queued by
	// the list-item-start walk.
	resumeOnlyOutsideRawText []int
	// resumedFormattingFromListItemStart marks formatting, or the item,
	// opened after a list-item-start closure.
	resumedFormattingFromListItemStart stackFlags
	// closingListItemForStart is true while that walk is closing the
	// preceding item.
	closingListItemForStart bool
	// currentStartClosedListItem is true when the current start closed the
	// preceding list item.
	currentStartClosedListItem bool
	// pushedOut has bit i set while the element at i of openElements is
	// closed in the output but still open here.
	//
	// A browser keeps a table, and any row group and row open in it, on its
	// stack when content arrives that cannot go inside a table: it puts the
	// content in front of the table instead, foster parenting, and later
	// table content pops that content and carries on in the same table.  The
	// output cannot put anything in front of a tag already written, so the
	// table is closed there and the content written after it, and the table
	// is written again, as a new table, when its content resumes (#342).
	// Meanwhile its entries stay here, so that table content finds them and
	// comes back to them, and so that they bound end tags for elements below
	// them as they do in a browser.  Such entries are contiguous, from a
	// table up, and are the only pushed-out entries below the content pushed
	// out of them.
	pushedOut stackFlags
	// impliedInputTables marks logical tables inserted only to wrap orphan
	// input table parts.
	impliedInputTables stackFlags
	// outputlessImpliedSelects marks implied selects kept logical because a
	// real output select was open.
	outputlessImpliedSelects stackFlags
	// outputTableUnavailable has bit i set when no output table remains for
	// a logical entry whose descendants still use table rules.  This happens
	// when policy does not emit a synthetic table while returning from
	// pushedOut, or when an element renamed to table has to close before
	// foster-parented content.  Table-structure descendants cannot be emitted
	// in that output context without changing when a browser reparses them.
	outputTableUnavailable stackFlags

	// droppedSkippableDepth is how many elements whose content the policy
	// would suppress -- <script>, <style>, <iframe> and friends, plus any the
	// policy names through the text suppression policy -- have been dropped
	// for exceeding the nesting limit and not yet closed.
	//
	// The policy decides to skip such an element's text when it sees the
	// element's start tag.  A tag this receiver drops never reaches the
	// policy, so the policy would render the content as ordinary text.
	// Counting them here keeps that content suppressed.
	droppedSkippableDepth int
	// droppedSuppressedOptionDepth is the number of untracked option starts
	// inside a suppressed mapped select.
	droppedSuppressedOptionDepth int
	// droppedSuppressedOptionOwnsPolicyEntry is whether the untracked option
	// run owns one policy-stack entry.
	droppedSuppressedOptionOwnsPolicyEntry bool
	// droppedSuppressedOptionStackDepth is the logical depth below
	// descendants of a policy-only suppressed option.
	droppedSuppressedOptionStackDepth int
	// droppedSuppressedOptionPassthroughDepth is the number of forwarded
	// elements open before a policy-only suppressed option.
	droppedSuppressedOptionPassthroughDepth int
	// droppedSuppressedOptionResumeDepth is the number of formatting entries
	// queued before a policy-only suppressed option.
	droppedSuppressedOptionResumeDepth int
	// droppedSuppressedTableDepth is the number of cap-dropped tables inside
	// the active suppressed table.
	droppedSuppressedTableDepth int
}

var (
	tagBalancingHTMLStreamEventReceiverMetadata        = htmlElementTablesGet()
	tagBalancingHTMLStreamEventReceiverUnrecognizedTag = tagBalancingHTMLStreamEventReceiverMetadata.IndexForName(
		htmlElementTablesHTMLElementNamesCustomElementName)
	tagBalancingHTMLStreamEventReceiverATag        = tagBalancingHTMLStreamEventReceiverMetadata.IndexForName("a")
	tagBalancingHTMLStreamEventReceiverBodyTag     = tagBalancingHTMLStreamEventReceiverMetadata.IndexForName("body")
	tagBalancingHTMLStreamEventReceiverColTag      = tagBalancingHTMLStreamEventReceiverMetadata.IndexForName("col")
	tagBalancingHTMLStreamEventReceiverColgroupTag = tagBalancingHTMLStreamEventReceiverMetadata.IndexForName("colgroup")
	tagBalancingHTMLStreamEventReceiverFormTag     = tagBalancingHTMLStreamEventReceiverMetadata.IndexForName("form")
	tagBalancingHTMLStreamEventReceiverLiTag       = tagBalancingHTMLStreamEventReceiverMetadata.IndexForName("li")
	tagBalancingHTMLStreamEventReceiverOlTag       = tagBalancingHTMLStreamEventReceiverMetadata.IndexForName("ol")
	tagBalancingHTMLStreamEventReceiverOptionTag   = tagBalancingHTMLStreamEventReceiverMetadata.IndexForName("option")
	tagBalancingHTMLStreamEventReceiverOptgroupTag = tagBalancingHTMLStreamEventReceiverMetadata.IndexForName("optgroup")
	tagBalancingHTMLStreamEventReceiverUlTag       = tagBalancingHTMLStreamEventReceiverMetadata.IndexForName("ul")
	tagBalancingHTMLStreamEventReceiverSelectTag   = tagBalancingHTMLStreamEventReceiverMetadata.IndexForName("select")
	tagBalancingHTMLStreamEventReceiverTableTag    = tagBalancingHTMLStreamEventReceiverMetadata.IndexForName("table")
	tagBalancingHTMLStreamEventReceiverCaptionTag  = tagBalancingHTMLStreamEventReceiverMetadata.IndexForName("caption")
	tagBalancingHTMLStreamEventReceiverTdTag       = tagBalancingHTMLStreamEventReceiverMetadata.IndexForName("td")
	tagBalancingHTMLStreamEventReceiverThTag       = tagBalancingHTMLStreamEventReceiverMetadata.IndexForName("th")
	tagBalancingHTMLStreamEventReceiverTemplateTag = tagBalancingHTMLStreamEventReceiverMetadata.IndexForName("template")
	tagBalancingHTMLStreamEventReceiverTbodyTag    = tagBalancingHTMLStreamEventReceiverMetadata.IndexForName("tbody")
	tagBalancingHTMLStreamEventReceiverTrTag       = tagBalancingHTMLStreamEventReceiverMetadata.IndexForName("tr")
)

const (
	tagBalancingHTMLStreamEventReceiverNoOutputElement        = -1
	tagBalancingHTMLStreamEventReceiverPolicyOnlyTableContext = -2
	tagBalancingHTMLStreamEventReceiverInputOnlyTableContext  = -3
)

var (
	// tagBalancingHTMLStreamEventReceiverTableContext are the elements a
	// browser keeps open, and later clears its stack back to, when it
	// foster-parents content that arrives inside them: a table and its row
	// groups and rows.  Not the cell, caption or template, inside which
	// content nests normally.
	tagBalancingHTMLStreamEventReceiverTableContext = tagBalancingHTMLStreamEventReceiverElementSet(
		"table", "tbody", "tfoot", "thead", "tr")
	// tagBalancingHTMLStreamEventReceiverTableParts are the elements whose
	// arrival, in a browser, ends foster-parented content and returns to the
	// table: its parts, which clear the stack back to the table, and a table
	// itself, which pops the open table and takes its place.
	//
	// These are the same elements whose end tags are scoped to a table in
	// tagBalancingHTMLStreamEventReceiverScopeForEndTag.
	tagBalancingHTMLStreamEventReceiverTableParts = tagBalancingHTMLStreamEventReceiverElementSet(
		"caption", "col", "colgroup", "table", "tbody", "td", "tfoot",
		"th", "thead", "tr")
	// tagBalancingHTMLStreamEventReceiverTableFormScopeBoundaries are the
	// elements that bound the table context used for the special form rule.
	tagBalancingHTMLStreamEventReceiverTableFormScopeBoundaries = tagBalancingHTMLStreamEventReceiverElementSet(
		"caption", "select", "td", "template", "th")
	// tagBalancingHTMLStreamEventReceiverListItemStartBarriers are the
	// elements that stop the walk down the stack that a list item start tag
	// makes for an open item to close: the specification's special category,
	// less the address, div and p that the rule steps over.  A formatting
	// element is not one of them, which is the point: a browser closes the
	// item through it (#492).
	tagBalancingHTMLStreamEventReceiverListItemStartBarriers = tagBalancingHTMLStreamEventReceiverNewListItemStartBarriers()
	// tagBalancingHTMLStreamEventReceiverFormattingMarkers are the elements
	// on entering which a browser puts a marker on its list of active
	// formatting elements, so that an a opened inside one of them does not
	// end an a open outside it: the cell, caption and template elements, and
	// the legacy applet, marquee and object.
	tagBalancingHTMLStreamEventReceiverFormattingMarkers = tagBalancingHTMLStreamEventReceiverElementSet(
		"applet", "caption", "marquee", "object", "td", "template", "th")
	// tagBalancingHTMLStreamEventReceiverTransparent are the elements whose
	// content model is their parent's.
	tagBalancingHTMLStreamEventReceiverTransparent = tagBalancingHTMLStreamEventReceiverElementSet(
		"a", "audio", "canvas", "del", "ins", "map", "object", "video")
)

// tagBalancingHTMLStreamEventReceiverElementSet is the set of the named
// elements, indexed by element index.
func tagBalancingHTMLStreamEventReceiverElementSet(names ...string) []bool {
	set := make([]bool, tagBalancingHTMLStreamEventReceiverMetadata.NElementTypes())
	for _, name := range names {
		set[tagBalancingHTMLStreamEventReceiverMetadata.IndexForName(name)] = true
	}
	return set
}

func tagBalancingHTMLStreamEventReceiverNewListItemStartBarriers() []bool {
	metadata := tagBalancingHTMLStreamEventReceiverMetadata
	barriers := make([]bool, metadata.NElementTypes())
	for name := range htmlSanitizerSpecialHTMLElementNames() {
		index := metadata.IndexForName(name)
		if index != tagBalancingHTMLStreamEventReceiverUnrecognizedTag {
			barriers[index] = true
		}
	}
	for _, name := range []string{"address", "div", "p"} {
		barriers[metadata.IndexForName(name)] = false
	}
	// Names the specification calls special but current Chrome does not:
	// this receiver follows Chrome, as the input tracker does, so a list
	// item start walks past them.
	for name := range htmlSanitizerAmbiguouslySpecialHTMLElementNames() {
		barriers[metadata.IndexForName(name)] = false
	}
	// An option is not special for a browser, but a list this receiver
	// opens inside one holds the item it writes for the list's content, and
	// closing that item for the next start tag would unwrite on the next
	// pass what this pass wrote.  The item stays where the output puts it.
	barriers[metadata.IndexForName("option")] = true
	barriers[metadata.IndexForName("optgroup")] = true
	return barriers
}

// tagBalancingHTMLStreamEventReceiverNestingLimitListener receives notice of
// start tags this receiver drops: those that would nest the output deeper
// than the nesting limit, and a form start a browser ignores while its form
// element pointer is set.
//
// This exists because the tag balancer runs upstream of the policy, and so
// upstream of the change reporter, which notices a discarded tag by watching
// for one that goes into the policy and does not come out.  A tag the
// balancer drops never reaches the policy at all, so without this it is
// invisible to a listener.
type tagBalancingHTMLStreamEventReceiverNestingLimitListener interface {
	// nestingLimitReached is given the canonical name of the tag that was
	// not emitted, which is the name it would have been forwarded under.
	nestingLimitReached(canonElementName string)
}

// tagBalancingHTMLStreamEventReceiverTextSuppressionPolicy is implemented by
// a policy that suppresses the text inside dropped elements beyond the fixed
// elementAndAttributePolicyBasedSanitizerPolicySkippableElementContent list,
// such as one built with DisallowTextIn.
//
// This receiver drops a start tag that would exceed the nesting limit before
// the policy sees it, and keeps the content of such an element suppressed on
// the policy's behalf (see droppedSkippableDepth).  It knows the fixed list
// itself; for anything else it has to ask.
type tagBalancingHTMLStreamEventReceiverTextSuppressionPolicy interface {
	// suppressesTextWhenDropped is true if text directly inside a dropped
	// canonElementName is suppressed rather than emitted where the element
	// was.
	suppressesTextWhenDropped(canonElementName string) bool
}

// tagBalancingHTMLStreamEventReceiverOpenTagOutputPolicy is implemented by a
// policy that can identify the element, if any, emitted by its most recent
// OpenTag call.  The balancer uses the output name when applying the
// formatting-marker rule for nested links: a marker the policy dropped cannot
// affect how a browser parses the sanitized output.
type tagBalancingHTMLStreamEventReceiverOpenTagOutputPolicy interface {
	// outputElementNameForLastOpenTag returns the canonical emitted name, or
	// false if no element was emitted.
	outputElementNameForLastOpenTag() (string, bool)

	// outputElementForLastOpenTagUsedForeignContentRules is whether that
	// output element was inserted using SVG or MathML rules.
	outputElementForLastOpenTagUsedForeignContentRules() bool

	// outputSelectRetiredForLastOpenTag is whether that call closed an HTML
	// select still open on this stack.
	outputSelectRetiredForLastOpenTag() bool

	// inputSelectRetiredForLastOpenTag is whether the retired output select
	// was the matching input select.
	inputSelectRetiredForLastOpenTag() bool

	// hasOpenHTMLOutputSelect is whether the current serialized-output scope
	// has an HTML select open.
	hasOpenHTMLOutputSelect() bool

	// hasOpenHTMLOutputListItem is whether an HTML list item is still open in
	// the emitted stream.
	hasOpenHTMLOutputListItem() bool

	// hasOpenHTMLOutputList is whether an HTML ordered or unordered list is
	// open in the output.
	hasOpenHTMLOutputList() bool

	// outputNestingDepth is the number of non-void elements currently open in
	// the emitted stream.
	outputNestingDepth() int

	// outputContainerElementName is the innermost non-void element currently
	// open in the emitted stream, or false if there is none.
	outputContainerElementName() (string, bool)
}

// tagBalancingHTMLStreamEventReceiverPushedOutTablePolicy holds optional
// policy operations used to keep output around a pushed-out table in a
// browser context that matches the logical input context.
type tagBalancingHTMLStreamEventReceiverPushedOutTablePolicy interface {
	// supportsPushedOutTableOperations is whether the operations below are
	// available for the current policy.
	supportsPushedOutTableOperations() bool

	// openTagWithoutOutput applies element and text policy while
	// deliberately emitting no tag.
	openTagWithoutOutput(elementName string, attrs []string)

	// openTagWithoutOutputWithInheritedTextGate stacks no output element and
	// keeps the current output text gate.
	openTagWithoutOutputWithInheritedTextGate(elementName string, attrs []string)

	// openTagWithoutOutputOrContent applies policy while deliberately
	// emitting neither tag nor contents.
	openTagWithoutOutputOrContent(elementName string, attrs []string)

	// openTagWithSuppressedContent emits a kept start while suppressing
	// everything through its end.
	openTagWithSuppressedContent(elementName string, attrs []string)

	// openTablePartWithInheritedTextGate emits a table part while retaining
	// the enclosing output text gate.
	openTablePartWithInheritedTextGate(elementName string, attrs []string)

	// isSuppressingOutputAndContent is whether a prior suppressed start still
	// suppresses its input subtree.
	isSuppressingOutputAndContent() bool

	// isSuppressingText is whether the current policy text gate suppresses
	// text.
	isSuppressingText() bool

	// openReopenedTable emits a synthetic table only if policy keeps it as a
	// table.
	openReopenedTable(attrs []string)

	// reopenedTableWasRenamed is whether the last synthetic table was
	// suppressed after being renamed.
	reopenedTableWasRenamed() bool

	// isOutputInForeignContent reports the browser context of the elements
	// actually emitted.
	isOutputInForeignContent() bool

	// outputForeignContentRootName is the outermost foreign root the policy
	// has emitted, or false if there is none.
	outputForeignContentRootName() (string, bool)

	// outputStartTagUsesForeignContentRules is whether the current output
	// context applies foreign rules to this start tag.
	outputStartTagUsesForeignContentRules(elementName string, attrs []string) bool

	// outputTemplateStartTagUsesForeignContentRules is whether this start is
	// foreign inside retained HTML template contents.
	outputTemplateStartTagUsesForeignContentRules(elementName string, attrs []string) bool

	// outputStartTagUsesHTMLIntegrationPointRules is whether an HTML start is
	// handled at a foreign integration point.
	outputStartTagUsesHTMLIntegrationPointRules(elementName string, attrs []string) bool
}

// tagBalancingHTMLStreamEventReceiverFormPointerPolicy is optional
// normalization for the HTML form-element pointer.
//
// A policy that has nothing to do for openRetiredFormTextContext,
// pushOutTableAroundRetiredForm, closeRetiredFormTextContext,
// hasRetiredFormTextContext, retiredFormTextContextAllowsEndTag or
// isInKeptLiteralElement implements them to do nothing and return false,
// except retiredFormTextContextAllowsEndTag, which then returns true.
type tagBalancingHTMLStreamEventReceiverFormPointerPolicy interface {
	// formStartTagUsesTableRules is whether the policy output is in a table
	// mode that pops a form at once.
	formStartTagUsesTableRules() bool

	// outputFormElementPointerIsSet is whether the policy output already has
	// a non-null form pointer.
	outputFormElementPointerIsSet() bool

	// prepareForFormStart prepares the next form open and reports whether it
	// will emit an HTML form.  The following open call consumes the prepared
	// policy result.  The attribute policies edit *attrs as they run, and
	// that open call passes the same list.
	prepareForFormStart(attrs *[]string) bool

	// prepareForStartTag prepares any start tag and returns the output name,
	// or false if no element will be emitted.  As for prepareForFormStart,
	// the attribute policies edit *attrs, and the open call that consumes the
	// result passes the same list.
	prepareForStartTag(elementName string, attrs *[]string) (string, bool)

	// preparedFormStartWillEmitAsHTML is whether the prepared form would be
	// an HTML form outside a template.
	preparedFormStartWillEmitAsHTML() bool

	// discardPreparedFormStart discards a prepared form result when the
	// output ignores its start.
	discardPreparedFormStart()

	// openRetiredFormTextContext keeps a logical policy entry for an HTML
	// form that the in-table rule popped from an implied table.  The form
	// was already opened, closed and reported; this entry carries only its
	// input-name text policy.
	openRetiredFormTextContext()

	// pushOutTableAroundRetiredForm moves that logical form outside an output
	// table as the table is pushed out for foster-parented content.  Returns
	// true when this method emitted the table suffix's close events itself.
	pushOutTableAroundRetiredForm() bool

	// closeRetiredFormTextContext removes that logical form for an effective
	// HTML form end tag without closing the output elements that remain
	// above it.
	closeRetiredFormTextContext() bool

	// hasRetiredFormTextContext is whether that logical form entry is still
	// open in the policy.
	hasRetiredFormTextContext() bool

	// retiredFormTextContextAllowsEndTag is whether the current output scope
	// lets an HTML form end reach it.
	retiredFormTextContextAllowsEndTag() bool

	// isInKeptLiteralElement is true while an emitted literal-output element
	// suppresses nested starts.
	isInKeptLiteralElement() bool

	// prepareOutputForHTMLStart closes an incompatible output suffix before
	// an HTML start is emitted.
	prepareOutputForHTMLStart(adjustedElementName string, attrs []string)

	// clearFormPointerWithBalancedPair clears an output form pointer while
	// table scope keeps its form element on the browser stack, using a
	// balanced pair whose start is ignored.
	clearFormPointerWithBalancedPair() bool

	// retireOutputTableForForm closes an output table while preserving its
	// logical descendants.
	retireOutputTableForForm(allowInputTable bool) bool

	// retireOutputSelectForHTMLStart closes an output select before an HTML
	// start changes insertion mode.
	retireOutputSelectForHTMLStart() bool
}

// newAttrList returns an empty attribute list for a start tag this receiver
// makes up.  Its backing array is its own, so a policy that recognizes the
// list it prepared a start tag with by identity never mistakes one made-up
// list for another.
func newAttrList() []string {
	return make([]string, 0, 1)
}

func (b *TagBalancingHTMLStreamEventReceiver) contentIsSkippable(canonElementName string) bool {
	if _, ok := elementAndAttributePolicyBasedSanitizerPolicySkippableElementContent[canonElementName]; ok {
		return true
	}
	return b.textSuppressionPolicy != nil &&
		b.textSuppressionPolicy.suppressesTextWhenDropped(canonElementName)
}

// reportDroppedStartTag tells the listener, if any, of a start tag dropped
// here, which the policy therefore never sees: one the nesting limit drops,
// or a form start a browser ignores while its form element pointer is set.
//
// canonElementName is the dropped tag's canonical name.  Every start tag is
// forwarded under its canonical name, so that is the name the policy would
// have been asked about, and the name a tag the policy drops is reported
// under.  Reporting the same name here lets a listener hear one name for a
// tag however it was dropped, even when a pre-processor handed this receiver
// the name in another case.
func (b *TagBalancingHTMLStreamEventReceiver) reportDroppedStartTag(canonElementName string) {
	if b.nestingLimitListener != nil {
		b.nestingLimitListener.nestingLimitReached(canonElementName)
	}
}

// NewTagBalancingHTMLStreamEventReceiver returns a balancer over underlying,
// an event receiver that should receive a stream of balanced events that is
// as close as possible to the stream of events received by the balancer.
func NewTagBalancingHTMLStreamEventReceiver(underlying HTMLStreamEventReceiver) *TagBalancingHTMLStreamEventReceiver {
	b := &TagBalancingHTMLStreamEventReceiver{
		underlying:   underlying,
		nestingLimit: math.MaxInt32,
	}
	b.nestingLimitListener, _ = underlying.(tagBalancingHTMLStreamEventReceiverNestingLimitListener)
	b.textSuppressionPolicy, _ = underlying.(tagBalancingHTMLStreamEventReceiverTextSuppressionPolicy)
	b.openTagOutputPolicy, _ = underlying.(tagBalancingHTMLStreamEventReceiverOpenTagOutputPolicy)
	b.tablePolicy, _ = underlying.(tagBalancingHTMLStreamEventReceiverPushedOutTablePolicy)
	b.formPointerPolicy, _ = underlying.(tagBalancingHTMLStreamEventReceiverFormPointerPolicy)
	b.passthroughIndicesByName = map[string][]int{}
	b.resetDocumentState()
	return b
}

// SetNestingLimit sets the maximum element nesting depth: the greatest
// number of elements that may be open at once.  A start tag that would nest
// the output deeper is dropped.  When the receiver below was built by
// (*PolicyFactory).ApplyWithListener, the listener hears of the dropped tag
// through DiscardedTag.  The limit may be changed while a
// document is open, but not to less than the depth already open.  After a
// receiver below panicked mid-document, call OpenDocument before lowering
// the limit: until then the depth judged is the abandoned document's.
//
// It returns an error, and leaves the limit unchanged, if elements are
// already open deeper than limit.  With no policy below to count its own
// output, the elements outside this receiver's containment metadata that it
// has forwarded, such as custom elements, count toward that depth.
func (b *TagBalancingHTMLStreamEventReceiver) SetNestingLimit(limit int) error {
	b.resetMappedForeignTableSuppressionIfPolicyEnded()
	b.resetDroppedSuppressedTableIfPolicyEnded()
	b.resetDroppedSuppressedOptionIfPolicyEnded()
	depth := b.effectiveNestingDepth()
	if depth > limit {
		return fmt.Errorf(
			"Cannot set the nesting limit to %d: elements are already open %d deep",
			limit, depth)
	}
	b.nestingLimit = limit
	return nil
}

// effectiveNestingDepth is how deep the output nests, which is what the
// limit bounds.
//
// A policy counts every element it has open, the forwarded ones it emitted
// included, so its own depth already covers them.  One it dropped nests
// nothing and must not consume the budget: counting those made a run of
// unknown tags a policy drops, such as the o:p of pasted word processor
// markup, strip everything after it.  With no policy to ask, every forwarded
// element reached the receiver below and nests there.
func (b *TagBalancingHTMLStreamEventReceiver) effectiveNestingDepth() int {
	depth := len(b.openElements) - b.neverSentImpliedListItemCount()
	if b.openTagOutputPolicy != nil {
		depth = max(depth, b.openTagOutputPolicy.outputNestingDepth())
	} else {
		depth += len(b.passthroughNames)
	}
	return depth
}

// outputNestingDepth is the number of elements that are physically open in
// the emitted stream.
func (b *TagBalancingHTMLStreamEventReceiver) outputNestingDepth() int {
	if b.openTagOutputPolicy != nil {
		return b.openTagOutputPolicy.outputNestingDepth()
	}
	depth := len(b.passthroughNames)
	for i := len(b.openElements) - 1; i >= 0; i-- {
		if b.sentToUnderlying.get(i) && !b.pushedOut.get(i) &&
			b.outputElements[i] != tagBalancingHTMLStreamEventReceiverNoOutputElement {
			depth++
		}
	}
	return depth
}

// neverSentImpliedListItemCount is how many browser-ignored implied list
// items are on the stack.  They are never sent below, so they nest nothing
// in the output and must not consume the budget: content that fit the limit
// when its wrapper was implied has to fit again when the wrapper is
// explicit.
func (b *TagBalancingHTMLStreamEventReceiver) neverSentImpliedListItemCount() int {
	n := 0
	for i := len(b.openElements) - 1; i > 0; i-- {
		if b.isNeverSentImpliedListItem(i) {
			n++
		}
	}
	return n
}

// isNeverSentImpliedListItem is whether the entry is an implied item that
// nests no output.
func (b *TagBalancingHTMLStreamEventReceiver) isNeverSentImpliedListItem(stackIndex int) bool {
	return stackIndex >= 0 &&
		b.openElements[stackIndex] == tagBalancingHTMLStreamEventReceiverLiTag &&
		b.inputElementSerials[stackIndex] == 0 &&
		b.outputElements[stackIndex] == tagBalancingHTMLStreamEventReceiverNoOutputElement &&
		!b.sentToUnderlying.get(stackIndex)
}

// OpenDocument starts a document, forgetting anything left of a previous
// one.
func (b *TagBalancingHTMLStreamEventReceiver) OpenDocument() {
	b.resetDocumentState()
	b.underlying.OpenDocument()
}

// CloseDocument closes every element still open and ends the document.
func (b *TagBalancingHTMLStreamEventReceiver) CloseDocument() {
	b.retirePendingUnrecognizedHTMLTextElement()
	b.resetMappedForeignTableSuppressionIfPolicyEnded()
	b.resetDroppedSuppressedTableIfPolicyEnded()
	b.syncOutputSelectState()
	b.resetDroppedSuppressedOptionIfPolicyEnded()
	for i := len(b.openElements) - 1; i >= 0; i-- {
		b.closePassthroughsInside(i, true)
		if !b.shouldSendClose(i) {
			continue
		}
		elIndex := b.openElements[i]
		elname := tagBalancingHTMLStreamEventReceiverMetadata.CanonNameForIndex(elIndex)
		b.underlying.CloseTag(elname)
	}
	for len(b.passthroughNames) != 0 {
		b.popPassthrough(true)
	}
	b.resetDocumentState()
	b.underlying.CloseDocument()
}

// resetDocumentState returns every field that describes the document being
// balanced to its value in a new instance.  Both OpenDocument and
// CloseDocument call this, so nothing of one document is left for a caller
// to see, or the next document to inherit, whichever of the two is called
// next.  The nesting limit is configuration rather than document state and
// is kept.
func (b *TagBalancingHTMLStreamEventReceiver) resetDocumentState() {
	b.openElements = b.openElements[:0]
	b.inputElementSerials = b.inputElementSerials[:0]
	b.outputElements = b.outputElements[:0]
	b.sentToUnderlying.clearAll()
	b.inputElementsInForeignContent.clearAll()
	b.outputElementsInForeignContent.clearAll()
	b.outputElementsStartForeignContent.clearAll()
	b.formPointerTargets.clearAll()
	b.clearedFormPointerTargets.clearAll()
	b.staleOutputFormPointerTargets.clearAll()
	b.pushedOut.clearAll()
	b.impliedInputTables.clearAll()
	b.outputlessImpliedSelects.clearAll()
	b.outputTableUnavailable.clearAll()
	b.toResumeInReverse = b.toResumeInReverse[:0]
	b.resumeOnlyOutsideRawText = b.resumeOnlyOutsideRawText[:0]
	b.resumedFormattingFromListItemStart.clearAll()
	b.closingListItemForStart = false
	b.currentStartClosedListItem = false
	b.passthroughNames = b.passthroughNames[:0]
	b.passthroughSpecialTextModeDepth = 0
	clear(b.passthroughIndicesByName)
	b.passthroughDepths = b.passthroughDepths[:0]
	b.passthroughSerials = b.passthroughSerials[:0]
	b.passthroughOutputForeign.clearAll()
	b.passthroughForeignRoots = b.passthroughForeignRoots[:0]
	b.outputlessTablesWithEmittedParts.clearAll()
	b.outputlessImpliedListAfterEmittedItem = -1
	b.outputSelectHasText = false
	b.outputSelectWasOpen = false
	b.outputListItemAfterClosedSelect = -1
	b.htmlInputSelectIsOpen = false
	b.pushedMappedTemplateOutputOpen.clearAll()
	b.suppressedMappedForeignSubtrees.clearAll()
	b.foreignContent = newHTMLSanitizerForeignContentContext()
	b.foreignRootPendingTableReturn = nil
	b.pendingUnrecognizedHTMLTextElement = nil
	b.policyOnlyTableMayBeOpen = false
	b.preparingPreparedPolicyStart = false
	b.insertionPointIsInForeignContent = false
	b.outputlessTablePartsMayBeOpen = false
	b.outputlessTablePartsOpenedAtEvent = -1
	b.openTagEvent = 0
	b.droppedSkippableDepth = 0
	b.droppedSuppressedOptionDepth = 0
	b.droppedSuppressedOptionOwnsPolicyEntry = false
	b.droppedSuppressedOptionStackDepth = -1
	b.droppedSuppressedOptionPassthroughDepth = -1
	b.droppedSuppressedOptionResumeDepth = -1
	b.droppedSuppressedTableDepth = 0
	b.suppressedMappedForeignTableResumeDepth = -1
}

// OpenTag balances a start tag: it closes what cannot contain the element,
// opens what the element needs around it, and forwards it unless it would
// nest the output past the limit.
func (b *TagBalancingHTMLStreamEventReceiver) OpenTag(elementName string, attrs []string) {
	b.retirePendingUnrecognizedHTMLTextElement()
	b.resetMappedForeignTableSuppressionIfPolicyEnded()
	b.resetDroppedSuppressedTableIfPolicyEnded()
	b.syncOutputSelectState()
	b.currentStartClosedListItem = false
	b.openTagEvent++
	canonElementName := htmlLexerCanonicalElementName(elementName)

	elIndex := tagBalancingHTMLStreamEventReceiverMetadata.IndexForName(canonElementName)
	inputTemplateWasOpen := b.hasOpenTemplateElement()
	inputSelectWasOpen := b.htmlInputSelectIsOpen
	if inputSelectWasOpen && !inputTemplateWasOpen &&
		tagBalancingHTMLStreamEventReceiverExitsHTMLSelect(canonElementName) {
		b.htmlInputSelectIsOpen = false
	}
	b.closeOpenHTMLOptionForStart(elIndex)
	parsingTemplateContents := elIndex == tagBalancingHTMLStreamEventReceiverFormTag &&
		b.hasOpenTemplateElement()
	formElementPointerWasSet := elIndex == tagBalancingHTMLStreamEventReceiverFormTag &&
		b.foreignContent.formElementPointerIsSet()
	foreignRootBefore, hasForeignRootBefore := b.foreignContent.outermostForeignElementName()
	_, hasOutputForeignRootBefore := b.outputForeignContentRootName()
	outputUsesForeignContentRules := b.outputStartTagUsesForeignContentRules(canonElementName, attrs)
	outputUsesHTMLIntegrationPointRules := b.outputStartTagUsesHTMLIntegrationPointRules(canonElementName, attrs)
	// Judged before this tag: queued formatting is resumed in front of it,
	// and a tag that breaks out of foreign content is still inserted after
	// the browser pops the foreign nodes, not before.
	b.insertionPointIsInForeignContent = b.textIsInForeignContent()
	b.foreignContent.processStartTag(canonElementName, attrs, false)
	usesForeignContentRules := b.foreignContent.lastTagUsedForeignContentRules()
	if elIndex == tagBalancingHTMLStreamEventReceiverSelectTag && !inputSelectWasOpen &&
		!inputTemplateWasOpen && !usesForeignContentRules {
		b.htmlInputSelectIsOpen = true
	}
	// The HTML form-pointer rules apply to an HTML form outside template
	// contents.  When the input tracker can no longer tell HTML from foreign
	// content, follow the output: a browser parsing it consults the pointer
	// only outside SVG and MathML, so a form emitted inside a foreign root
	// must not be dropped, or latch the pointer, as if it were HTML.
	formUsesHTMLPointerRules := elIndex == tagBalancingHTMLStreamEventReceiverFormTag &&
		!usesForeignContentRules &&
		!parsingTemplateContents &&
		!(b.foreignContent.isUnknown() && hasOutputForeignRootBefore)
	startSerial := b.foreignContent.lastStartTagPushedSerial()
	tablePolicyAtStart := b.pushedOutTablePolicy()
	suppressingPolicySubtree := tablePolicyAtStart != nil &&
		tablePolicyAtStart.isSuppressingOutputAndContent()
	if b.droppedSuppressedOptionDepth != 0 && !suppressingPolicySubtree {
		b.resetDroppedSuppressedOption()
	}
	optionInForeignMappedSelect := elIndex == tagBalancingHTMLStreamEventReceiverOptionTag &&
		outputUsesForeignContentRules &&
		b.hasInputTableMappedToForeignSelectInScope()
	if optionInForeignMappedSelect {
		// The policy result cannot be queried without consuming its stateful
		// element policy.  If it renames option, the first and second parse
		// use different HTML/foreign insertion rules.  Fail closed for this
		// rare policy-produced context, including the option's contents.
		if b.droppedSuppressedOptionDepth != 0 {
			if b.droppedSuppressedOptionDepth != math.MaxInt32 {
				b.droppedSuppressedOptionDepth++
			}
			b.reportDroppedStartTag(canonElementName)
		} else if b.effectiveNestingDepth() >= b.nestingLimit {
			if !suppressingPolicySubtree {
				// The policy-only suppression entry owns a stack entry below
				// even though nothing is emitted for it.
				tablePolicyAtStart.openTagWithoutOutputOrContent(canonElementName, attrs)
				b.droppedSuppressedOptionOwnsPolicyEntry = true
				b.droppedSuppressedOptionStackDepth = len(b.openElements)
				b.droppedSuppressedOptionPassthroughDepth = len(b.passthroughNames)
				b.droppedSuppressedOptionResumeDepth = len(b.toResumeInReverse)
			} else {
				b.droppedSuppressedOptionStackDepth = len(b.openElements)
				b.droppedSuppressedOptionResumeDepth = -1
				b.reportDroppedStartTag(canonElementName)
			}
			b.droppedSuppressedOptionDepth = 1
		} else {
			tablePolicyAtStart.openTagWithoutOutputOrContent(canonElementName, attrs)
			b.stackElementWithoutOutput(elIndex, usesForeignContentRules, startSerial)
		}
		return
	}
	if formUsesHTMLPointerRules {
		if formElementPointerWasSet {
			// Outside template contents, a browser ignores another form start
			// while its form element pointer is set.  It never reaches the
			// policy, so a listener hears of it from here, as of a tag the
			// nesting limit drops.
			b.reportDroppedStartTag(canonElementName)
			return
		}
		// The foreign content context may have become unknown while
		// retaining the independently knowable pointer state, so keep that
		// state synchronized here for forms accepted after the unknown
		// region.
		b.foreignContent.markFormElementPointerSet()
	}
	if !b.pushedOut.isEmpty() && hasForeignRootBefore && !usesForeignContentRules {
		if _, ok := b.foreignContent.outermostForeignElementName(); !ok {
			b.foreignRootPendingTableReturn = nil
			if hasOutputForeignRootBefore {
				b.foreignRootPendingTableReturn = &foreignRootBefore
			}
		}
	}
	mayOpenAtNestingLimit := true
	if tagBalancingHTMLStreamEventReceiverIsForeignContentRoot(canonElementName) &&
		!usesForeignContentRules &&
		b.foreignRootArrivesInTableMode() {
		// An SVG or MathML root that HTML rules insert in a table insertion
		// mode is foster-parented like any other content there, after an
		// open column group is popped.  Anywhere else a browser inserts it
		// where it is, so the containment metadata, which has no entry for it
		// and would imply a list item or select wrapper around it, is not
		// consulted.
		mayOpenAtNestingLimit = b.prepareForNewContent(elIndex, true, false)
	}
	_, inputHasForeignRoot := b.foreignContent.outermostForeignElementName()
	if (usesForeignContentRules ||
		inputHasForeignRoot ||
		b.foreignRootPendingTableReturn != nil ||
		b.hasPushedOutputlessTableWithEmittedParts()) &&
		outputUsesForeignContentRules &&
		tagBalancingHTMLStreamEventReceiverTableParts[elIndex] &&
		b.isOutputInForeignContent() &&
		!b.containerHasSpecialTextMode() {
		// HTML table balancing does not apply to SVG or MathML descendants,
		// even when a local name happens to be a table part.  A part whose
		// output would be foreign is forwarded as the foreign element the
		// output parser makes of it, whether the input had it under foreign
		// rules too, or at an integration point the policy dropped, or under
		// an HTML element inside one, where a browser ignores the part in the
		// input and an implied HTML table in the output would break out of
		// the root and turn every SVG or MathML sibling after it into HTML
		// (#492).  An integration point the output keeps makes the output
		// rules HTML too, so the part takes the table path; so does a part
		// arriving once the input parser's context is unknown, where the
		// input tracker names no root, and one in a node this receiver's
		// lexer reads as raw text, a recased SVG textArea, where HTML
		// containment closes that node first.
		if b.effectiveNestingDepth() >= b.nestingLimit {
			b.reportDroppedStartTag(canonElementName)
			return
		}
		b.underlying.OpenTag(canonElementName, attrs)
		b.pushPassthrough(canonElementName, startSerial)
		return
	}
	// Treat unrecognized tags as void, but emit closing tags in CloseTag.
	// They go below under their canonical name, like recognized tags: the
	// policy prepares its result under that name, and a preprocessor can hand
	// this receiver a name in a case the lexer would not.
	if elIndex == tagBalancingHTMLStreamEventReceiverUnrecognizedTag {
		b.openUnrecognizedTag(
			canonElementName, attrs, startSerial, mayOpenAtNestingLimit,
			usesForeignContentRules, suppressingPolicySubtree,
			hasOutputForeignRootBefore)
		return
	}

	if elIndex == tagBalancingHTMLStreamEventReceiverATag {
		// A browser ends a link when the next begins, and drops the old link
		// from its list of active formatting elements, so a link closed with
		// an earlier container and queued to resume is not resumed around
		// content after the new one either.
		b.forgetQueuedFormatting(tagBalancingHTMLStreamEventReceiverATag)
	}
	formTableContext := -1
	if elIndex == tagBalancingHTMLStreamEventReceiverFormTag {
		formTableContext = b.formStartTagTableContext(
			usesForeignContentRules, outputUsesForeignContentRules)
	}
	// HTML containment is for an HTML element.  A start tag that the output
	// parser inserts as an SVG or MathML element goes into the current
	// foreign node there: the HTML element below the foreign root implies no
	// wrapper for it and does not close for it, as for a start tag at an HTML
	// integration point.  The list item the metadata implies for a list's
	// content used to land inside a forwarded svg that way, and li is a
	// breakout name, so a browser popped the svg and read the SVG textarea or
	// a that followed as HTML (#492).  The output decides: an element the
	// input parser read as HTML at an integration point the policy dropped is
	// foreign in the output all the same.  A form there has no HTML form
	// pointer either.  Three exceptions keep HTML containment: an input whose
	// parser context is unknown, where the input tracker names no root, since
	// the output alone is not trusted then (a form under a root still closes
	// the form before it); a table part, which is forwarded above when the
	// input names a root; and a foreign node whose name this receiver's lexer
	// reads as raw text, an SVG textArea written out in lower case by a
	// policy, where elements nested in it would be read back as its text, so
	// the HTML containment that closes it first stays.
	insertsIntoForeignNode := outputUsesForeignContentRules &&
		(usesForeignContentRules || inputHasForeignRoot) &&
		!tagBalancingHTMLStreamEventReceiverTableParts[elIndex] &&
		!b.containerHasSpecialTextMode()
	if !suppressingPolicySubtree &&
		(!outputUsesHTMLIntegrationPointRules || tagBalancingHTMLStreamEventReceiverTableParts[elIndex]) &&
		!insertsIntoForeignNode {
		mayOpenAtNestingLimit = b.prepareForNewContent(
			elIndex,
			elIndex != tagBalancingHTMLStreamEventReceiverTableTag || !b.hasUnavailableInputTableInScope(),
			false) && mayOpenAtNestingLimit
	}
	suppressingPolicySubtree = tablePolicyAtStart != nil &&
		tablePolicyAtStart.isSuppressingOutputAndContent()

	if !mayOpenAtNestingLimit || b.effectiveNestingDepth() >= b.nestingLimit {
		b.retireContainerForUnemittedListChild(elIndex)
		if formUsesHTMLPointerRules {
			// Dropped at the limit, as below: not in the output, so no
			// pointer.
			b.foreignContent.clearFormElementPointer()
		}
		if elIndex == tagBalancingHTMLStreamEventReceiverTableTag &&
			suppressingPolicySubtree &&
			b.suppressedMappedForeignTableIndex() >= 0 &&
			b.droppedSuppressedTableDepth != math.MaxInt32 {
			b.droppedSuppressedTableDepth++
		}
		if b.contentIsSkippable(canonElementName) {
			b.droppedSkippableDepth++
		}
		b.reportDroppedStartTag(canonElementName)
		return
	}

	formPolicy := b.formPointerPolicy
	formStartPrepared := false
	preparedFormWillEmitAsHTML := false
	suppressPreparedOutputForm := false
	suppressedMappedForeignTemplateStart := false
	suppressMappedForeignTableContents := false
	preparedOutputName, hasPreparedOutput := "", false
	outputTableContext := b.outputTableContextForStart()
	if formPolicy != nil && !suppressingPolicySubtree {
		preparedOutputName, hasPreparedOutput = formPolicy.prepareForStartTag(canonElementName, &attrs)
		func() {
			b.preparingPreparedPolicyStart = true
			defer func() { b.preparingPreparedPolicyStart = false }()
			canonPreparedOutputName := ""
			if hasPreparedOutput {
				canonPreparedOutputName = htmlLexerCanonicalElementName(preparedOutputName)
			}
			formStartPrepared = elIndex == tagBalancingHTMLStreamEventReceiverFormTag
			preparedFormWillEmitAsHTML = formStartPrepared &&
				formPolicy.preparedFormStartWillEmitAsHTML()
			if hasPreparedOutput &&
				canonPreparedOutputName == "li" &&
				b.outputSelectHasText &&
				b.outputlessListIsCurrentContainer() &&
				formPolicy.retireOutputSelectForHTMLStart() {
				b.markOutputSelectRetired()
			}
			if hasPreparedOutput &&
				canonPreparedOutputName == "style" &&
				b.hasDroppedTableInSyntheticSelectListItemContext() {
				if formPolicy.retireOutputSelectForHTMLStart() {
					b.markOutputSelectRetired()
				}
			}
			if hasPreparedOutput &&
				(usesForeignContentRules ||
					(b.outputContainerIsParagraph() &&
						(canonElementName != canonPreparedOutputName ||
							canonPreparedOutputName == "p" ||
							(elIndex == tagBalancingHTMLStreamEventReceiverFormTag &&
								preparedFormWillEmitAsHTML &&
								!b.hasUnavailableInputTableInScope()))) ||
					(b.outputContainerIsAnchor() && canonPreparedOutputName == "a")) &&
				!(usesForeignContentRules &&
					b.foreignContent.lastStartTagOpenedIntegrationPoint() &&
					canonPreparedOutputName != "table") &&
				!b.outputStartTagUsesForeignContentRules(preparedOutputName, attrs) {
				preparedOutputIndex := tagBalancingHTMLStreamEventReceiverMetadata.IndexForName(canonPreparedOutputName)
				if preparedOutputIndex != tagBalancingHTMLStreamEventReceiverUnrecognizedTag &&
					(canonElementName != preparedOutputName || usesForeignContentRules) {
					mayOpenAtNestingLimit = b.prepareForNewContent(preparedOutputIndex, false, false) &&
						mayOpenAtNestingLimit
				}
				// A table part inside literal output will be deferred by the
				// policy, so it must not retire that literal output during
				// preflight.
				if !(tagBalancingHTMLStreamEventReceiverTableParts[elIndex] &&
					formPolicy.isInKeptLiteralElement() &&
					b.hasOpenLiteralOutputFromImpliedTable()) {
					formPolicy.prepareOutputForHTMLStart(preparedOutputName, attrs)
				}
				outputTableContext = b.outputTableContextForStart()
			}
			suppressPreparedOutputForm = elIndex != tagBalancingHTMLStreamEventReceiverFormTag &&
				hasPreparedOutput &&
				(b.shouldSuppressUnalignedOutputStart(
					canonElementName, preparedOutputName, outputTableContext, formPolicy) ||
					(canonElementName != canonPreparedOutputName &&
						(outputTableContext != -1 ||
							!b.pushedOut.isEmpty() ||
							b.hasUnavailableInputTableInScope()) &&
						!b.outputStartTagUsesForeignContentRules(preparedOutputName, attrs) &&
						tagBalancingHTMLStreamEventReceiverHasSpecialTextMode(
							tagBalancingHTMLStreamEventReceiverMetadata.IndexForName(
								stringsToLowerCase(preparedOutputName)))))
			suppressedMappedForeignTemplateStart = suppressPreparedOutputForm &&
				elIndex == tagBalancingHTMLStreamEventReceiverTemplateTag &&
				tagBalancingHTMLStreamEventReceiverIsForeignContentRoot(preparedOutputName)
			suppressMappedForeignTableContents = elIndex == tagBalancingHTMLStreamEventReceiverTableTag &&
				hasPreparedOutput &&
				canonPreparedOutputName == "select" &&
				!b.hasUnavailableInputTableInScope() &&
				(b.outputStartTagUsesForeignContentRules(preparedOutputName, attrs) ||
					b.outputTemplateStartTagUsesForeignContentRules(preparedOutputName, attrs))
			if hasPreparedOutput &&
				outputTableContext != -1 &&
				b.outputStartNeedsTablePreparation(
					canonElementName, preparedOutputName, outputTableContext) {
				if !suppressPreparedOutputForm {
					b.prepareForOutputStart(preparedOutputName, attrs, outputTableContext)
				}
				if elIndex == tagBalancingHTMLStreamEventReceiverFormTag {
					formTableContext = b.formStartTagTableContext(
						usesForeignContentRules, outputUsesForeignContentRules)
				}
			}
		}()
	}
	if elIndex == tagBalancingHTMLStreamEventReceiverFormTag &&
		formPolicy != nil &&
		formStartPrepared &&
		preparedFormWillEmitAsHTML &&
		b.foreignContent.isUnknown() &&
		hasOutputForeignRootBefore &&
		b.hasUnavailableInputTableInScope() &&
		formPolicy.outputFormElementPointerIsSet() {
		// The input tracker cannot decide whether this form is HTML, but the
		// prepared output is at an integration point and has a form pointer.
		// A browser ignores the start there.  Do not leave a logical policy
		// entry that would imply a second dropped table around later cells,
		// and do not emit later table parts without the missing table.
		b.markNearestInputTableUnavailable()
		formPolicy.discardPreparedFormStart()
		b.reportDroppedStartTag(canonElementName)
		return
	}
	if !mayOpenAtNestingLimit || b.effectiveNestingDepth() >= b.nestingLimit {
		b.retireContainerForUnemittedListChild(elIndex)
		if formPolicy != nil {
			formPolicy.discardPreparedFormStart()
		}
		if formUsesHTMLPointerRules {
			// The pointer was set for this form above.  The form is not in
			// the output, so the output parser's pointer stays null, and a
			// later form must not be ignored on its account.
			b.foreignContent.clearFormElementPointer()
		}
		if b.contentIsSkippable(canonElementName) {
			b.droppedSkippableDepth++
		}
		b.reportDroppedStartTag(canonElementName)
		return
	}
	if elIndex == tagBalancingHTMLStreamEventReceiverFormTag &&
		formTableContext != -1 &&
		formPolicy != nil &&
		formPolicy.outputFormElementPointerIsSet() {
		if !formStartPrepared {
			preparedFormWillEmitAsHTML = formPolicy.prepareForFormStart(&attrs)
			formStartPrepared = true
		}
		if preparedFormWillEmitAsHTML {
			// The output parser ignores this start because its pointer is
			// set.  Do not send an end tag either: it would clear the
			// existing pointer.
			formPolicy.discardPreparedFormStart()
			b.retireOutputTableForForm(formTableContext)
			if usesForeignContentRules {
				b.stackForeignFormWithoutOutput(startSerial)
			}
			return
		}
	}
	if elIndex == tagBalancingHTMLStreamEventReceiverFormTag &&
		!b.clearedFormPointerTargets.isEmpty() {
		formWillEmitAsHTML := preparedFormWillEmitAsHTML
		if !formStartPrepared {
			formWillEmitAsHTML = b.formWillEmitAsHTML(&attrs)
		}
		if formWillEmitAsHTML {
			b.retireClearedOutputFormPointer()
			formTableContext = b.formStartTagTableContext(
				usesForeignContentRules, outputUsesForeignContentRules)
		}
	}
	var outputElementIndex int
	switch {
	case suppressPreparedOutputForm:
		tablePolicy := b.pushedOutTablePolicy()
		if hasPreparedOutput && htmlLexerCanonicalElementName(preparedOutputName) == "template" {
			tablePolicy.openTagWithoutOutputOrContent(canonElementName, attrs)
		} else {
			tablePolicy.openTagWithoutOutput(canonElementName, attrs)
		}
		outputElementIndex = tagBalancingHTMLStreamEventReceiverNoOutputElement
	case suppressMappedForeignTableContents:
		tablePolicyAtStart.openTagWithSuppressedContent(canonElementName, attrs)
		outputElementIndex = b.outputElementIndexForLastOpenTag(elIndex)
	default:
		outputElementIndex = b.openElement(elIndex, attrs, false)
	}
	ignoredNestedInputSelect := elIndex == tagBalancingHTMLStreamEventReceiverSelectTag &&
		outputElementIndex == tagBalancingHTMLStreamEventReceiverNoOutputElement &&
		b.openTagOutputPolicy != nil &&
		b.openTagOutputPolicy.outputSelectRetiredForLastOpenTag()
	outputElementIsForeign := b.lastOutputElementUsedForeignContentRules()
	if formTableContext != -1 {
		// The in-table rule inserts the form and immediately pops it.  Send a
		// balanced empty element downstream, but leave the input form pointer
		// set until an actual </form> arrives.
		keepRetiredFormTextContext := !usesForeignContentRules &&
			formTableContext >= 0 &&
			b.impliedInputTables.get(formTableContext) &&
			!outputElementIsForeign &&
			!b.hasOpenTemplateElement() &&
			!b.hasOpenHTMLInputSelect() &&
			!b.hasOpenHTMLOutputSelect() &&
			formPolicy != nil
		b.underlying.CloseTag(canonElementName)
		b.retireOutputTableForForm(formTableContext)
		if keepRetiredFormTextContext {
			// The table exists only because this receiver supplied it.  A
			// browser reading the input has no table here, so its form stays
			// on the stack and owns later text even though the serialized form
			// is the balanced empty element above.  Keep that input context
			// only in the policy; putting it on this stack changes
			// containment.
			formPolicy.openRetiredFormTextContext()
		}
		if usesForeignContentRules {
			b.stackForeignFormWithoutOutput(startSerial)
		}
	} else if !ignoredNestedInputSelect && !IsVoidElement(canonElementName) {
		stackIndex := len(b.openElements)
		b.openElements = append(b.openElements, elIndex)
		b.inputElementSerials = append(b.inputElementSerials, startSerial)
		b.outputElements = append(b.outputElements, outputElementIndex)
		b.resumedFormattingFromListItemStart.setTo(
			stackIndex, elIndex == tagBalancingHTMLStreamEventReceiverLiTag && b.currentStartClosedListItem)
		b.outputlessTablesWithEmittedParts.clear(stackIndex)
		b.outputlessImpliedSelects.clear(stackIndex)
		b.pushedMappedTemplateOutputOpen.clear(stackIndex)
		b.suppressedMappedForeignSubtrees.setTo(
			stackIndex, suppressedMappedForeignTemplateStart || suppressMappedForeignTableContents)
		if suppressMappedForeignTableContents {
			b.droppedSuppressedTableDepth = 0
			b.suppressedMappedForeignTableResumeDepth = len(b.toResumeInReverse)
		}
		b.sentToUnderlying.set(stackIndex)
		b.inputElementsInForeignContent.setTo(stackIndex, usesForeignContentRules)
		b.outputElementsInForeignContent.setTo(stackIndex, outputElementIsForeign)
		b.outputElementsStartForeignContent.setTo(
			stackIndex, outputElementIndex != tagBalancingHTMLStreamEventReceiverNoOutputElement &&
				b.lastOutputElementStartsForeignContent(canonElementName))
		b.clearedFormPointerTargets.clear(stackIndex)
		b.staleOutputFormPointerTargets.clear(stackIndex)
		b.impliedInputTables.clear(stackIndex)
		b.outputlessImpliedSelects.clear(stackIndex)
		if elIndex == tagBalancingHTMLStreamEventReceiverTableTag &&
			outputUsesHTMLIntegrationPointRules &&
			outputElementIndex != tagBalancingHTMLStreamEventReceiverTableTag &&
			outputElementIndex != tagBalancingHTMLStreamEventReceiverTemplateTag &&
			!outputElementIsForeign &&
			!b.outputElementsStartForeignContent.get(stackIndex) {
			b.outputTableUnavailable.set(stackIndex)
		}
		if formUsesHTMLPointerRules {
			b.formPointerTargets.clearAll()
			b.formPointerTargets.set(stackIndex)
		}
		b.recordEmittedPartForOutputlessTable(
			stackIndex+1, outputElementIndex, outputElementIsForeign)
	}
}

// openUnrecognizedTag handles the start of an element outside the
// containment metadata for OpenTag: it is forwarded without a stack entry,
// as a passthrough, after the output around it is prepared for whatever the
// policy will emit for it.
func (b *TagBalancingHTMLStreamEventReceiver) openUnrecognizedTag(
	canonElementName string, attrs []string, startSerial int,
	mayOpenAtNestingLimit, usesForeignContentRules, suppressingPolicySubtree,
	hasOutputForeignRootBefore bool,
) {
	if !mayOpenAtNestingLimit || b.effectiveNestingDepth() >= b.nestingLimit {
		if b.contentIsSkippable(canonElementName) {
			b.droppedSkippableDepth++
		}
		b.reportDroppedStartTag(canonElementName)
		return
	}
	policy := b.formPointerPolicy
	suppressPreparedOutput := false
	suppressForeignBreakoutBesidePushedTable := false
	leaveHTMLTextElementPending := false
	preparedOutputName, hasPreparedOutput := "", false
	if policy != nil && !suppressingPolicySubtree {
		preparedOutputName, hasPreparedOutput = policy.prepareForStartTag(canonElementName, &attrs)
		func() {
			b.preparingPreparedPolicyStart = true
			defer func() { b.preparingPreparedPolicyStart = false }()
			if !hasPreparedOutput {
				return
			}
			canonPreparedOutputName := htmlLexerCanonicalElementName(preparedOutputName)
			outputTableContext := b.outputTableContextForStart()
			// A foreign element beside a pushed-out table whose output would
			// be HTML, because the output's foreign root was popped by an
			// emitted breakout or the policy renamed the element, lands where
			// this receiver cannot follow it, so it is suppressed with its
			// contents.  That needs the output to have entered the foreign
			// region at all: when the policy dropped the root, or renamed it
			// to an HTML element, the elements inside it are ordinary HTML
			// beside the table, like their siblings, and go through like them.
			suppressForeignBreakoutBesidePushedTable = usesForeignContentRules &&
				!b.foreignContent.lastStartTagOpenedIntegrationPoint() &&
				!b.pushedOut.isEmpty() &&
				(hasOutputForeignRootBefore || b.forwardedForeignRootEnteredOutput()) &&
				canonPreparedOutputName != "table" &&
				!b.outputStartTagUsesForeignContentRules(preparedOutputName, attrs)
			if (usesForeignContentRules ||
				canonPreparedOutputName == "form" ||
				(b.outputContainerIsParagraph() && canonElementName != canonPreparedOutputName) ||
				(b.outputContainerIsAnchor() && canonPreparedOutputName == "a")) &&
				!suppressForeignBreakoutBesidePushedTable &&
				!(usesForeignContentRules &&
					b.foreignContent.lastStartTagOpenedIntegrationPoint() &&
					canonPreparedOutputName != "table") &&
				!b.outputStartTagUsesForeignContentRules(preparedOutputName, attrs) {
				if usesForeignContentRules && outputTableContext != -1 {
					b.prepareForOutputStart(preparedOutputName, attrs, outputTableContext)
				}
				policy.prepareOutputForHTMLStart(preparedOutputName, attrs)
				outputTableContext = b.outputTableContextForStart()
			}
			suppressPreparedOutput = b.shouldSuppressUnalignedOutputStart(
				canonElementName, preparedOutputName, outputTableContext, policy) ||
				suppressForeignBreakoutBesidePushedTable
			logicalTop := len(b.openElements) - 1
			exposedByExplicitOutputlessTable := b.topIsOutputlessInputTable() &&
				!b.impliedInputTables.get(logicalTop) &&
				(b.outputlessTablePartsMayBeOpen || b.outputlessTablesWithEmittedParts.get(logicalTop))
			exposedByTemplateAboveOutputlessTable := b.hasOutputTemplateAboveOutputlessTable() &&
				!b.hasOpenHTMLOutputSelect()
			isDirectHTMLTextArea := canonElementName == preparedOutputName &&
				stringsToLowerCase(preparedOutputName) == "textarea" &&
				!b.outputStartTagUsesForeignContentRules(preparedOutputName, attrs) &&
				!b.hasOpenHTMLOutputTable()
			deferHTMLTextElementClose := isDirectHTMLTextArea && exposedByTemplateAboveOutputlessTable
			directHTMLTextAreaOutsidePhysicalTable := isDirectHTMLTextArea &&
				!exposedByExplicitOutputlessTable &&
				!exposedByTemplateAboveOutputlessTable
			if directHTMLTextAreaOutsidePhysicalTable && b.topIsOutputlessInputTable() {
				top := len(b.openElements) - 1
				b.closeStackFrom(top, tagBalancingHTMLStreamEventReceiverTableTag, true)
			}
			if !directHTMLTextAreaOutsidePhysicalTable &&
				!deferHTMLTextElementClose &&
				(outputTableContext != -1 ||
					!b.pushedOut.isEmpty() ||
					b.hasUnavailableInputTableInScope() ||
					exposedByExplicitOutputlessTable) &&
				!b.outputStartTagUsesForeignContentRules(preparedOutputName, attrs) &&
				tagBalancingHTMLStreamEventReceiverHasSpecialTextMode(
					tagBalancingHTMLStreamEventReceiverMetadata.IndexForName(
						stringsToLowerCase(preparedOutputName))) {
				suppressPreparedOutput = true
			}
			leaveHTMLTextElementPending = deferHTMLTextElementClose
			if !suppressPreparedOutput &&
				outputTableContext != -1 &&
				b.outputStartNeedsTablePreparation(
					canonElementName, preparedOutputName, outputTableContext) {
				b.prepareForOutputStart(preparedOutputName, attrs, outputTableContext)
			}
			preparedOutputIndex := tagBalancingHTMLStreamEventReceiverMetadata.IndexForName(canonPreparedOutputName)
			// A foreign root the policy emits is prepared like one the input
			// wrote: only where a browser foster-parents it.
			preparedForeignRootInTableMode :=
				tagBalancingHTMLStreamEventReceiverIsForeignContentRoot(preparedOutputName) &&
					b.foreignRootArrivesInTableMode()
			if !suppressPreparedOutput &&
				(canonElementName != preparedOutputName || preparedForeignRootInTableMode) &&
				(preparedOutputIndex != tagBalancingHTMLStreamEventReceiverUnrecognizedTag ||
					preparedForeignRootInTableMode) {
				mayOpenAtNestingLimit = b.prepareForNewContent(preparedOutputIndex, false, false) &&
					mayOpenAtNestingLimit
			}
		}()
	}
	switch {
	case !mayOpenAtNestingLimit || b.effectiveNestingDepth() >= b.nestingLimit:
		if policy != nil {
			policy.discardPreparedFormStart()
		}
		if b.contentIsSkippable(canonElementName) {
			b.droppedSkippableDepth++
		}
		b.reportDroppedStartTag(canonElementName)
	case suppressPreparedOutput:
		tablePolicy := b.pushedOutTablePolicy()
		if suppressForeignBreakoutBesidePushedTable ||
			(hasPreparedOutput && htmlLexerCanonicalElementName(preparedOutputName) == "template") {
			tablePolicy.openTagWithoutOutputOrContent(canonElementName, attrs)
		} else {
			tablePolicy.openTagWithoutOutput(canonElementName, attrs)
		}
		b.pushPassthrough(canonElementName, startSerial)
	default:
		b.underlying.OpenTag(canonElementName, attrs)
		outputElementIndex := b.outputElementIndexForLastOpenTag(tagBalancingHTMLStreamEventReceiverUnrecognizedTag)
		b.pushPassthrough(canonElementName, startSerial)
		if leaveHTMLTextElementPending && b.openTagOutputPolicy != nil {
			if lastName, ok := b.openTagOutputPolicy.outputElementNameForLastOpenTag(); ok && preparedOutputName == lastName {
				pending := canonElementName
				b.pendingUnrecognizedHTMLTextElement = &pending
			}
		}
		if outputElementIndex == tagBalancingHTMLStreamEventReceiverTableTag {
			b.policyOnlyTableMayBeOpen = true
		}
	}
}

// shouldSuppressUnalignedOutputStart is whether a policy rename lacks enough
// input structure to balance safely.
func (b *TagBalancingHTMLStreamEventReceiver) shouldSuppressUnalignedOutputStart(
	inputElementName, outputElementName string, tableContext int,
	policy tagBalancingHTMLStreamEventReceiverFormPointerPolicy,
) bool {
	if inputElementName == htmlLexerCanonicalElementName(outputElementName) ||
		b.pushedOutTablePolicy() == nil {
		return false
	}
	outputElement := tagBalancingHTMLStreamEventReceiverMetadata.IndexForName(
		htmlLexerCanonicalElementName(outputElementName))
	tableOrListStructure := tagBalancingHTMLStreamEventReceiverTableParts[outputElement] ||
		outputElement == tagBalancingHTMLStreamEventReceiverLiTag ||
		outputElement == tagBalancingHTMLStreamEventReceiverOptionTag
	if tableContext == -1 &&
		b.pushedOut.isEmpty() &&
		!(b.hasOpenHTMLOutputTemplate() && tableOrListStructure) {
		return false
	}
	if inputElementName == "table" &&
		tagBalancingHTMLStreamEventReceiverIsForeignContentRoot(outputElementName) {
		// SVG and MathML use their own insertion rules, so table-part local
		// names can remain children of the mapped root without table
		// recovery.
		return false
	}
	if tagBalancingHTMLStreamEventReceiverHasSpecialTextMode(outputElement) {
		return true
	}
	if outputElementName == "form" {
		return tableContext != -1 && policy.preparedFormStartWillEmitAsHTML()
	}
	return tableOrListStructure ||
		outputElement == tagBalancingHTMLStreamEventReceiverSelectTag ||
		outputElement == tagBalancingHTMLStreamEventReceiverTemplateTag ||
		tagBalancingHTMLStreamEventReceiverIsForeignContentRoot(outputElementName)
}

// outputTableContextForStart is the nearest represented or policy-only HTML
// table insertion context, or -1.
func (b *TagBalancingHTMLStreamEventReceiver) outputTableContextForStart() int {
	if b.policyOnlyTableMayBeOpen {
		if policyContext := b.policyOnlyFormTableContext(); policyContext != -1 {
			return policyContext
		}
	}
	for i := len(b.openElements) - 1; i >= 0; i-- {
		if !b.sentToUnderlying.get(i) ||
			b.pushedOut.get(i) ||
			b.outputElementsInForeignContent.get(i) {
			continue
		}
		outputElement := b.outputElements[i]
		if outputElement == tagBalancingHTMLStreamEventReceiverNoOutputElement {
			continue
		}
		if tagBalancingHTMLStreamEventReceiverTableFormScopeBoundaries[outputElement] {
			return -1
		}
		if outputElement == tagBalancingHTMLStreamEventReceiverTableTag {
			return i
		}
	}
	return b.policyOnlyFormTableContext()
}

// preparePolicyStartInOutputTable prepares one policy result, which edits
// *attrs, and balances the output table around it.  It returns true when the
// caller should suppress the start it prepared.
func (b *TagBalancingHTMLStreamEventReceiver) preparePolicyStartInOutputTable(
	inputElementName string, attrs *[]string,
) bool {
	if b.preparingPreparedPolicyStart || b.formPointerPolicy == nil {
		return false
	}
	policy := b.formPointerPolicy
	preparedOutputName, ok := policy.prepareForStartTag(inputElementName, attrs)
	if !ok {
		return false
	}
	outputTableContext := b.outputTableContextForStart()
	if outputTableContext == -1 {
		return false
	}
	if inputElementName != "form" &&
		preparedOutputName == "form" &&
		b.pushedOutTablePolicy() != nil &&
		policy.preparedFormStartWillEmitAsHTML() {
		// The output parser would insert this mapped form in table mode and
		// pop it immediately, while the input element may remain open.  Keep
		// the logical input entry but suppress the unstable mapped start.
		return true
	}
	if b.outputStartNeedsTablePreparation(
		inputElementName, preparedOutputName, outputTableContext) {
		b.prepareForOutputStart(preparedOutputName, *attrs, outputTableContext)
	}
	return false
}

// outputStartNeedsTablePreparation is whether input balancing alone cannot
// place this output start safely.
func (b *TagBalancingHTMLStreamEventReceiver) outputStartNeedsTablePreparation(
	inputElementName, outputElementName string, tableContext int,
) bool {
	return inputElementName != htmlLexerCanonicalElementName(outputElementName) ||
		tableContext < 0 ||
		tableContext >= len(b.openElements) ||
		b.openElements[tableContext] != b.outputElements[tableContext] ||
		!b.outputSuffixMatchesInput(tableContext)
}

// prepareForOutputStart balances a table before a prepared output tag that
// cannot stay in it.
func (b *TagBalancingHTMLStreamEventReceiver) prepareForOutputStart(
	outputElementName string, attrs []string, tableContext int,
) {
	if b.outputStartTagUsesForeignContentRules(outputElementName, attrs) {
		return
	}
	outputElement := tagBalancingHTMLStreamEventReceiverMetadata.IndexForName(
		htmlLexerCanonicalElementName(outputElementName))
	if outputElement != tagBalancingHTMLStreamEventReceiverTableTag &&
		tagBalancingHTMLStreamEventReceiverMetadata.CanContain(
			tagBalancingHTMLStreamEventReceiverTableTag, outputElement) {
		return
	}
	b.retireOutputTableForFosteredContent(tableContext)
}

// retireOutputTableForFosteredContent closes an output table before content
// its insertion mode fosters out.
func (b *TagBalancingHTMLStreamEventReceiver) retireOutputTableForFosteredContent(tableContext int) {
	if tableContext == tagBalancingHTMLStreamEventReceiverPolicyOnlyTableContext {
		b.formPointerPolicy.retireOutputTableForForm(false)
		return
	}
	if tableContext < 0 || tableContext >= len(b.openElements) {
		return
	}
	if b.openElements[tableContext] != tagBalancingHTMLStreamEventReceiverTableTag {
		b.retireMappedOutputTable(tableContext)
		return
	}
	if b.outputSuffixMatchesInput(tableContext) {
		top := tableContext
		for i, n := tableContext+1, len(b.openElements); i < n; i++ {
			if b.sentToUnderlying.get(i) &&
				!b.pushedOut.get(i) &&
				!b.outputElementsInForeignContent.get(i) &&
				tagBalancingHTMLStreamEventReceiverTableContext[b.outputElements[i]] {
				top = i
			}
		}
		b.pushOutTable(top)
		return
	}
	if b.formPointerPolicy != nil && b.formPointerPolicy.retireOutputTableForForm(true) {
		b.markRetiredTableDescendants(tableContext)
		b.pushedOut.set(tableContext)
		b.outputTableUnavailable.set(tableContext)
	}
}

// stackForeignFormWithoutOutput keeps an input foreign form from closing an
// older HTML form on its end.
func (b *TagBalancingHTMLStreamEventReceiver) stackForeignFormWithoutOutput(serial int) {
	stackIndex := len(b.openElements)
	b.openElements = append(b.openElements, tagBalancingHTMLStreamEventReceiverFormTag)
	b.inputElementSerials = append(b.inputElementSerials, serial)
	b.outputElements = append(b.outputElements, tagBalancingHTMLStreamEventReceiverNoOutputElement)
	b.resumedFormattingFromListItemStart.clear(stackIndex)
	b.outputlessTablesWithEmittedParts.clear(stackIndex)
	b.pushedMappedTemplateOutputOpen.clear(stackIndex)
	b.suppressedMappedForeignSubtrees.clear(stackIndex)
	b.sentToUnderlying.clear(stackIndex)
	b.inputElementsInForeignContent.set(stackIndex)
	b.outputElementsInForeignContent.clear(stackIndex)
	b.outputElementsStartForeignContent.clear(stackIndex)
	b.formPointerTargets.clear(stackIndex)
	b.clearedFormPointerTargets.clear(stackIndex)
	b.staleOutputFormPointerTargets.clear(stackIndex)
	b.pushedOut.clear(stackIndex)
	b.impliedInputTables.clear(stackIndex)
	b.outputlessImpliedSelects.clear(stackIndex)
	b.outputTableUnavailable.clear(stackIndex)
}

// stackElementWithoutOutput keeps a deliberately suppressed start available
// for its matching end.
func (b *TagBalancingHTMLStreamEventReceiver) stackElementWithoutOutput(
	element int, inputUsesForeignContentRules bool, serial int,
) {
	stackIndex := len(b.openElements)
	b.openElements = append(b.openElements, element)
	b.inputElementSerials = append(b.inputElementSerials, serial)
	b.outputElements = append(b.outputElements, tagBalancingHTMLStreamEventReceiverNoOutputElement)
	b.resumedFormattingFromListItemStart.clear(stackIndex)
	b.sentToUnderlying.set(stackIndex)
	b.inputElementsInForeignContent.setTo(stackIndex, inputUsesForeignContentRules)
	b.outputElementsInForeignContent.clear(stackIndex)
	b.outputElementsStartForeignContent.clear(stackIndex)
	b.formPointerTargets.clear(stackIndex)
	b.clearedFormPointerTargets.clear(stackIndex)
	b.staleOutputFormPointerTargets.clear(stackIndex)
	b.pushedOut.clear(stackIndex)
	b.impliedInputTables.clear(stackIndex)
	b.outputlessImpliedSelects.clear(stackIndex)
	b.outputTableUnavailable.clear(stackIndex)
	b.outputlessTablesWithEmittedParts.clear(stackIndex)
	b.pushedMappedTemplateOutputOpen.clear(stackIndex)
	b.suppressedMappedForeignSubtrees.clear(stackIndex)
}

// removeStackEntry removes the entry at i from the parallel stacks of
// element indices and returns its input element.  The caller clears its
// flags with clearStackFlags.
func (b *TagBalancingHTMLStreamEventReceiver) removeStackEntry(i int) int {
	element := b.openElements[i]
	b.openElements = slices.Delete(b.openElements, i, i+1)
	b.inputElementSerials = slices.Delete(b.inputElementSerials, i, i+1)
	b.outputElements = slices.Delete(b.outputElements, i, i+1)
	return element
}

// clearStackFlags clears bit i in every per-entry flag set.  Entries are
// only ever removed from the top, so the flags above stay clear.
func (b *TagBalancingHTMLStreamEventReceiver) clearStackFlags(i int) {
	b.resumedFormattingFromListItemStart.clear(i)
	b.sentToUnderlying.clear(i)
	b.inputElementsInForeignContent.clear(i)
	b.outputElementsInForeignContent.clear(i)
	b.outputElementsStartForeignContent.clear(i)
	b.formPointerTargets.clear(i)
	b.clearedFormPointerTargets.clear(i)
	b.staleOutputFormPointerTargets.clear(i)
	b.pushedOut.clear(i)
	b.impliedInputTables.clear(i)
	b.outputlessImpliedSelects.clear(i)
	b.outputTableUnavailable.clear(i)
	b.outputlessTablesWithEmittedParts.clear(i)
	b.pushedMappedTemplateOutputOpen.clear(i)
	b.suppressedMappedForeignSubtrees.clear(i)
}

// discardStackSuffix removes shadow entries whose policy-stack counterparts
// already closed.
func (b *TagBalancingHTMLStreamEventReceiver) discardStackSuffix(fromIndex int) {
	b.forgetListOutputContextsFrom(fromIndex)
	for i := len(b.openElements) - 1; i >= fromIndex; i-- {
		b.closePassthroughsInside(i, false)
		b.removeStackEntry(i)
		b.clearStackFlags(i)
	}
}

// forgetListOutputContextsFrom forgets list-output markers at or above a
// stack suffix being changed.
func (b *TagBalancingHTMLStreamEventReceiver) forgetListOutputContextsFrom(fromIndex int) {
	if fromIndex <= b.outputlessImpliedListAfterEmittedItem {
		b.outputlessImpliedListAfterEmittedItem = -1
	}
	if fromIndex <= b.outputListItemAfterClosedSelect {
		b.outputListItemAfterClosedSelect = -1
	}
}

// suppressedMappedForeignTableIndex is the table whose policy-produced
// foreign select suppresses its contents, or -1.
func (b *TagBalancingHTMLStreamEventReceiver) suppressedMappedForeignTableIndex() int {
	// Asked on every event, and the scan can only find a marked table.
	if b.suppressedMappedForeignSubtrees.isEmpty() {
		return -1
	}
	for i := len(b.openElements) - 1; i >= 0; i-- {
		if b.openElements[i] == tagBalancingHTMLStreamEventReceiverTableTag &&
			b.suppressedMappedForeignSubtrees.get(i) {
			return i
		}
	}
	return -1
}

// hasOpenTableAbove is whether a tracked descendant table should consume the
// next table end.
func (b *TagBalancingHTMLStreamEventReceiver) hasOpenTableAbove(stackIndex int) bool {
	for i := len(b.openElements) - 1; i > stackIndex; i-- {
		if b.openElements[i] == tagBalancingHTMLStreamEventReceiverTableTag {
			return true
		}
	}
	return false
}

// truncateResumeQueue forgets the formatting queued after the first depth
// entries.
func (b *TagBalancingHTMLStreamEventReceiver) truncateResumeQueue(depth int) {
	for len(b.toResumeInReverse) > depth {
		b.toResumeInReverse = b.toResumeInReverse[:len(b.toResumeInReverse)-1]
		b.resumeOnlyOutsideRawText = b.resumeOnlyOutsideRawText[:len(b.resumeOnlyOutsideRawText)-1]
	}
}

// resetMappedForeignTableSuppressionIfPolicyEnded removes logical state left
// after an ancestor end closed the policy's suppressed select before the
// input table itself ended.
func (b *TagBalancingHTMLStreamEventReceiver) resetMappedForeignTableSuppressionIfPolicyEnded() {
	if tableIndex := b.suppressedMappedForeignTableIndex(); tableIndex >= 0 {
		if policy := b.pushedOutTablePolicy(); policy != nil && policy.isSuppressingOutputAndContent() {
			return
		}
		b.discardStackSuffix(tableIndex)
	} else if b.suppressedMappedForeignTableResumeDepth < 0 {
		return
	}
	if b.suppressedMappedForeignTableResumeDepth >= 0 {
		b.truncateResumeQueue(b.suppressedMappedForeignTableResumeDepth)
	}
	b.droppedSuppressedTableDepth = 0
	b.droppedSuppressedOptionDepth = 0
	b.droppedSuppressedOptionOwnsPolicyEntry = false
	b.droppedSuppressedOptionStackDepth = -1
	b.droppedSuppressedOptionPassthroughDepth = -1
	b.droppedSuppressedOptionResumeDepth = -1
	b.suppressedMappedForeignTableResumeDepth = -1
}

// resetDroppedSuppressedTableIfPolicyEnded clears a dropped-table shadow
// when its suppression owner has ended.
func (b *TagBalancingHTMLStreamEventReceiver) resetDroppedSuppressedTableIfPolicyEnded() {
	if b.droppedSuppressedTableDepth != 0 && b.suppressedMappedForeignTableIndex() < 0 {
		b.droppedSuppressedTableDepth = 0
	}
}

// resetDroppedSuppressedOption retires logical and formatting state from a
// policy-suppressed option.
func (b *TagBalancingHTMLStreamEventReceiver) resetDroppedSuppressedOption() {
	if b.droppedSuppressedOptionOwnsPolicyEntry && b.droppedSuppressedOptionStackDepth >= 0 {
		b.discardStackSuffix(b.droppedSuppressedOptionStackDepth)
		b.popPassthroughsForwardedSince(b.droppedSuppressedOptionPassthroughDepth)
	}
	if b.droppedSuppressedOptionResumeDepth >= 0 {
		b.truncateResumeQueue(b.droppedSuppressedOptionResumeDepth)
	}
	b.droppedSuppressedOptionDepth = 0
	b.droppedSuppressedOptionOwnsPolicyEntry = false
	b.droppedSuppressedOptionStackDepth = -1
	b.droppedSuppressedOptionPassthroughDepth = -1
	b.droppedSuppressedOptionResumeDepth = -1
}

// resetDroppedSuppressedOptionIfPolicyEnded retires a virtual option after
// the policy has already closed it.
func (b *TagBalancingHTMLStreamEventReceiver) resetDroppedSuppressedOptionIfPolicyEnded() {
	if b.droppedSuppressedOptionDepth == 0 {
		return
	}
	if policy := b.pushedOutTablePolicy(); policy == nil || !policy.isSuppressingOutputAndContent() {
		b.resetDroppedSuppressedOption()
	}
}

// hasTrackedOptionAtOrAbove is whether a normal stacked option is inside the
// untracked option run.
func (b *TagBalancingHTMLStreamEventReceiver) hasTrackedOptionAtOrAbove(stackIndex int) bool {
	if stackIndex < 0 {
		return false
	}
	for i := len(b.openElements) - 1; i >= stackIndex; i-- {
		if b.openElements[i] == tagBalancingHTMLStreamEventReceiverOptionTag {
			return true
		}
	}
	return false
}

// formStartTagTableContext is the table context in which an HTML form start
// is handled by the special in-table rule, or -1 if it is not.
func (b *TagBalancingHTMLStreamEventReceiver) formStartTagTableContext(
	inputUsesForeignContentRules, outputUsesForeignContentRules bool,
) int {
	if inputUsesForeignContentRules && outputUsesForeignContentRules {
		return -1
	}
	for i := len(b.openElements) - 1; i >= 0; i-- {
		inputElement := b.openElements[i]
		outputElement := b.outputElements[i]
		if b.outputTableUnavailable.get(i) {
			return -1
		}
		if inputElement == tagBalancingHTMLStreamEventReceiverTableTag {
			if b.pushedOut.get(i) {
				if policyContext := b.policyOnlyFormTableContext(); policyContext != -1 {
					return policyContext
				}
				if _, ok := b.outputForeignContentRootName(); ok {
					return -1
				}
				if b.impliedInputTables.get(i) {
					return -1
				}
				return tagBalancingHTMLStreamEventReceiverInputOnlyTableContext
			}
			// A table that policy dropped or renamed cannot put the sanitized
			// output in a table insertion mode.  Following that output context
			// keeps a second sanitization from changing the form's extent.
			if outputElement == tagBalancingHTMLStreamEventReceiverTableTag &&
				!b.outputElementsInForeignContent.get(i) {
				return i
			}
			return -1
		}
		if outputElement != tagBalancingHTMLStreamEventReceiverNoOutputElement &&
			tagBalancingHTMLStreamEventReceiverTableFormScopeBoundaries[outputElement] {
			return b.policyOnlyFormTableContext()
		}
		if outputElement == tagBalancingHTMLStreamEventReceiverTableTag &&
			!b.outputElementsInForeignContent.get(i) {
			return i
		}
	}
	return b.policyOnlyFormTableContext()
}

// policyOnlyFormTableContext is the table context known only to the
// policy's more complete output stack, or -1.
func (b *TagBalancingHTMLStreamEventReceiver) policyOnlyFormTableContext() int {
	if b.formPointerPolicy != nil && b.formPointerPolicy.formStartTagUsesTableRules() {
		return tagBalancingHTMLStreamEventReceiverPolicyOnlyTableContext
	}
	return -1
}

// retireOutputTableForForm retires a mapped table represented on either
// available output stack.
func (b *TagBalancingHTMLStreamEventReceiver) retireOutputTableForForm(tableContext int) {
	switch {
	case tableContext == tagBalancingHTMLStreamEventReceiverInputOnlyTableContext:
		return
	case tableContext == tagBalancingHTMLStreamEventReceiverPolicyOnlyTableContext:
		b.formPointerPolicy.retireOutputTableForForm(false)
	case tableContext >= 0 && b.openElements[tableContext] == tagBalancingHTMLStreamEventReceiverTableTag:
		if tableContext+1 < len(b.openElements) &&
			b.sentToUnderlying.get(tableContext) &&
			!b.pushedOut.get(tableContext) &&
			b.outputElements[tableContext] == tagBalancingHTMLStreamEventReceiverTableTag &&
			!b.outputElementsInForeignContent.get(tableContext) &&
			b.outputSuffixChangesTableInsertionMode(tableContext) &&
			b.formPointerPolicy != nil &&
			b.formPointerPolicy.retireOutputTableForForm(true) {
			// A dropped or renamed template can leave the logical input
			// context above a physical output table.  Content after an
			// output-ignored form would be foster-parented from that table
			// even though the logical template contains it, so close the
			// table now as the text path would if the dropped boundary were
			// absent.  A dropped row group or row is no such boundary: the
			// output parser implies it again, the form is inserted in the row
			// and popped, and the table stays open for the cells that follow.
			b.markRetiredTableDescendants(tableContext)
			b.pushedOut.set(tableContext)
			b.outputTableUnavailable.set(tableContext)
		}
	default:
		b.retireMappedOutputTable(tableContext)
	}
}

// outputSuffixMatchesInput is whether the output suffix represents the same
// parser contexts as the input.
func (b *TagBalancingHTMLStreamEventReceiver) outputSuffixMatchesInput(tableContext int) bool {
	for i, n := tableContext+1, len(b.openElements); i < n; i++ {
		if !b.sentToUnderlying.get(i) ||
			b.pushedOut.get(i) ||
			b.outputElements[i] != b.openElements[i] ||
			b.outputElementsInForeignContent.get(i) != b.inputElementsInForeignContent.get(i) {
			return false
		}
	}
	return true
}

// outputSuffixChangesTableInsertionMode is whether the output between this
// table and the current position parses in a different table insertion
// mode than the input did.  A tbody or tr the policy dropped does not change
// it: those are exactly what the output parser implies again for the row or
// cell that follows.  A dropped thead or tfoot does, since the parser
// implies a tbody in its place and a policy that keeps tbody then emits one
// on the next pass.  Anything else missing or renamed, such as a dropped
// template, does too.
func (b *TagBalancingHTMLStreamEventReceiver) outputSuffixChangesTableInsertionMode(tableContext int) bool {
	for i, n := tableContext+1, len(b.openElements); i < n; i++ {
		inputElement := b.openElements[i]
		if b.outputElements[i] == tagBalancingHTMLStreamEventReceiverNoOutputElement &&
			!b.pushedOut.get(i) &&
			(inputElement == tagBalancingHTMLStreamEventReceiverTbodyTag ||
				inputElement == tagBalancingHTMLStreamEventReceiverTrTag) {
			continue
		}
		if !b.sentToUnderlying.get(i) ||
			b.pushedOut.get(i) ||
			b.outputElements[i] != inputElement ||
			b.outputElementsInForeignContent.get(i) != b.inputElementsInForeignContent.get(i) {
			return true
		}
	}
	return false
}

// markRetiredTableDescendants mirrors descendants that the policy retained
// without output elements.
func (b *TagBalancingHTMLStreamEventReceiver) markRetiredTableDescendants(tableContext int) {
	for i, n := tableContext+1, len(b.openElements); i < n; i++ {
		b.outputElements[i] = tagBalancingHTMLStreamEventReceiverNoOutputElement
		b.outputElementsInForeignContent.clear(i)
		b.outputElementsStartForeignContent.clear(i)
		b.clearedFormPointerTargets.clear(i)
		b.staleOutputFormPointerTargets.clear(i)
		b.pushedMappedTemplateOutputOpen.clear(i)
	}
}

// shouldSendClose is whether the receiver below still has a logical entry to
// close.
func (b *TagBalancingHTMLStreamEventReceiver) shouldSendClose(stackIndex int) bool {
	return b.sentToUnderlying.get(stackIndex) &&
		(!b.pushedOut.get(stackIndex) ||
			b.isRetiredInputTable(stackIndex) ||
			b.pushedMappedTemplateOutputOpen.get(stackIndex))
}

// isRetiredInputTable is whether the entry is a pushed table retained as an
// outputless policy-stack entry.
func (b *TagBalancingHTMLStreamEventReceiver) isRetiredInputTable(stackIndex int) bool {
	return b.pushedOut.get(stackIndex) &&
		b.outputTableUnavailable.get(stackIndex) &&
		b.openElements[stackIndex] == tagBalancingHTMLStreamEventReceiverTableTag
}

// isOutputlessSyntheticScopeBoundary is whether the entry is a synthetic
// scope boundary that established no boundary in the output.
func (b *TagBalancingHTMLStreamEventReceiver) isOutputlessSyntheticScopeBoundary(stackIndex int) bool {
	if b.impliedInputTables.get(stackIndex) &&
		b.pushedOut.get(stackIndex) &&
		b.formPointerPolicy != nil &&
		b.formPointerPolicy.hasRetiredFormTextContext() {
		// The form is outside this receiver's implied table in the input
		// browser.  Once that table is pushed out it cannot keep an end tag
		// from reaching the form's real input ancestor.
		return true
	}
	if b.outputElements[stackIndex] != tagBalancingHTMLStreamEventReceiverNoOutputElement {
		return false
	}
	return (b.impliedInputTables.get(stackIndex) &&
		!(b.pushedOut.get(stackIndex) && b.foreignRootPendingTableReturn != nil)) ||
		b.isNeverSentImpliedListItem(stackIndex)
}

// retireMappedOutputTable closes a policy-produced table whose logical input
// element must remain open.  Content after an in-table form is
// foster-parented out of that table when the output is parsed, so it must
// be serialized after the table on the first pass too.
func (b *TagBalancingHTMLStreamEventReceiver) retireMappedOutputTable(tableContext int) {
	if tableContext < 0 ||
		tableContext >= len(b.openElements) ||
		b.openElements[tableContext] == tagBalancingHTMLStreamEventReceiverTableTag ||
		b.outputElements[tableContext] != tagBalancingHTMLStreamEventReceiverTableTag ||
		!b.sentToUnderlying.get(tableContext) ||
		b.pushedOut.get(tableContext) ||
		b.outputElementsInForeignContent.get(tableContext) {
		return
	}
	if tableContext+1 == len(b.openElements) {
		// The mapped table that triggers this rule is outside any row, cell
		// or caption context.  Closing by the input name keeps the policy's
		// own input/output stack synchronized.
		b.underlying.CloseTag(
			tagBalancingHTMLStreamEventReceiverMetadata.CanonNameForIndex(b.openElements[tableContext]))
	} else {
		if b.formPointerPolicy == nil || !b.formPointerPolicy.retireOutputTableForForm(false) {
			return
		}
		// The policy closed the mapped table and its output descendants,
		// then retained the descendants as dropped logical input entries.
		// Mirror that state here so later context checks and end tags see
		// the same stack in both layers.
		b.markRetiredTableDescendants(tableContext)
	}
	b.sentToUnderlying.clear(tableContext)
	b.outputElementsInForeignContent.clear(tableContext)
	b.outputElementsStartForeignContent.clear(tableContext)
	b.clearedFormPointerTargets.clear(tableContext)
	b.staleOutputFormPointerTargets.clear(tableContext)
	b.outputTableUnavailable.set(tableContext)
}

// hasOpenTemplateElement is whether the parser is currently processing
// template contents.
func (b *TagBalancingHTMLStreamEventReceiver) hasOpenTemplateElement() bool {
	return slices.Contains(b.openElements, tagBalancingHTMLStreamEventReceiverTemplateTag)
}

// hasOpenLinkInFormattingScope is true if an a is open above the nearest
// formatting marker, which is when a browser ends it before opening another
// a: the adoption agency algorithm runs for an a on the list of active
// formatting elements after the last marker, and a link inside a table cell
// leaves one outside the table alone.  The scan looks no further down than
// lowerBound: a link below a forwarded foreign root is out of scope for a
// link inside the root's integration point, as it is for a browser's
// adoption agency algorithm.
func (b *TagBalancingHTMLStreamEventReceiver) hasOpenLinkInFormattingScope(lowerBound int) bool {
	for i := len(b.outputElements) - 1; i >= max(0, lowerBound); i-- {
		openElementIndex := b.outputElements[i]
		if openElementIndex == tagBalancingHTMLStreamEventReceiverATag {
			return true
		}
		if openElementIndex != tagBalancingHTMLStreamEventReceiverNoOutputElement &&
			tagBalancingHTMLStreamEventReceiverFormattingMarkers[openElementIndex] {
			return false
		}
	}
	return false
}

// outputElementIndexForLastOpenTag is the output counterpart of an input
// element just sent downstream.  Receivers other than the library policy
// cannot provide this feedback, so preserve the traditional input-based
// balancing for them.
func (b *TagBalancingHTMLStreamEventReceiver) outputElementIndexForLastOpenTag(inputElementIndex int) int {
	policy := b.openTagOutputPolicy
	if policy == nil {
		return inputElementIndex
	}
	if policy.outputSelectRetiredForLastOpenTag() {
		b.markOutputSelectRetired()
	}
	if outputElementName, ok := policy.outputElementNameForLastOpenTag(); ok {
		return tagBalancingHTMLStreamEventReceiverMetadata.IndexForName(
			htmlLexerCanonicalElementName(outputElementName))
	}
	return tagBalancingHTMLStreamEventReceiverNoOutputElement
}

// lastOutputElementUsedForeignContentRules is whether the most recently
// emitted element is in SVG or MathML.
func (b *TagBalancingHTMLStreamEventReceiver) lastOutputElementUsedForeignContentRules() bool {
	return b.openTagOutputPolicy != nil &&
		b.openTagOutputPolicy.outputElementForLastOpenTagUsedForeignContentRules()
}

// lastOutputElementStartsForeignContent is whether policy renamed the most
// recent output to an SVG or MathML root.
func (b *TagBalancingHTMLStreamEventReceiver) lastOutputElementStartsForeignContent(inputElementName string) bool {
	if b.openTagOutputPolicy == nil {
		return false
	}
	outputName, ok := b.openTagOutputPolicy.outputElementNameForLastOpenTag()
	if !ok {
		return false
	}
	canonOutputName := htmlLexerCanonicalElementName(outputName)
	return inputElementName != canonOutputName &&
		tagBalancingHTMLStreamEventReceiverIsForeignContentRoot(canonOutputName)
}

// isOutputInForeignContent is whether a foreign table-part token will
// actually be written in foreign content.  A receiver without policy
// feedback keeps the legacy balancing behavior, including its nesting-limit
// accounting.
func (b *TagBalancingHTMLStreamEventReceiver) isOutputInForeignContent() bool {
	policy := b.pushedOutTablePolicy()
	return policy != nil && policy.isOutputInForeignContent()
}

// textIsInForeignContent is whether the insertion point is under SVG or
// MathML rules: the current node below is foreign and not an integration
// point.  Asked as a start tag for a, a name that does not break out of
// foreign content, so the answer describes the insertion point rather than
// any particular tag.
func (b *TagBalancingHTMLStreamEventReceiver) textIsInForeignContent() bool {
	noAttrs := newAttrList()
	if policy := b.pushedOutTablePolicy(); policy != nil {
		return policy.outputStartTagUsesForeignContentRules("a", noAttrs)
	}
	return b.foreignContent.startTagUsesForeignContentRules("a", noAttrs)
}

// forwardedForeignRootBoundary is the stack depth of the innermost forwarded
// SVG or MathML root that the output entered, when the content arriving now
// goes inside that root, or -1.  Entries below that depth were open before
// the root; a browser inserts the content into the foreign node, or the
// integration point, inside the root, so those entries imply no wrapper for
// it and do not close for it.  The list item implied for a list's content
// used to land inside a forwarded svg that way, and li is a breakout name,
// so a browser popped the svg and read the SVG textarea or a beside it as
// HTML (#492).
//
// Table parts keep their table structure wherever they are.
func (b *TagBalancingHTMLStreamEventReceiver) forwardedForeignRootBoundary(elIndex int) int {
	if elIndex != TextNode && tagBalancingHTMLStreamEventReceiverTableParts[elIndex] {
		return -1
	}
	// Nothing is under a root the output parser has left: an emitted
	// breakout pops it there, and text or a later tag is HTML again.
	if _, ok := b.outputForeignContentRootName(); !ok {
		return -1
	}
	// The innermost forwarded root that the output entered and that the
	// input parser still has open.  A breakout pops the roots it breaks out
	// of, so after one the boundary is the next root out, if any.  When the
	// input parser has none open, but the output parser still does because
	// the policy dropped the breakout, the innermost emitted root stands.
	root := -1
	poppedInnerRoot := false
	rootIsOpen := false
	for i := len(b.passthroughForeignRoots) - 1; i >= 0; i-- {
		candidate := b.passthroughForeignRoots[i]
		if !b.passthroughOutputForeign.get(candidate) {
			continue
		}
		if root < 0 {
			root = candidate
		}
		if b.foreignContent.isNodeOpen(b.passthroughSerials[candidate]) {
			root = candidate
			rootIsOpen = true
			break
		}
		poppedInnerRoot = true
	}
	if root < 0 {
		return -1
	}
	rootDepth := b.passthroughDepths[root]
	// Text goes into the root's current node.  An element does when an HTML
	// entry is open above the root, at an integration point, or when it
	// broke out of an inner root only and so landed at the integration point
	// inside this one.  With neither, a foreign current node took the
	// foreign path in OpenTag before reaching here, and a breakout out of
	// the last root is judged against the HTML below it, as a browser
	// inserts it there.
	inside := elIndex == TextNode ||
		len(b.openElements) > rootDepth ||
		(rootIsOpen && poppedInnerRoot)
	if inside {
		return rootDepth
	}
	return -1
}

// outputForeignContentRootName is the outermost foreign root the policy has
// actually emitted, if known.
func (b *TagBalancingHTMLStreamEventReceiver) outputForeignContentRootName() (string, bool) {
	if policy := b.pushedOutTablePolicy(); policy != nil {
		return policy.outputForeignContentRootName()
	}
	return "", false
}

// outputStartTagUsesForeignContentRules is whether the current output
// context applies foreign rules to this tag.
func (b *TagBalancingHTMLStreamEventReceiver) outputStartTagUsesForeignContentRules(
	elementName string, attrs []string,
) bool {
	policy := b.pushedOutTablePolicy()
	return policy != nil && policy.outputStartTagUsesForeignContentRules(elementName, attrs)
}

// outputTemplateStartTagUsesForeignContentRules is whether retained template
// contents apply foreign rules to this start.
func (b *TagBalancingHTMLStreamEventReceiver) outputTemplateStartTagUsesForeignContentRules(
	elementName string, attrs []string,
) bool {
	policy := b.pushedOutTablePolicy()
	return policy != nil && policy.outputTemplateStartTagUsesForeignContentRules(elementName, attrs)
}

// outputStartTagUsesHTMLIntegrationPointRules is whether the output handles
// this HTML start at a foreign integration point.
func (b *TagBalancingHTMLStreamEventReceiver) outputStartTagUsesHTMLIntegrationPointRules(
	elementName string, attrs []string,
) bool {
	policy := b.pushedOutTablePolicy()
	return policy != nil && policy.outputStartTagUsesHTMLIntegrationPointRules(elementName, attrs)
}

// outputContainerIs is whether the policy reports name as the innermost
// element open in the output.  It is false with no policy to ask.
func (b *TagBalancingHTMLStreamEventReceiver) outputContainerIs(name string) bool {
	if b.openTagOutputPolicy == nil {
		return false
	}
	parentName, ok := b.openTagOutputPolicy.outputContainerElementName()
	return ok && parentName == name
}

// outputContainerIsParagraph is whether an HTML form start must close a
// policy-produced paragraph.
func (b *TagBalancingHTMLStreamEventReceiver) outputContainerIsParagraph() bool {
	return b.outputContainerIs("p")
}

// outputContainerIsAnchor is whether an HTML start must close a
// policy-produced link.
func (b *TagBalancingHTMLStreamEventReceiver) outputContainerIsAnchor() bool {
	return b.outputContainerIs("a")
}

// pushedOutTablePolicy returns the pushed-out-table operations supported by
// the current policy, or nil.
func (b *TagBalancingHTMLStreamEventReceiver) pushedOutTablePolicy() tagBalancingHTMLStreamEventReceiverPushedOutTablePolicy {
	if b.tablePolicy != nil && b.tablePolicy.supportsPushedOutTableOperations() {
		return b.tablePolicy
	}
	return nil
}

// retirePendingUnrecognizedHTMLTextElement ends an HTML text element whose
// case-sensitive input name was not parsed as one.  A browser treats the
// serialized name case-insensitively, so any later tag would otherwise be
// swallowed as text on the next parse.
func (b *TagBalancingHTMLStreamEventReceiver) retirePendingUnrecognizedHTMLTextElement() {
	pending := b.pendingUnrecognizedHTMLTextElement
	if pending == nil {
		return
	}
	b.pendingUnrecognizedHTMLTextElement = nil
	if passthrough := b.indexOfPassthroughNamed(*pending); passthrough >= 0 {
		b.closePassthrough(passthrough, true)
	}
}

// openElement opens one logical element, suppressing unsafe table structure
// if needed, and returns the element it became in the output.  implied
// treats an implied table as part of the structure below a synthetic table
// that the policy did not emit.
func (b *TagBalancingHTMLStreamEventReceiver) openElement(
	inputElementIndex int, attrs []string, implied bool,
) int {
	inputElementName := tagBalancingHTMLStreamEventReceiverMetadata.CanonNameForIndex(inputElementIndex)
	policy := b.pushedOutTablePolicy()
	if policy != nil && b.shouldSuppressTablePart(inputElementIndex, implied) {
		policy.openTagWithoutOutput(inputElementName, attrs)
		return tagBalancingHTMLStreamEventReceiverNoOutputElement
	}
	if policy != nil &&
		inputElementIndex != tagBalancingHTMLStreamEventReceiverTableTag &&
		tagBalancingHTMLStreamEventReceiverTableParts[inputElementIndex] &&
		b.outputTableContextForStart() == -1 {
		policy.openTablePartWithInheritedTextGate(inputElementName, attrs)
	} else {
		b.underlying.OpenTag(inputElementName, attrs)
	}
	return b.outputElementIndexForLastOpenTag(inputElementIndex)
}

// shouldSuppressTablePart is whether the nearest logical table was not
// re-opened in the output, making an emitted row, cell, section or column
// invalid there.  includeTable asks the same of a table, as part of the
// structure below a synthetic table.
func (b *TagBalancingHTMLStreamEventReceiver) shouldSuppressTablePart(elIndex int, includeTable bool) bool {
	if (elIndex == tagBalancingHTMLStreamEventReceiverTableTag && !includeTable) ||
		!tagBalancingHTMLStreamEventReceiverTableParts[elIndex] {
		return false
	}
	for i := len(b.openElements) - 1; i >= 0; i-- {
		if includeTable && b.openElements[i] == tagBalancingHTMLStreamEventReceiverTemplateTag {
			return false
		}
		if b.outputTableUnavailable.get(i) {
			return true
		}
		if b.openElements[i] == tagBalancingHTMLStreamEventReceiverTableTag {
			outputElement := b.outputElements[i]
			return b.sentToUnderlying.get(i) &&
				outputElement != tagBalancingHTMLStreamEventReceiverNoOutputElement &&
				outputElement != tagBalancingHTMLStreamEventReceiverTableTag &&
				outputElement != tagBalancingHTMLStreamEventReceiverTemplateTag &&
				!b.outputElementsInForeignContent.get(i) &&
				!(b.outputElementsStartForeignContent.get(i) && b.isOutputInForeignContent())
		}
		if b.sentToUnderlying.get(i) &&
			!b.pushedOut.get(i) &&
			b.outputElements[i] == tagBalancingHTMLStreamEventReceiverTableTag &&
			!b.outputElementsInForeignContent.get(i) {
			return false
		}
	}
	return false
}

// hasUnavailableOutputlessTable is whether an unavailable logical table also
// emitted no element.
func (b *TagBalancingHTMLStreamEventReceiver) hasUnavailableOutputlessTable() bool {
	for i := b.outputTableUnavailable.nextSetBit(0); i >= 0; i = b.outputTableUnavailable.nextSetBit(i + 1) {
		if b.outputElements[i] == tagBalancingHTMLStreamEventReceiverNoOutputElement {
			return true
		}
	}
	return false
}

// hasOutputlessTemplateAbove is whether a dropped or renamed template
// separates an output table.
func (b *TagBalancingHTMLStreamEventReceiver) hasOutputlessTemplateAbove(tableContext int) bool {
	for i := len(b.openElements) - 1; i > tableContext; i-- {
		if b.openElements[i] == tagBalancingHTMLStreamEventReceiverTemplateTag &&
			b.outputElements[i] != tagBalancingHTMLStreamEventReceiverTemplateTag {
			return true
		}
	}
	return false
}

// hasDroppedTemplateAbove is whether policy suppressed a template that still
// affects input parsing.
func (b *TagBalancingHTMLStreamEventReceiver) hasDroppedTemplateAbove(stackIndex int) bool {
	for i := len(b.openElements) - 1; i > stackIndex; i-- {
		if b.openElements[i] == tagBalancingHTMLStreamEventReceiverTemplateTag &&
			b.outputElements[i] == tagBalancingHTMLStreamEventReceiverNoOutputElement {
			return true
		}
	}
	return false
}

// prepareForNewContent prepares the stack for content about to arrive, a
// start tag for elIndex or text: it first closes a free output item the
// content makes a sibling of, and retires a list inferred for the preceding
// item, then judges the content against the forwarded foreign root it goes
// into, if any.  It returns false if an element the content needs around it
// would not fit the nesting limit.
func (b *TagBalancingHTMLStreamEventReceiver) prepareForNewContent(
	elIndex int, resumeFormatting, impliedTableEscapesSyntheticSelect bool,
) bool {
	b.closeFreeOutputItemBeforeSibling(elIndex)
	if elIndex == TextNode || elIndex == tagBalancingHTMLStreamEventReceiverSelectTag {
		b.retireOutputlessImpliedListBeforeContent()
	}
	return b.prepareForContent(
		elIndex, resumeFormatting, impliedTableEscapesSyntheticSelect,
		b.forwardedForeignRootBoundary(elIndex), true)
}

// retireOutputlessImpliedListBeforeContent retires a browser-invisible list
// inferred for the preceding output item.
func (b *TagBalancingHTMLStreamEventReceiver) retireOutputlessImpliedListBeforeContent() {
	top := len(b.openElements) - 1
	if top != b.outputlessImpliedListAfterEmittedItem {
		return
	}
	if top < 0 || b.inputElementSerials[top] != 0 ||
		!b.sentToUnderlying.get(top) || b.pushedOut.get(top) ||
		b.outputElements[top] != tagBalancingHTMLStreamEventReceiverNoOutputElement {
		b.outputlessImpliedListAfterEmittedItem = -1
		return
	}
	element := b.openElements[top]
	if element == tagBalancingHTMLStreamEventReceiverUlTag || element == tagBalancingHTMLStreamEventReceiverOlTag {
		if b.outputContainerIs("li") {
			// A nested item start already ended that output item for a
			// browser.  Keep the logical list so later content gets its own
			// item too.
			b.outputlessImpliedListAfterEmittedItem = -1
			return
		}
		// The inferred list established no output context.  Leaving it open
		// makes later content behave as its next item only on a subsequent
		// pass, after an emitted free item causes the same inference again.
		b.closeStackFrom(top, element, true)
	}
}

// closeFreeOutputItemBeforeSibling closes a free output item before a
// dropped list implies its sibling.
func (b *TagBalancingHTMLStreamEventReceiver) closeFreeOutputItemBeforeSibling(elIndex int) {
	item := b.outputListItemAfterClosedSelect
	if item < 0 || item >= len(b.openElements) ||
		!b.outputContainerIs("li") ||
		!b.sentToUnderlying.get(item) || b.pushedOut.get(item) ||
		b.outputElements[item] != tagBalancingHTMLStreamEventReceiverLiTag ||
		b.outputElementsInForeignContent.get(item) {
		return
	}
	container := b.containerIndex()
	if container < 0 {
		return
	}
	list := b.openElements[container]
	if list != tagBalancingHTMLStreamEventReceiverUlTag && list != tagBalancingHTMLStreamEventReceiverOlTag {
		return
	}
	impliesItem := elIndex == tagBalancingHTMLStreamEventReceiverLiTag ||
		slices.Contains(
			tagBalancingHTMLStreamEventReceiverMetadata.impliedElements(list, elIndex),
			tagBalancingHTMLStreamEventReceiverLiTag)
	if impliesItem {
		b.closeListItemForStart(item)
	}
}

// closeListItemForStart closes an item while marking its formatting as
// raw-text-sensitive.
func (b *TagBalancingHTMLStreamEventReceiver) closeListItemForStart(item int) {
	b.currentStartClosedListItem = true
	wasClosingListItemForStart := b.closingListItemForStart
	b.closingListItemForStart = true
	defer func() { b.closingListItemForStart = wasClosingListItemForStart }()
	b.closeStackFrom(item, tagBalancingHTMLStreamEventReceiverLiTag, true)
}

// prepareForContent prepares the stack for content of kind elIndex: it
// returns to or out of tables, closes an open list item for a list item
// start, opens implied elements, closes containers that cannot hold the
// content and resumes formatting.  It returns false if an element the
// content needs around it would not fit the nesting limit.
//
// foreignRootBoundary is the boundary forwardedForeignRootBoundary judged
// once for the content and kept while containers close for it.
// mayCloseOpenListItem is false when preparation re-enters itself, which a
// browser's one walk down the stack for a list item start tag does not do:
// the barriers that walk honoured may have closed since.
func (b *TagBalancingHTMLStreamEventReceiver) prepareForContent(
	elIndex int, resumeFormatting, impliedTableEscapesSyntheticSelect bool,
	foreignRootBoundary int, mayCloseOpenListItem bool,
) bool {
	metadata := tagBalancingHTMLStreamEventReceiverMetadata
	mayOpenAtNestingLimit := true
	retiredFormattingForImplicitOutputTable := false
	if elIndex == TextNode && b.hasOutputlessTableWithEmittedPartsInScope() {
		if tablePolicy := b.pushedOutTablePolicy(); tablePolicy != nil && !tablePolicy.isSuppressingText() {
			textContainer := b.containerIndex()
			if textContainer >= 0 &&
				tagBalancingHTMLStreamEventReceiverTableContext[b.openElements[textContainer]] &&
				b.textIsInLoneHTMLForeignObjectPassthrough(textContainer) {
				// The output has no physical table insertion mode.  Leave text
				// in this standalone integration point instead of
				// foster-parenting it only when the bare parts came directly
				// from the input.
				return true
			}
			if maskedTableContext := b.tableContextMaskedForText(); maskedTableContext >= 0 {
				b.pushOutTable(maskedTableContext)
			}
		}
	}
	impliedTableEscapesSyntheticSelect = impliedTableEscapesSyntheticSelect ||
		(elIndex == tagBalancingHTMLStreamEventReceiverColTag && b.isInSyntheticSelectListItemContext())
	isTablePart := elIndex != TextNode && tagBalancingHTMLStreamEventReceiverTableParts[elIndex]
	// The flags and the marked-table checks are cheap and usually false; the
	// scan of the whole stack for an output scope boundary comes last.
	if isTablePart &&
		((b.outputlessTablePartsMayBeOpen && b.outputlessTablePartsOpenedAtEvent != b.openTagEvent) ||
			b.hasPushedOutputlessTableWithEmittedParts() ||
			b.hasNestedOutputlessTableInCaptionWithEmittedParts()) &&
		b.outputAllowsImplicitTableReturn() {
		retiredFormattingForImplicitOutputTable = b.retireFormattingAboveImplicitOutputTable()
	}
	if !b.pushedOut.isEmpty() && isTablePart {
		b.returnToPushedOutTable(elIndex)
	}
	if isTablePart && elIndex != tagBalancingHTMLStreamEventReceiverTableTag {
		preserveOuterOutputlessTableParts := b.hasNestedUnavailableTableAboveEmittedOutputlessTable()
		b.returnToTableContext(elIndex)
		container := b.containerIndex()
		if container >= 0 &&
			tagBalancingHTMLStreamEventReceiverTableContext[b.openElements[container]] &&
			!b.hasUnavailableInputTableInScope() {
			// A table part clears a browser's stack back to the table
			// context, which pops any element forwarded inside it that has no
			// entry here.  A table the policy dropped or renamed establishes
			// no such context in the output, and its logical parts keep the
			// older path.
			b.closePassthroughsInside(container, true)
		}
		top := b.effectiveContainer(elIndex, container)
		implied := metadata.impliedElements(top, elIndex)
		if !preserveOuterOutputlessTableParts &&
			len(implied) != 0 && implied[0] == tagBalancingHTMLStreamEventReceiverTableTag &&
			(container < 0 || !b.canHold(elIndex, top, container)) {
			// A dropped raw-text container cannot hide an emitted paragraph
			// from the implied table that the output parser will place beside
			// it.  A dropped template is not such a container: the part under
			// it is judged where the template stood, and its own content is
			// the part's, so suppressing it would delete the text of a caption
			// the policy keeps (#492, item 2).
			if container >= 0 &&
				!b.isDroppedTemplate(container) &&
				b.outputElements[container] == tagBalancingHTMLStreamEventReceiverNoOutputElement &&
				b.contentIsSkippable(metadata.CanonNameForIndex(b.openElements[container])) {
				b.droppedSkippableDepth++
				b.closeStackFrom(container, b.openElements[container], true)
			}
			// An orphan table part still needs its table wrapper, but that
			// table must close containers such as p before any of its
			// structure opens.
			mayOpenAtNestingLimit = b.prepareForNewContent(
				tagBalancingHTMLStreamEventReceiverTableTag, false, impliedTableEscapesSyntheticSelect) &&
				mayOpenAtNestingLimit
		}
	}
	// Push an open table out of the way before anything below asks what
	// contains the content: a browser puts content a table cannot hold in
	// front of the table, so what contains the table contains the content,
	// and it is what decides which elements are implied and what must close.
	if b.needsFosterParenting(elIndex, foreignRootBoundary) {
		tableIndex := b.containerIndex()
		b.pushOutTable(tableIndex)
	}

	// A browser's list item start tag closes an open list item before it
	// inserts the new one, walking down its stack past the formatting
	// elements open inside that item, so the two items are siblings and the
	// formatting is reconstructed inside the second.  Without this the
	// containment metadata answered the open formatting element with a fresh
	// list inside it, and each following item nested one level deeper
	// (#492).
	closedListItemForStart := false
	if elIndex == tagBalancingHTMLStreamEventReceiverLiTag && mayCloseOpenListItem &&
		!b.contentGoesIntoRawTextElement() &&
		!b.listItemStartPoppedForwardedForeignRoot() {
		if itemToClose := b.listItemToCloseForStart(foreignRootBoundary); itemToClose >= 0 {
			b.closeListItemForStart(itemToClose)
			closedListItemForStart = true
		}
	}

	// Content that goes into a forwarded SVG or MathML root is contained by
	// the foreign element, or the integration point, inside that root, not
	// by the HTML entries below it: those imply nothing for it, so it is
	// judged as in a fresh body, where a list item or an option still gets
	// the list or select it must never be emitted without, and closing stops
	// at the root.  Formatting still resumes for it below, as a browser
	// reconstructs it at an integration point.
	stackDepthBeforeImpliedElements := len(b.openElements)
	if !b.openImpliedElements(
		elIndex, impliedTableEscapesSyntheticSelect, foreignRootBoundary, closedListItemForStart) {
		mayOpenAtNestingLimit = false
	}
	// Close all the elements that cannot contain the content to open.
	closedPreexistingContainer := false
	for {
		container := b.containerIndex()
		if container < 0 || container < foreignRootBoundary {
			break
		}
		top := b.openElements[container]
		// A link ends the link open before it, wherever that is: nested
		// links do not survive a browser's parse, so a table between them
		// cannot stay open either.
		endsLink := b.endsAnOpenLink(elIndex, foreignRootBoundary)
		if !endsLink && b.canContain(elIndex, top, container) {
			break
		}
		if !endsLink &&
			tagBalancingHTMLStreamEventReceiverTableContext[top] &&
			tagBalancingHTMLStreamEventReceiverIsFosterParented(elIndex) {
			// As above, for a table uncovered by closing what held it.
			b.pushOutTable(container)
			continue
		}
		// Close the container, and with it anything put in front of a table
		// it holds, from the top down.
		closedPreexistingContainer = closedPreexistingContainer ||
			container < stackDepthBeforeImpliedElements
		b.forgetListOutputContextsFrom(container)
		for i := len(b.openElements) - 1; i >= container; i-- {
			unclosed := b.openElements[i]
			resumedFromListItemStart := b.resumedFormattingFromListItemStart.get(i)
			b.closePassthroughsInside(i, true)
			if b.shouldSendClose(i) {
				b.underlying.CloseTag(metadata.CanonNameForIndex(unclosed))
			}
			b.detachOutputlessTableWithEmittedParts(i)
			b.removeStackEntry(i)
			b.clearStackFlags(i)
			if metadata.Resumable(unclosed) && unclosed != elIndex {
				b.queueForResumption(unclosed, resumedFromListItemStart)
			}
		}
	}

	// Closing a container can uncover a context that needs a different
	// implied path.  For example, after a thead closes for a col, the table
	// below it needs to imply a colgroup.  Re-run preparation from that new
	// top before resuming formatting elements.
	if closedPreexistingContainer {
		mayOpenAtNestingLimit = b.prepareForContent(
			elIndex, false, impliedTableEscapesSyntheticSelect,
			foreignRootBoundary, false) && mayOpenAtNestingLimit
	}

	if retiredFormattingForImplicitOutputTable {
		resumeFormatting = false
	}
	formattingWaitsUntilAfterRawText := len(b.toResumeInReverse) != 0 &&
		b.resumeOnlyOutsideRawText[len(b.resumeOnlyOutsideRawText)-1] != 0
	if formattingWaitsUntilAfterRawText &&
		elIndex != TextNode &&
		elIndex != tagBalancingHTMLStreamEventReceiverUnrecognizedTag &&
		tagBalancingHTMLStreamEventReceiverWrittenAsRawTextElement(elIndex) {
		// A browser does not reconstruct formatting for an element whose
		// content it reads as text: the element is inserted beside the
		// formatting, which is reconstructed again for the text after it.
		resumeFormatting = false
	}
	// Formatting is not reconstructed inside an element whose content a
	// browser reads as text, such as textarea or style: a tag written inside
	// it would come out as that element's text (#492).  Asked once: nothing
	// the loop opens is such an element.
	intoRawTextElement := resumeFormatting &&
		len(b.toResumeInReverse) != 0 &&
		formattingWaitsUntilAfterRawText &&
		b.contentGoesIntoRawTextElement()
	resumed := false
	for resumeFormatting &&
		!b.insertionPointIsInForeignContent &&
		!intoRawTextElement &&
		len(b.toResumeInReverse) != 0 {
		toResume := b.toResumeInReverse[len(b.toResumeInReverse)-1]
		// If toResume can contain elIndex AND the top of the stack can
		// contain toResume, then we push toResume.  A link is not resumed
		// around another link, or where one is open: a browser ends a link
		// when the next begins, and nested links do not survive a browser's
		// parse, so the output would not read back as written.
		nOpen := len(b.openElements)
		// The resumed element has to hold the content directly.  One that
		// would need a wrapper implied inside it, such as the list around a
		// list item, stays queued for the content inside the tag, where a
		// browser reconstructs it.  Resuming it here put it inside the
		// wrapper already implied for the tag and then implied that wrapper
		// again.
		if !((nOpen == 0 ||
			(b.canContain(toResume, b.openElements[nOpen-1], nOpen) &&
				// And directly: one that would need a wrapper implied between
				// the container and it, such as the item a list gives its
				// content, is left queued for the content that implies that
				// wrapper, which is where a browser puts it.  Once the nesting
				// limit prevents emitting it, keeping the logical formatting
				// entry costs no output wrapper and preserves the stack seen
				// by a later dynamic limit change.
				(b.effectiveNestingDepth() >= b.nestingLimit ||
					len(metadata.impliedElements(b.openElements[nOpen-1], toResume)) == 0))) &&
			b.canContain(elIndex, toResume, nOpen) &&
			b.canHold(elIndex, toResume, nOpen) &&
			!(toResume == tagBalancingHTMLStreamEventReceiverATag &&
				(elIndex == tagBalancingHTMLStreamEventReceiverATag ||
					b.hasOpenLinkInFormattingScope(foreignRootBoundary)))) {
			break
		}
		resumesFromListItemStart := b.resumeOnlyOutsideRawText[len(b.resumeOnlyOutsideRawText)-1] != 0
		b.toResumeInReverse = b.toResumeInReverse[:len(b.toResumeInReverse)-1]
		b.resumeOnlyOutsideRawText = b.resumeOnlyOutsideRawText[:len(b.resumeOnlyOutsideRawText)-1]
		outputElementIndex := tagBalancingHTMLStreamEventReceiverNoOutputElement
		sent := b.effectiveNestingDepth() < b.nestingLimit
		if sent {
			attrs := newAttrList()
			inputName := metadata.CanonNameForIndex(toResume)
			if b.preparePolicyStartInOutputTable(inputName, &attrs) {
				b.pushedOutTablePolicy().openTagWithoutOutput(inputName, attrs)
			} else {
				outputElementIndex = b.openElement(toResume, attrs, false)
			}
		}
		outputElementIsForeign := sent && b.lastOutputElementUsedForeignContentRules()
		stackIndex := len(b.openElements)
		b.openElements = append(b.openElements, toResume)
		b.inputElementSerials = append(b.inputElementSerials, 0)
		b.outputElements = append(b.outputElements, outputElementIndex)
		b.resumedFormattingFromListItemStart.setTo(stackIndex, resumesFromListItemStart)
		b.outputlessTablesWithEmittedParts.clear(stackIndex)
		b.outputlessImpliedSelects.clear(stackIndex)
		b.pushedMappedTemplateOutputOpen.clear(stackIndex)
		b.suppressedMappedForeignSubtrees.clear(stackIndex)
		b.sentToUnderlying.setTo(stackIndex, sent)
		b.inputElementsInForeignContent.clear(stackIndex)
		b.outputElementsInForeignContent.setTo(stackIndex, outputElementIsForeign)
		b.outputElementsStartForeignContent.setTo(
			stackIndex, sent && outputElementIndex != tagBalancingHTMLStreamEventReceiverNoOutputElement &&
				b.lastOutputElementStartsForeignContent(metadata.CanonNameForIndex(toResume)))
		b.formPointerTargets.clear(stackIndex)
		b.clearedFormPointerTargets.clear(stackIndex)
		b.staleOutputFormPointerTargets.clear(stackIndex)
		b.impliedInputTables.clear(stackIndex)
		b.outputlessImpliedSelects.clear(stackIndex)
		resumed = true
	}
	if resumed {
		mayOpenAtNestingLimit = b.prepareForContent(
			elIndex, false, impliedTableEscapesSyntheticSelect,
			foreignRootBoundary, false) && mayOpenAtNestingLimit
	}
	return mayOpenAtNestingLimit
}

// openImpliedElements opens, for prepareForContent, the elements such as
// list items and table cells and rows that the content of kind elIndex
// needs between the current container and itself.  It returns false if one
// of them would not fit the nesting limit.
func (b *TagBalancingHTMLStreamEventReceiver) openImpliedElements(
	elIndex int, impliedTableEscapesSyntheticSelect bool, foreignRootBoundary int,
	closedListItemForStart bool,
) bool {
	metadata := tagBalancingHTMLStreamEventReceiverMetadata
	mayOpenAtNestingLimit := true
	container := b.containerIndex()
	top := tagBalancingHTMLStreamEventReceiverBodyTag
	if container >= foreignRootBoundary {
		top = b.effectiveContainer(elIndex, container)
	}
	if closedListItemForStart && b.openTagOutputPolicy != nil {
		if b.openTagOutputPolicy.hasOpenHTMLOutputList() || b.outputlessListIsCurrentContainer() {
			// The list-item start algorithm inserts the new item at the
			// current insertion point after popping the prior item, even if
			// non-special elements sit between that point and the list.
			top = tagBalancingHTMLStreamEventReceiverUlTag
		} else {
			top = tagBalancingHTMLStreamEventReceiverBodyTag
			if outputContainer := b.outputContainerIndex(); outputContainer != tagBalancingHTMLStreamEventReceiverUnrecognizedTag {
				top = outputContainer
			}
		}
	}
	// Open implied elements, such as list-items and table cells & rows.
	impliedElIndices := metadata.impliedElements(top, elIndex)
	if len(impliedElIndices) == 0 {
		return true
	}
	startPos := tagBalancingHTMLStreamEventReceiverStartAfter(impliedElIndices, top)
	recompute := func() {
		container = b.containerIndex()
		top = tagBalancingHTMLStreamEventReceiverBodyTag
		if container >= foreignRootBoundary {
			top = b.effectiveContainer(elIndex, container)
		}
		impliedElIndices = metadata.impliedElements(top, elIndex)
		startPos = tagBalancingHTMLStreamEventReceiverStartAfter(impliedElIndices, top)
	}

	// An option can imply a select where the current table context cannot
	// contain one, for example after a colgroup.  Prepare that implied
	// select like an explicit start tag, then recompute the path after it
	// has closed or pushed out the table.
	if startPos < len(impliedElIndices) &&
		impliedElIndices[startPos] == tagBalancingHTMLStreamEventReceiverSelectTag &&
		top == tagBalancingHTMLStreamEventReceiverColgroupTag &&
		container >= 0 &&
		b.openElements[container] != tagBalancingHTMLStreamEventReceiverColgroupTag &&
		b.retireMappedOutputContainer(tagBalancingHTMLStreamEventReceiverColgroupTag) {
		recompute()
	}
	// The select has to fit where the option's output goes.  An entry the
	// policy dropped, a cell, a caption, a template or any other element, is
	// no container in the output: what holds the option there is the nearest
	// entry below with output, and if that is table structure, which holds
	// no select, the table is pushed out from there, as a browser
	// foster-parents the select before the table, while the dropped entries
	// stay where they are, so that the cell's end tag still closes the
	// option it holds (#492).  A container the policy renamed into table
	// structure is closed instead, since the select cannot go inside it
	// either.
	outputTableEntry := -1
	if startPos < len(impliedElIndices) &&
		impliedElIndices[startPos] == tagBalancingHTMLStreamEventReceiverSelectTag &&
		container >= 0 &&
		b.sentToUnderlying.get(container) {
		below := container
		for below >= 0 &&
			b.outputElements[below] == tagBalancingHTMLStreamEventReceiverNoOutputElement &&
			b.sentToUnderlying.get(below) {
			below--
		}
		// The scan stops at the select's own logical list item too, which
		// has no output and is not the policy's.
		if below >= 0 &&
			!b.pushedOut.get(below) &&
			b.outputElements[below] != tagBalancingHTMLStreamEventReceiverNoOutputElement &&
			tagBalancingHTMLStreamEventReceiverTableContext[b.outputElements[below]] {
			outputTableEntry = below
		}
	}
	if startPos < len(impliedElIndices) &&
		impliedElIndices[startPos] == tagBalancingHTMLStreamEventReceiverSelectTag &&
		container >= 0 &&
		(outputTableEntry >= 0 ||
			!b.canHold(tagBalancingHTMLStreamEventReceiverSelectTag, top, container)) {
		switch {
		case outputTableEntry < 0:
			mayOpenAtNestingLimit = b.prepareForNewContent(
				tagBalancingHTMLStreamEventReceiverSelectTag, false, impliedTableEscapesSyntheticSelect) &&
				mayOpenAtNestingLimit
		case outputTableEntry < container ||
			tagBalancingHTMLStreamEventReceiverTableContext[b.openElements[outputTableEntry]]:
			b.pushOutTable(outputTableEntry)
		default:
			b.closeStackFrom(container, b.openElements[container], true)
		}
		recompute()
	}

	attrs := newAttrList()
	for _, impliedElIndex := range impliedElIndices[startPos:] {
		// The containment metadata answers most children of a select with a
		// list item, so that they nest inside the select the way a browser
		// nests their text instead of closing it.  No browser creates that
		// element.  Below a policy it stays on this stack as the container
		// but is never sent, so it needs no room in the output: a policy that
		// allowed li emitted <select><li>x</li></select>, the next pass
		// wrapped that li in a ul and the ul in a li without bound, and the
		// emitted li bounded the select end tag's scope search, so text after
		// </select> landed inside the select (#492).  A receiver with no
		// policy to drop it would serialize it, so it is skipped there.  So
		// is the item for an element beside a pushed-out table: retaining it
		// on the logical stack can hide the select from its explicit end tag
		// on a second sanitization.  Likewise, an item implied under an
		// outputless list while an output select is open is ignored by the
		// browser, so it remains logical-only instead of serializing an
		// element that a second pass would put outside the select (#494).
		syntheticSelectListItem := top == tagBalancingHTMLStreamEventReceiverSelectTag &&
			impliedElIndex == tagBalancingHTMLStreamEventReceiverLiTag
		keepsSyntheticSelectListItem := syntheticSelectListItem &&
			b.pushedOutTablePolicy() != nil &&
			(elIndex == TextNode || !b.pushedTableRequiresSelectEscape())
		ignoredImpliedListItemInOutputSelect := !syntheticSelectListItem &&
			impliedElIndex == tagBalancingHTMLStreamEventReceiverLiTag &&
			b.outputlessListIsCurrentContainer() &&
			b.hasOpenHTMLOutputSelect()
		keepsLogicalOnlyListItem := keepsSyntheticSelectListItem || ignoredImpliedListItemInOutputSelect
		physicalListItemFits := impliedElIndex == tagBalancingHTMLStreamEventReceiverLiTag &&
			!b.pushedOut.isEmpty() &&
			b.isInsideItemOpenedAfterListItemStart() &&
			b.outputNestingDepth() < b.nestingLimit
		if !keepsLogicalOnlyListItem && !physicalListItemFits &&
			b.effectiveNestingDepth() >= b.nestingLimit {
			mayOpenAtNestingLimit = false
			break
		}
		if syntheticSelectListItem && !keepsSyntheticSelectListItem {
			continue
		}
		attrs = attrs[:0]
		suppressMappedImpliedTemplate := false
		if impliedElIndex == tagBalancingHTMLStreamEventReceiverTableTag {
			outputTableContext := b.outputTableContextForStart()
			if outputTableContext >= 0 && b.hasOutputlessTemplateAbove(outputTableContext) {
				b.preparePolicyStartInOutputTable("table", &attrs)
			} else if !b.preparingPreparedPolicyStart &&
				(b.hasOpenHTMLOutputTemplate() || impliedTableEscapesSyntheticSelect) &&
				b.formPointerPolicy != nil &&
				b.pushedOutTablePolicy() != nil {
				preparedOutputName, ok := b.formPointerPolicy.prepareForStartTag("table", &attrs)
				suppressMappedImpliedTemplate = ok &&
					htmlLexerCanonicalElementName(preparedOutputName) == "template"
			}
			if b.outputContainerIsParagraph() && b.formPointerPolicy != nil {
				b.formPointerPolicy.prepareOutputForHTMLStart("table", attrs)
			}
		}
		suppressedImpliedTable := impliedElIndex == tagBalancingHTMLStreamEventReceiverTableTag &&
			b.shouldSuppressTablePart(impliedElIndex, true)
		if (impliedElIndex == tagBalancingHTMLStreamEventReceiverUlTag ||
			impliedElIndex == tagBalancingHTMLStreamEventReceiverOlTag) &&
			b.outputContainerIsParagraph() &&
			b.formPointerPolicy != nil {
			b.formPointerPolicy.prepareOutputForHTMLStart(metadata.CanonNameForIndex(impliedElIndex), attrs)
		}
		outputlessImpliedSelect := impliedElIndex == tagBalancingHTMLStreamEventReceiverSelectTag &&
			b.pushedOutTablePolicy() != nil &&
			b.hasOpenHTMLOutputSelect()
		var outputElementIndex int
		switch {
		case syntheticSelectListItem || ignoredImpliedListItemInOutputSelect:
			outputElementIndex = tagBalancingHTMLStreamEventReceiverNoOutputElement
		case outputlessImpliedSelect:
			b.pushedOutTablePolicy().openTagWithoutOutputWithInheritedTextGate("select", attrs)
			outputElementIndex = tagBalancingHTMLStreamEventReceiverNoOutputElement
		case suppressMappedImpliedTemplate:
			if impliedTableEscapesSyntheticSelect {
				b.pushedOutTablePolicy().openTagWithoutOutputOrContent("table", attrs)
			} else {
				b.pushedOutTablePolicy().openTagWithoutOutput("table", attrs)
			}
			outputElementIndex = tagBalancingHTMLStreamEventReceiverNoOutputElement
		default:
			outputElementIndex = b.openElement(impliedElIndex, attrs, true)
		}
		outputElementIsForeign := b.lastOutputElementUsedForeignContentRules()
		stackIndex := len(b.openElements)
		b.openElements = append(b.openElements, impliedElIndex)
		b.inputElementSerials = append(b.inputElementSerials, 0)
		b.outputElements = append(b.outputElements, outputElementIndex)
		b.resumedFormattingFromListItemStart.clear(stackIndex)
		b.outputlessTablesWithEmittedParts.clear(stackIndex)
		b.pushedMappedTemplateOutputOpen.clear(stackIndex)
		b.suppressedMappedForeignSubtrees.clear(stackIndex)
		b.sentToUnderlying.setTo(
			stackIndex, !syntheticSelectListItem && !ignoredImpliedListItemInOutputSelect)
		b.inputElementsInForeignContent.clear(stackIndex)
		b.outputElementsInForeignContent.setTo(stackIndex, outputElementIsForeign)
		b.outputElementsStartForeignContent.setTo(
			stackIndex, outputElementIndex != tagBalancingHTMLStreamEventReceiverNoOutputElement &&
				b.lastOutputElementStartsForeignContent(metadata.CanonNameForIndex(impliedElIndex)))
		b.formPointerTargets.clear(stackIndex)
		b.clearedFormPointerTargets.clear(stackIndex)
		b.staleOutputFormPointerTargets.clear(stackIndex)
		b.impliedInputTables.setTo(stackIndex, impliedElIndex == tagBalancingHTMLStreamEventReceiverTableTag)
		b.outputlessImpliedSelects.setTo(stackIndex, outputlessImpliedSelect)
		if impliedElIndex == tagBalancingHTMLStreamEventReceiverTableTag &&
			(suppressedImpliedTable ||
				(outputElementIndex != tagBalancingHTMLStreamEventReceiverNoOutputElement &&
					outputElementIndex != tagBalancingHTMLStreamEventReceiverTableTag &&
					outputElementIndex != tagBalancingHTMLStreamEventReceiverTemplateTag)) {
			b.outputTableUnavailable.set(stackIndex)
		}
		b.recordEmittedPartForOutputlessTable(stackIndex+1, outputElementIndex, outputElementIsForeign)
	}
	return mayOpenAtNestingLimit
}

// queueForResumption queues a formatting element to reconstruct later,
// keeping at most three of a name as a browser's list of active formatting
// elements does: its Noah's Ark clause drops the earliest of four alike.
// Without that bound one list item after another closing over the same open
// formatting element grew the output by a level each time (#492).  The
// queue holds the innermost first, so the earliest is the last of the alike.
// resumedFromListItemStart, like a closure by the list-item-start walk,
// makes raw-text starts precede the formatting.
func (b *TagBalancingHTMLStreamEventReceiver) queueForResumption(elIndex int, resumedFromListItemStart bool) {
	alike := 0
	earliest := -1
	for i := len(b.toResumeInReverse) - 1; i >= 0; i-- {
		if b.toResumeInReverse[i] == elIndex {
			alike++
			if earliest < 0 {
				earliest = i
			}
		}
	}
	if alike >= 3 {
		b.toResumeInReverse = slices.Delete(b.toResumeInReverse, earliest, earliest+1)
		b.resumeOnlyOutsideRawText = slices.Delete(b.resumeOnlyOutsideRawText, earliest, earliest+1)
	}
	b.toResumeInReverse = append(b.toResumeInReverse, elIndex)
	onlyOutsideRawText := 0
	if b.closingListItemForStart || resumedFromListItemStart {
		onlyOutsideRawText = 1
	}
	b.resumeOnlyOutsideRawText = append(b.resumeOnlyOutsideRawText, onlyOutsideRawText)
}

// forgetQueuedFormatting drops the innermost queued formatting element with
// this index, if any.
func (b *TagBalancingHTMLStreamEventReceiver) forgetQueuedFormatting(elIndex int) {
	for i := len(b.toResumeInReverse) - 1; i >= 0; i-- {
		if b.toResumeInReverse[i] == elIndex {
			b.toResumeInReverse = slices.Delete(b.toResumeInReverse, i, i+1)
			b.resumeOnlyOutsideRawText = slices.Delete(b.resumeOnlyOutsideRawText, i, i+1)
			return
		}
	}
}

// retireContainerForUnemittedListChild closes an output wrapper whose
// required child did not fit the limit.
func (b *TagBalancingHTMLStreamEventReceiver) retireContainerForUnemittedListChild(child int) {
	if child != tagBalancingHTMLStreamEventReceiverLiTag && child != tagBalancingHTMLStreamEventReceiverOptionTag {
		return
	}
	container := b.containerIndex()
	if container < 0 {
		return
	}
	element := b.openElements[container]
	if (child == tagBalancingHTMLStreamEventReceiverOptionTag && element == tagBalancingHTMLStreamEventReceiverSelectTag) ||
		(child == tagBalancingHTMLStreamEventReceiverLiTag &&
			(element == tagBalancingHTMLStreamEventReceiverUlTag || element == tagBalancingHTMLStreamEventReceiverOlTag)) {
		b.closeStackFrom(container, element, true)
	}
}

// hasDroppedTableInSyntheticSelectListItemContext is whether an outputless
// table is nested under the select's synthetic li.
func (b *TagBalancingHTMLStreamEventReceiver) hasDroppedTableInSyntheticSelectListItemContext() bool {
	n := len(b.openElements)
	return n >= 3 &&
		b.openElements[n-1] == tagBalancingHTMLStreamEventReceiverTableTag &&
		b.outputElements[n-1] == tagBalancingHTMLStreamEventReceiverNoOutputElement &&
		b.openElements[n-2] == tagBalancingHTMLStreamEventReceiverLiTag &&
		b.outputElements[n-2] == tagBalancingHTMLStreamEventReceiverNoOutputElement &&
		b.openElements[n-3] == tagBalancingHTMLStreamEventReceiverSelectTag &&
		b.outputElements[n-3] == tagBalancingHTMLStreamEventReceiverSelectTag &&
		b.sentToUnderlying.get(n-3) &&
		!b.pushedOut.get(n-3)
}

// isInSyntheticSelectListItemContext is whether the canned implied list
// item is still below an HTML select.
func (b *TagBalancingHTMLStreamEventReceiver) isInSyntheticSelectListItemContext() bool {
	for i := len(b.openElements) - 1; i > 0; i-- {
		element := b.openElements[i]
		if element == tagBalancingHTMLStreamEventReceiverTableTag ||
			element == tagBalancingHTMLStreamEventReceiverTemplateTag ||
			element == tagBalancingHTMLStreamEventReceiverTdTag ||
			element == tagBalancingHTMLStreamEventReceiverThTag {
			return false
		}
		if element == tagBalancingHTMLStreamEventReceiverLiTag &&
			b.outputElements[i] == tagBalancingHTMLStreamEventReceiverNoOutputElement &&
			b.openElements[i-1] == tagBalancingHTMLStreamEventReceiverSelectTag &&
			b.outputElements[i-1] == tagBalancingHTMLStreamEventReceiverSelectTag &&
			b.sentToUnderlying.get(i-1) &&
			!b.pushedOut.get(i-1) {
			return true
		}
	}
	return false
}

// hasOpenHTMLOutputTable is whether the serialized output still has an HTML
// table open.
func (b *TagBalancingHTMLStreamEventReceiver) hasOpenHTMLOutputTable() bool {
	if b.policyOnlyFormTableContext() != -1 {
		return true
	}
	return b.mayHavePhysicalOutputTableOnStack()
}

// mayHavePhysicalOutputTableOnStack is whether an entry on the stack has an
// HTML table open in the output.
func (b *TagBalancingHTMLStreamEventReceiver) mayHavePhysicalOutputTableOnStack() bool {
	for i := len(b.openElements) - 1; i >= 0; i-- {
		if b.sentToUnderlying.get(i) &&
			!b.pushedOut.get(i) &&
			b.outputElements[i] == tagBalancingHTMLStreamEventReceiverTableTag &&
			!b.outputElementsInForeignContent.get(i) {
			return true
		}
	}
	return false
}

// outputlessListIsCurrentContainer is whether the current logical container
// is a list absent from the output.
func (b *TagBalancingHTMLStreamEventReceiver) outputlessListIsCurrentContainer() bool {
	container := b.containerIndex()
	if container < 0 || !b.sentToUnderlying.get(container) ||
		b.pushedOut.get(container) ||
		b.outputElements[container] != tagBalancingHTMLStreamEventReceiverNoOutputElement {
		return false
	}
	element := b.openElements[container]
	return element == tagBalancingHTMLStreamEventReceiverUlTag || element == tagBalancingHTMLStreamEventReceiverOlTag
}

// hasOpenHTMLOutputSelect is whether the current serialized-output scope has
// an HTML select open.
func (b *TagBalancingHTMLStreamEventReceiver) hasOpenHTMLOutputSelect() bool {
	if b.openTagOutputPolicy != nil {
		return b.openTagOutputPolicy.hasOpenHTMLOutputSelect()
	}
	for i := len(b.openElements) - 1; i >= 0; i-- {
		if !b.sentToUnderlying.get(i) ||
			b.pushedOut.get(i) ||
			b.outputElementsInForeignContent.get(i) {
			continue
		}
		switch b.outputElements[i] {
		case tagBalancingHTMLStreamEventReceiverTemplateTag:
			return false
		case tagBalancingHTMLStreamEventReceiverSelectTag:
			return true
		}
	}
	return false
}

// tagBalancingHTMLStreamEventReceiverExitsHTMLSelect is whether a start
// token exits the HTML in-select insertion mode.
func tagBalancingHTMLStreamEventReceiverExitsHTMLSelect(canonElementName string) bool {
	switch canonElementName {
	case "input", "keygen", "select", "textarea":
		return true
	}
	return false
}

// hasOpenHTMLInputSelect is whether a real input select makes a form start
// browser-ignored.
func (b *TagBalancingHTMLStreamEventReceiver) hasOpenHTMLInputSelect() bool {
	return b.htmlInputSelectIsOpen
}

// syncOutputSelectState records output-select closure that happened in the
// preceding event.
func (b *TagBalancingHTMLStreamEventReceiver) syncOutputSelectState() {
	outputSelectIsOpen := b.hasOpenHTMLOutputSelect()
	if b.outputSelectWasOpen && !outputSelectIsOpen {
		if freeItem := b.freeOutputListItemBelow(len(b.openElements)); freeItem >= 0 {
			b.outputListItemAfterClosedSelect = freeItem
		}
	}
	b.outputSelectWasOpen = outputSelectIsOpen
	if b.outputSelectHasText && !outputSelectIsOpen {
		b.outputSelectHasText = false
	}
}

// closeOpenHTMLOptionForStart closes an output option that the next option
// start makes its sibling.
func (b *TagBalancingHTMLStreamEventReceiver) closeOpenHTMLOptionForStart(elIndex int) {
	if elIndex != tagBalancingHTMLStreamEventReceiverOptionTag {
		return
	}
	if b.closeHTMLOutputContainer(tagBalancingHTMLStreamEventReceiverOptionTag) {
		return
	}
	if !b.hasOpenHTMLOutputSelect() {
		return
	}
	option := -1
	for i := len(b.openElements) - 1; i >= 0; i-- {
		if !b.sentToUnderlying.get(i) || b.pushedOut.get(i) {
			continue
		}
		if b.outputElementsInForeignContent.get(i) {
			return
		}
		outputElement := b.outputElements[i]
		if outputElement == tagBalancingHTMLStreamEventReceiverTemplateTag {
			return
		}
		if outputElement == tagBalancingHTMLStreamEventReceiverOptionTag && option < 0 {
			option = i
		} else if outputElement == tagBalancingHTMLStreamEventReceiverSelectTag {
			closeFrom := -1
			if option >= 0 && option+1 < len(b.openElements) {
				onlyTableContextAbove := true
				for j, n := option+1, len(b.openElements); j < n; j++ {
					stackedOutputElement := b.outputElements[j]
					if !b.sentToUnderlying.get(j) ||
						b.pushedOut.get(j) ||
						stackedOutputElement == tagBalancingHTMLStreamEventReceiverNoOutputElement ||
						b.outputElementsInForeignContent.get(j) ||
						!tagBalancingHTMLStreamEventReceiverTableContext[stackedOutputElement] {
						onlyTableContextAbove = false
						break
					}
				}
				if onlyTableContextAbove {
					closeFrom = option
				}
			}
			if closeFrom >= 0 {
				b.closeStackFrom(closeFrom, b.openElements[closeFrom], true)
			}
			return
		}
	}
}

// closeHTMLOutputContainer closes the stacked entry for the current HTML
// output container.
func (b *TagBalancingHTMLStreamEventReceiver) closeHTMLOutputContainer(element int) bool {
	if !b.outputContainerIs(tagBalancingHTMLStreamEventReceiverMetadata.CanonNameForIndex(element)) {
		return false
	}
	for i := len(b.openElements) - 1; i >= 0; i-- {
		if !b.sentToUnderlying.get(i) || b.pushedOut.get(i) {
			continue
		}
		if b.outputElementsInForeignContent.get(i) {
			return false
		}
		outputElement := b.outputElements[i]
		if outputElement == tagBalancingHTMLStreamEventReceiverTemplateTag {
			return false
		}
		if outputElement == element {
			b.closeStackFrom(i, b.openElements[i], true)
			return true
		}
	}
	return false
}

// markOutputSelectRetired mirrors an HTML select suffix the policy closed
// but kept logically.
func (b *TagBalancingHTMLStreamEventReceiver) markOutputSelectRetired() {
	b.outputSelectHasText = false
	selectIndex := -1
	for i := len(b.openElements) - 1; i >= 0; i-- {
		if b.sentToUnderlying.get(i) &&
			!b.pushedOut.get(i) &&
			b.outputElements[i] == tagBalancingHTMLStreamEventReceiverSelectTag &&
			!b.outputElementsInForeignContent.get(i) {
			selectIndex = i
			break
		}
	}
	if selectIndex < 0 {
		return
	}
	if freeItem := b.freeOutputListItemBelow(selectIndex); freeItem >= 0 {
		b.outputListItemAfterClosedSelect = freeItem
	}
	if b.openTagOutputPolicy != nil && b.openTagOutputPolicy.inputSelectRetiredForLastOpenTag() {
		b.discardRetiredInputSelectKeepingPushedTables(selectIndex)
		return
	}
	// The policy already closed every forwarded output element inside the
	// policy-mapped select.  Keep the differently named input elements, but
	// forget them from this output mirror.
	b.closePassthroughsInside(selectIndex, false)
	for i, n := selectIndex, len(b.openElements); i < n; i++ {
		// Table context temporarily pushed out of the output was not in the
		// suffix the policy closed.  Preserve it so a later table part can
		// reopen it in front of the now-retired select.
		if b.pushedOut.get(i) && !b.pushedMappedTemplateOutputOpen.get(i) {
			continue
		}
		b.outputElements[i] = tagBalancingHTMLStreamEventReceiverNoOutputElement
		b.outputElementsInForeignContent.clear(i)
		b.outputElementsStartForeignContent.clear(i)
		b.clearedFormPointerTargets.clear(i)
		b.staleOutputFormPointerTargets.clear(i)
		b.pushedMappedTemplateOutputOpen.clear(i)
	}
}

// freeOutputListItemBelow finds a kept item whose inferred or explicit list
// produced no output, or -1.
func (b *TagBalancingHTMLStreamEventReceiver) freeOutputListItemBelow(stackIndex int) int {
	for i := stackIndex - 1; i >= 0; i-- {
		if !b.sentToUnderlying.get(i) || b.pushedOut.get(i) {
			continue
		}
		if b.outputElementsInForeignContent.get(i) {
			return -1
		}
		outputElement := b.outputElements[i]
		if outputElement == tagBalancingHTMLStreamEventReceiverNoOutputElement {
			continue
		}
		if outputElement != tagBalancingHTMLStreamEventReceiverLiTag || i == 0 {
			return -1
		}
		parent := i - 1
		parentElement := b.openElements[parent]
		if (parentElement == tagBalancingHTMLStreamEventReceiverUlTag ||
			parentElement == tagBalancingHTMLStreamEventReceiverOlTag) &&
			b.sentToUnderlying.get(parent) && !b.pushedOut.get(parent) &&
			b.outputElements[parent] == tagBalancingHTMLStreamEventReceiverNoOutputElement {
			return i
		}
		return -1
	}
	return -1
}

// discardRetiredInputSelectKeepingPushedTables drops a popped input select
// but retains table context already pushed out.
func (b *TagBalancingHTMLStreamEventReceiver) discardRetiredInputSelectKeepingPushedTables(selectIndex int) {
	b.closePassthroughsInside(selectIndex, false)
	b.forgetListOutputContextsFrom(selectIndex)
	oldSize := len(b.openElements)
	destination := selectIndex
	for source := selectIndex + 1; source < oldSize; source++ {
		if !b.pushedOut.get(source) || b.pushedMappedTemplateOutputOpen.get(source) {
			continue
		}
		b.openElements[destination] = b.openElements[source]
		b.inputElementSerials[destination] = b.inputElementSerials[source]
		b.outputElements[destination] = b.outputElements[source]
		b.resumedFormattingFromListItemStart.setTo(destination, b.resumedFormattingFromListItemStart.get(source))
		b.sentToUnderlying.setTo(destination, b.sentToUnderlying.get(source))
		b.inputElementsInForeignContent.setTo(destination, b.inputElementsInForeignContent.get(source))
		b.outputElementsInForeignContent.setTo(destination, b.outputElementsInForeignContent.get(source))
		b.outputElementsStartForeignContent.setTo(destination, b.outputElementsStartForeignContent.get(source))
		b.formPointerTargets.setTo(destination, b.formPointerTargets.get(source))
		b.clearedFormPointerTargets.setTo(destination, b.clearedFormPointerTargets.get(source))
		b.staleOutputFormPointerTargets.setTo(destination, b.staleOutputFormPointerTargets.get(source))
		b.pushedOut.set(destination)
		b.impliedInputTables.setTo(destination, b.impliedInputTables.get(source))
		b.outputlessImpliedSelects.setTo(destination, b.outputlessImpliedSelects.get(source))
		b.outputTableUnavailable.setTo(destination, b.outputTableUnavailable.get(source))
		b.outputlessTablesWithEmittedParts.setTo(destination, b.outputlessTablesWithEmittedParts.get(source))
		b.pushedMappedTemplateOutputOpen.clear(destination)
		b.suppressedMappedForeignSubtrees.setTo(destination, b.suppressedMappedForeignSubtrees.get(source))
		destination++
	}
	for len(b.openElements) > destination {
		last := len(b.openElements) - 1
		b.resumedFormattingFromListItemStart.clear(last)
		b.openElements = b.openElements[:last]
		b.inputElementSerials = b.inputElementSerials[:last]
		b.outputElements = b.outputElements[:last]
	}
	b.sentToUnderlying.clearRange(destination, oldSize)
	b.inputElementsInForeignContent.clearRange(destination, oldSize)
	b.outputElementsInForeignContent.clearRange(destination, oldSize)
	b.outputElementsStartForeignContent.clearRange(destination, oldSize)
	b.formPointerTargets.clearRange(destination, oldSize)
	b.clearedFormPointerTargets.clearRange(destination, oldSize)
	b.staleOutputFormPointerTargets.clearRange(destination, oldSize)
	b.pushedOut.clearRange(destination, oldSize)
	b.impliedInputTables.clearRange(destination, oldSize)
	b.outputlessImpliedSelects.clearRange(destination, oldSize)
	b.outputTableUnavailable.clearRange(destination, oldSize)
	b.outputlessTablesWithEmittedParts.clearRange(destination, oldSize)
	b.pushedMappedTemplateOutputOpen.clearRange(destination, oldSize)
	b.suppressedMappedForeignSubtrees.clearRange(destination, oldSize)
	b.resumedFormattingFromListItemStart.clearRange(destination, oldSize)
}

// retireMappedOutputContainer closes a mapped HTML output container and its
// logical descendants.
func (b *TagBalancingHTMLStreamEventReceiver) retireMappedOutputContainer(outputElement int) bool {
	for i := len(b.openElements) - 1; i >= 0; i-- {
		if !b.sentToUnderlying.get(i) ||
			b.pushedOut.get(i) ||
			b.outputElements[i] == tagBalancingHTMLStreamEventReceiverNoOutputElement {
			continue
		}
		if b.outputElementsInForeignContent.get(i) ||
			b.outputElements[i] != outputElement ||
			b.openElements[i] == outputElement {
			return false
		}
		b.closeStackFrom(i, b.openElements[i], true)
		return true
	}
	return false
}

// hasOpenLiteralOutputFromImpliedTable is whether an implied logical table
// owns the kept literal output.
func (b *TagBalancingHTMLStreamEventReceiver) hasOpenLiteralOutputFromImpliedTable() bool {
	for i := len(b.openElements) - 1; i >= 0; i-- {
		outputElement := b.outputElements[i]
		if b.impliedInputTables.get(i) &&
			b.sentToUnderlying.get(i) &&
			!b.pushedOut.get(i) &&
			outputElement != tagBalancingHTMLStreamEventReceiverNoOutputElement &&
			!b.outputElementsInForeignContent.get(i) &&
			tagBalancingHTMLStreamEventReceiverHasSpecialTextMode(outputElement) {
			return true
		}
	}
	return false
}

// hasUnavailableInputTableInScope is whether the nearest input table in
// scope has no usable output table.
func (b *TagBalancingHTMLStreamEventReceiver) hasUnavailableInputTableInScope() bool {
	tableScope := tagBalancingHTMLStreamEventReceiverScopeForEndTag[tagBalancingHTMLStreamEventReceiverTableTag]
	for i := len(b.openElements) - 1; i >= 0; i-- {
		openElement := b.openElements[i]
		if openElement == tagBalancingHTMLStreamEventReceiverTableTag {
			return b.outputTableUnavailable.get(i) ||
				b.outputElements[i] != tagBalancingHTMLStreamEventReceiverTableTag
		}
		if tagBalancingHTMLStreamEventReceiverScopesByElement[openElement]&tableScope != 0 {
			return false
		}
	}
	return false
}

// markNearestInputTableUnavailable prevents later parts of the nearest
// missing input table from emitting.
func (b *TagBalancingHTMLStreamEventReceiver) markNearestInputTableUnavailable() {
	tableScope := tagBalancingHTMLStreamEventReceiverScopeForEndTag[tagBalancingHTMLStreamEventReceiverTableTag]
	for i := len(b.openElements) - 1; i >= 0; i-- {
		openElement := b.openElements[i]
		if openElement == tagBalancingHTMLStreamEventReceiverTableTag {
			b.outputTableUnavailable.set(i)
			return
		}
		if tagBalancingHTMLStreamEventReceiverScopesByElement[openElement]&tableScope != 0 {
			return
		}
	}
}

// hasInputTableMappedToForeignSelectInScope is whether the nearest input
// table became a foreign select.
func (b *TagBalancingHTMLStreamEventReceiver) hasInputTableMappedToForeignSelectInScope() bool {
	tableScope := tagBalancingHTMLStreamEventReceiverScopeForEndTag[tagBalancingHTMLStreamEventReceiverTableTag]
	for i := len(b.openElements) - 1; i >= 0; i-- {
		openElement := b.openElements[i]
		if openElement == tagBalancingHTMLStreamEventReceiverTableTag {
			return b.sentToUnderlying.get(i) &&
				!b.pushedOut.get(i) &&
				b.outputElements[i] == tagBalancingHTMLStreamEventReceiverSelectTag &&
				b.outputElementsInForeignContent.get(i)
		}
		if tagBalancingHTMLStreamEventReceiverScopesByElement[openElement]&tableScope != 0 {
			return false
		}
	}
	return false
}

// topIsOutputlessInputTable is whether the logical top is a table the policy
// did not emit.
func (b *TagBalancingHTMLStreamEventReceiver) topIsOutputlessInputTable() bool {
	top := len(b.openElements) - 1
	return top >= 0 &&
		!b.pushedOut.get(top) &&
		b.openElements[top] == tagBalancingHTMLStreamEventReceiverTableTag &&
		b.outputElements[top] == tagBalancingHTMLStreamEventReceiverNoOutputElement
}

// hasOutputTemplateAboveOutputlessTable is whether an output template
// exposes a missing table below it.
func (b *TagBalancingHTMLStreamEventReceiver) hasOutputTemplateAboveOutputlessTable() bool {
	sawOutputTemplate := false
	for i := len(b.openElements) - 1; i >= 0; i-- {
		if b.openElements[i] == tagBalancingHTMLStreamEventReceiverTemplateTag &&
			b.sentToUnderlying.get(i) &&
			!b.pushedOut.get(i) &&
			b.outputElements[i] == tagBalancingHTMLStreamEventReceiverTemplateTag &&
			!b.outputElementsInForeignContent.get(i) {
			sawOutputTemplate = true
		}
		if b.openElements[i] == tagBalancingHTMLStreamEventReceiverTableTag {
			return sawOutputTemplate && b.outputElements[i] != tagBalancingHTMLStreamEventReceiverTableTag
		}
	}
	return false
}

// recordEmittedPartForOutputlessTable records a part emitted into an
// outputless logical table in scope.
func (b *TagBalancingHTMLStreamEventReceiver) recordEmittedPartForOutputlessTable(
	stackIndex, outputElementIndex int, outputIsForeign bool,
) {
	if outputElementIndex == tagBalancingHTMLStreamEventReceiverNoOutputElement ||
		outputIsForeign || !tagBalancingHTMLStreamEventReceiverTableParts[outputElementIndex] {
		return
	}
	tableScope := tagBalancingHTMLStreamEventReceiverScopeForEndTag[tagBalancingHTMLStreamEventReceiverTableTag]
	for i := stackIndex - 1; i >= 0; i-- {
		openElement := b.openElements[i]
		if openElement == tagBalancingHTMLStreamEventReceiverTableTag {
			if b.outputElements[i] != tagBalancingHTMLStreamEventReceiverTableTag ||
				b.outputTableUnavailable.get(i) {
				b.outputlessTablesWithEmittedParts.set(i)
			}
			return
		}
		if tagBalancingHTMLStreamEventReceiverScopesByElement[openElement]&tableScope != 0 {
			return
		}
	}
}

// hasNestedOutputlessTableInCaptionWithEmittedParts is whether a nested
// outputless implied table inside a caption emitted parts.  A later table
// part exits the caption in the output parser, so formatting opened after
// the nested table cannot remain around that part.
func (b *TagBalancingHTMLStreamEventReceiver) hasNestedOutputlessTableInCaptionWithEmittedParts() bool {
	if b.outputlessTablesWithEmittedParts.isEmpty() {
		return false
	}
	innerTable := -1
	for i := len(b.openElements) - 1; i >= 0; i-- {
		openElement := b.openElements[i]
		if openElement == tagBalancingHTMLStreamEventReceiverTableTag {
			if !b.outputlessTablesWithEmittedParts.get(i) {
				return false
			}
			innerTable = i
			break
		}
		if openElement == tagBalancingHTMLStreamEventReceiverTemplateTag ||
			openElement == tagBalancingHTMLStreamEventReceiverTdTag ||
			openElement == tagBalancingHTMLStreamEventReceiverThTag {
			return false
		}
	}
	if innerTable < 0 {
		return false
	}
	sawOutputCaption := false
	for i := innerTable - 1; i >= 0; i-- {
		openElement := b.openElements[i]
		if openElement == tagBalancingHTMLStreamEventReceiverCaptionTag &&
			b.sentToUnderlying.get(i) &&
			!b.pushedOut.get(i) &&
			b.outputElements[i] == tagBalancingHTMLStreamEventReceiverCaptionTag &&
			!b.outputElementsInForeignContent.get(i) {
			sawOutputCaption = true
		}
		if openElement == tagBalancingHTMLStreamEventReceiverTableTag {
			return sawOutputCaption && b.outputlessTablesWithEmittedParts.get(i)
		}
		if openElement == tagBalancingHTMLStreamEventReceiverTemplateTag {
			return false
		}
	}
	return false
}

// hasPushedOutputlessTableWithEmittedParts is whether a marked outputless
// table is pushed out in table scope.
func (b *TagBalancingHTMLStreamEventReceiver) hasPushedOutputlessTableWithEmittedParts() bool {
	if b.outputlessTablesWithEmittedParts.isEmpty() {
		return false
	}
	tableScope := tagBalancingHTMLStreamEventReceiverScopeForEndTag[tagBalancingHTMLStreamEventReceiverTableTag]
	for i := len(b.openElements) - 1; i >= 0; i-- {
		openElement := b.openElements[i]
		if openElement == tagBalancingHTMLStreamEventReceiverTableTag {
			return b.pushedOut.get(i) && b.outputlessTablesWithEmittedParts.get(i)
		}
		if tagBalancingHTMLStreamEventReceiverScopesByElement[openElement]&tableScope != 0 {
			return false
		}
	}
	return false
}

// hasOutputlessTableWithEmittedPartsInScope is whether the nearest logical
// table emitted parts but no table element.
func (b *TagBalancingHTMLStreamEventReceiver) hasOutputlessTableWithEmittedPartsInScope() bool {
	if b.outputlessTablesWithEmittedParts.isEmpty() {
		return false
	}
	for i := len(b.openElements) - 1; i >= 0; i-- {
		openElement := b.openElements[i]
		if openElement == tagBalancingHTMLStreamEventReceiverTableTag {
			return b.outputElements[i] != tagBalancingHTMLStreamEventReceiverTableTag &&
				b.outputlessTablesWithEmittedParts.get(i)
		}
		if openElement == tagBalancingHTMLStreamEventReceiverTemplateTag {
			return false
		}
	}
	return false
}

// textIsInLoneHTMLForeignObjectPassthrough is whether text is in the only
// HTML foreignObject passthrough.
func (b *TagBalancingHTMLStreamEventReceiver) textIsInLoneHTMLForeignObjectPassthrough(logicalContainer int) bool {
	if !b.outputContainerIs("foreignObject") {
		return false
	}
	_, hasOutputForeignRoot := b.outputForeignContentRootName()
	return !hasOutputForeignRoot &&
		len(b.passthroughNames) == 1 &&
		b.passthroughNames[0] == "foreignObject" &&
		b.passthroughDepths[0] == logicalContainer+1
}

// tableContextMaskedForText is the output table context hidden by logical
// entries that emitted no node, or -1.
func (b *TagBalancingHTMLStreamEventReceiver) tableContextMaskedForText() int {
	if b.openTagOutputPolicy == nil {
		return -1
	}
	name, ok := b.openTagOutputPolicy.outputContainerElementName()
	if !ok {
		return -1
	}
	actualOutputContainer := tagBalancingHTMLStreamEventReceiverMetadata.IndexForName(
		htmlLexerCanonicalElementName(name))
	sawOutputlessEntry := false
	for i := b.containerIndex(); i >= 0; i-- {
		if !b.sentToUnderlying.get(i) || b.pushedOut.get(i) {
			continue
		}
		outputElement := b.outputElements[i]
		if outputElement == tagBalancingHTMLStreamEventReceiverNoOutputElement {
			sawOutputlessEntry = true
			continue
		}
		if sawOutputlessEntry &&
			outputElement == actualOutputContainer &&
			tagBalancingHTMLStreamEventReceiverTableContext[b.openElements[i]] &&
			tagBalancingHTMLStreamEventReceiverTableContext[outputElement] {
			return i
		}
		return -1
	}
	return -1
}

// hasNestedUnavailableTableAboveEmittedOutputlessTable is whether a nested
// missing table hides parts emitted for an outer one.
func (b *TagBalancingHTMLStreamEventReceiver) hasNestedUnavailableTableAboveEmittedOutputlessTable() bool {
	if b.outputlessTablesWithEmittedParts.isEmpty() {
		return false
	}
	sawUnavailableTable := false
	for i := len(b.openElements) - 1; i >= 0; i-- {
		if b.openElements[i] != tagBalancingHTMLStreamEventReceiverTableTag {
			continue
		}
		if sawUnavailableTable &&
			b.impliedInputTables.get(i) &&
			b.outputElements[i] == tagBalancingHTMLStreamEventReceiverNoOutputElement &&
			b.outputlessTablesWithEmittedParts.get(i) {
			return true
		}
		if b.outputTableUnavailable.get(i) &&
			!b.impliedInputTables.get(i) &&
			b.outputElements[i] == tagBalancingHTMLStreamEventReceiverNoOutputElement {
			sawUnavailableTable = true
		}
	}
	return false
}

// outputAllowsImplicitTableReturn is whether no output scope boundary
// separates a detached implied table.
func (b *TagBalancingHTMLStreamEventReceiver) outputAllowsImplicitTableReturn() bool {
	if b.isOutputInForeignContent() {
		return false
	}
	for i := len(b.openElements) - 1; i >= 0; i-- {
		if !b.sentToUnderlying.get(i) || b.pushedOut.get(i) {
			continue
		}
		outputElement := b.outputElements[i]
		if b.outputElementsInForeignContent.get(i) ||
			outputElement == tagBalancingHTMLStreamEventReceiverTemplateTag ||
			(outputElement != tagBalancingHTMLStreamEventReceiverNoOutputElement &&
				(tagBalancingHTMLStreamEventReceiverHasSpecialTextMode(outputElement) ||
					tagBalancingHTMLStreamEventReceiverMetadata.CanonNameForIndex(outputElement) == "noscript")) {
			return false
		}
	}
	return true
}

// markOutputlessTablePartsMayBeOpen starts persistent state without making
// it visible recursively.
func (b *TagBalancingHTMLStreamEventReceiver) markOutputlessTablePartsMayBeOpen() {
	if !b.outputlessTablePartsMayBeOpen {
		b.outputlessTablePartsMayBeOpen = true
		b.outputlessTablePartsOpenedAtEvent = b.openTagEvent
	}
}

// detachOutputlessTableWithEmittedParts carries an unclosed browser-implied
// table beyond its logical table.
func (b *TagBalancingHTMLStreamEventReceiver) detachOutputlessTableWithEmittedParts(stackIndex int) {
	if b.openElements[stackIndex] == tagBalancingHTMLStreamEventReceiverTableTag &&
		b.outputlessTablesWithEmittedParts.get(stackIndex) {
		b.markOutputlessTablePartsMayBeOpen()
	}
	b.outputlessTablesWithEmittedParts.clear(stackIndex)
}

// retireFormattingAboveImplicitOutputTable retires formatting fostered
// beside an output-only implied table.
func (b *TagBalancingHTMLStreamEventReceiver) retireFormattingAboveImplicitOutputTable() bool {
	formatting := -1
	for i := len(b.openElements) - 1; i >= 0; i-- {
		if b.openElements[i] == tagBalancingHTMLStreamEventReceiverTableTag {
			return false
		}
		if tagBalancingHTMLStreamEventReceiverMetadata.Resumable(b.openElements[i]) {
			formatting = i
			break
		}
	}
	if formatting < 0 {
		return false
	}
	formattingElement := b.openElements[formatting]
	resumedFromListItemStart := b.resumedFormattingFromListItemStart.get(formatting)
	b.closeStackFrom(formatting, formattingElement, true)
	b.queueForResumption(formattingElement, resumedFromListItemStart)
	return true
}

// pushedTableRequiresSelectEscape is whether a hidden select wrapper must
// not block return to a real table.
func (b *TagBalancingHTMLStreamEventReceiver) pushedTableRequiresSelectEscape() bool {
	for i := b.pushedOut.nextSetBit(0); i >= 0; i = b.pushedOut.nextSetBit(i + 1) {
		if b.openElements[i] == tagBalancingHTMLStreamEventReceiverTableTag &&
			(!b.impliedInputTables.get(i) ||
				b.outputElements[i] != tagBalancingHTMLStreamEventReceiverNoOutputElement) {
			return true
		}
	}
	return false
}

// returnToTableContext returns a table part to the nearest table in table
// scope before implying wrappers.  A row inside a cell's div ends the cell
// and row; it does not start a second table in the div.  A template starts
// a separate context.
//
// It returns false if the nearest logical table was not emitted as a table,
// in which case the caller preserves the older implied-element path.
func (b *TagBalancingHTMLStreamEventReceiver) returnToTableContext(elIndex int) bool {
	table := -1
	tableScope := tagBalancingHTMLStreamEventReceiverScopeForEndTag[tagBalancingHTMLStreamEventReceiverTableTag]
	for i := len(b.openElements) - 1; i >= 0; i-- {
		openElementIndex := b.openElements[i]
		if openElementIndex == tagBalancingHTMLStreamEventReceiverTableTag {
			// A table that policy dropped or renamed does not establish table
			// context in the output.  Keep the older implied-table path for
			// its parts so the output does not acquire bare adjacent row
			// groups.
			if b.outputElements[i] != tagBalancingHTMLStreamEventReceiverTableTag &&
				(b.outputElements[i] != tagBalancingHTMLStreamEventReceiverColTag ||
					b.outputElementsInForeignContent.get(i)) {
				return false
			}
			table = i
			break
		}
		if tagBalancingHTMLStreamEventReceiverScopesByElement[openElementIndex]&tableScope != 0 {
			return true
		}
	}
	if table < 0 {
		return true
	}
	for i := len(b.openElements) - 1; i > table; i-- {
		if b.canHold(elIndex, b.openElements[i], i) {
			break
		}
		sendClose := b.shouldSendClose(i)
		b.closePassthroughsInside(i, true)
		b.forgetListOutputContextsFrom(i)
		unclosed := b.removeStackEntry(i)
		if sendClose {
			b.underlying.CloseTag(tagBalancingHTMLStreamEventReceiverMetadata.CanonNameForIndex(unclosed))
		}
		b.clearStackFlags(i)
	}
	return true
}

// endsAnOpenLink is true if a link is open, no further down than lowerBound,
// that a browser ends before opening this one.
func (b *TagBalancingHTMLStreamEventReceiver) endsAnOpenLink(elIndex, lowerBound int) bool {
	return elIndex == tagBalancingHTMLStreamEventReceiverATag && b.hasOpenLinkInFormattingScope(lowerBound)
}

// tagBalancingHTMLStreamEventReceiverStartAfter is the position in an
// implied path after the container itself, if the path runs through it,
// else the start of the path.
func tagBalancingHTMLStreamEventReceiverStartAfter(implied []int, top int) int {
	if i := slices.Index(implied, top); i >= 0 {
		return i + 1
	}
	return 0
}

// listItemToCloseForStart is the open list item that a browser closes for a
// list item start tag, or -1 for none: the walk down the stack stops at the
// first barrier, and at the foreign root below which content is judged as in
// a fresh body.  The item a select keeps for content it cannot hold is none
// of the input's, and the select below it is a barrier anyway.
func (b *TagBalancingHTMLStreamEventReceiver) listItemToCloseForStart(foreignRootBoundary int) int {
	floor := max(0, foreignRootBoundary)
	for i := len(b.openElements) - 1; i >= floor; i-- {
		if b.inputElementsInForeignContent.get(i) || b.outputElementsInForeignContent.get(i) {
			// Neither parser is under HTML rules here.
			return -1
		}
		openElement := b.openElements[i]
		if openElement == tagBalancingHTMLStreamEventReceiverLiTag &&
			!b.isNeverSentImpliedListItem(i) &&
			b.shouldSendClose(i) &&
			b.outputElements[i] == tagBalancingHTMLStreamEventReceiverLiTag &&
			!b.outputElementsInForeignContent.get(i) &&
			(b.openTagOutputPolicy == nil || b.openTagOutputPolicy.hasOpenHTMLOutputListItem()) {
			return i
		}
		// An element with no output, one the policy dropped or one this
		// receiver implied, and a table already closed in the output to put
		// content in front of it, bound nothing a browser reading that output
		// can see, so they bound nothing here: leaving them barriers made a
		// first pass keep an item that the second pass closed.
		if b.outputElements[i] == tagBalancingHTMLStreamEventReceiverNoOutputElement || b.pushedOut.get(i) {
			// A select that the policy drops, and the option or optgroup it
			// implies around content, still determine which list item the
			// balancer writes.  Crossing one here makes a first pass nest an
			// item and the next pass close it after the dropped wrapper is no
			// longer present (#494, #502).
			if b.outputElements[i] == tagBalancingHTMLStreamEventReceiverNoOutputElement &&
				(openElement == tagBalancingHTMLStreamEventReceiverSelectTag ||
					openElement == tagBalancingHTMLStreamEventReceiverOptionTag ||
					openElement == tagBalancingHTMLStreamEventReceiverOptgroupTag) {
				return -1
			}
			continue
		}
		// The emitted element is what bounds the walk, not the name the input
		// wrote: a policy that renames a barrier to something else leaves no
		// barrier in the output to find.
		if tagBalancingHTMLStreamEventReceiverListItemStartBarriers[b.outputElements[i]] {
			return -1
		}
	}
	return -1
}

// isInsideItemOpenedAfterListItemStart is whether the current stack is
// inside the sibling opened by the list-item-start rule.
func (b *TagBalancingHTMLStreamEventReceiver) isInsideItemOpenedAfterListItemStart() bool {
	for i := len(b.openElements) - 1; i >= 0; i-- {
		if b.openElements[i] == tagBalancingHTMLStreamEventReceiverLiTag &&
			b.resumedFormattingFromListItemStart.get(i) {
			return true
		}
	}
	return false
}

// listItemStartPoppedForwardedForeignRoot is whether this start just broke
// out of a forwarded output foreign root.
func (b *TagBalancingHTMLStreamEventReceiver) listItemStartPoppedForwardedForeignRoot() bool {
	for i := len(b.passthroughForeignRoots) - 1; i >= 0; i-- {
		root := b.passthroughForeignRoots[i]
		if b.passthroughOutputForeign.get(root) &&
			!b.foreignContent.isNodeOpen(b.passthroughSerials[root]) {
			return true
		}
	}
	return false
}

// needsFosterParenting is whether a browser would foster-parent this token
// out of an open table.
func (b *TagBalancingHTMLStreamEventReceiver) needsFosterParenting(elIndex, foreignRootBoundary int) bool {
	if !tagBalancingHTMLStreamEventReceiverIsFosterParented(elIndex) ||
		b.endsAnOpenLink(elIndex, foreignRootBoundary) {
		return false
	}
	tableIndex := b.containerIndex()
	return tableIndex >= 0 &&
		tagBalancingHTMLStreamEventReceiverTableContext[b.openElements[tableIndex]] &&
		!b.canHold(elIndex, b.openElements[tableIndex], tableIndex)
}

// foreignRootArrivesInTableMode is whether an SVG or MathML root arriving
// under HTML rules is in a table insertion mode: directly in a table, row
// group, row or column group, where a browser foster-parents it in front of
// the table.
func (b *TagBalancingHTMLStreamEventReceiver) foreignRootArrivesInTableMode() bool {
	container := b.containerIndex()
	if container < 0 {
		return false
	}
	top := b.openElements[container]
	return tagBalancingHTMLStreamEventReceiverTableContext[top] || top == tagBalancingHTMLStreamEventReceiverColgroupTag
}

// tagBalancingHTMLStreamEventReceiverIsFosterParented is true if a browser
// puts content of this kind that arrives inside a table, outside a cell or
// caption, in front of the table rather than in it: text, and any element
// that is not one of a table's own parts.  What a table may hold directly,
// such as a script or a form, never reaches this: the containment tables say
// the table can contain it.
func tagBalancingHTMLStreamEventReceiverIsFosterParented(elIndex int) bool {
	return elIndex == TextNode || !tagBalancingHTMLStreamEventReceiverTableParts[elIndex]
}

// tagBalancingHTMLStreamEventReceiverIsForeignContentRoot is whether this
// name establishes SVG or MathML foreign content.
func tagBalancingHTMLStreamEventReceiverIsForeignContentRoot(canonElementName string) bool {
	return canonElementName == "svg" || canonElementName == "math"
}

// containerHasSpecialTextMode is whether the entry content goes into is read
// as raw text by the lexer.
func (b *TagBalancingHTMLStreamEventReceiver) containerHasSpecialTextMode() bool {
	container := b.containerIndex()
	return container >= 0 && tagBalancingHTMLStreamEventReceiverHasSpecialTextMode(b.openElements[container])
}

// contentGoesIntoRawTextElement is whether content arriving now goes into
// an element whose content this lexer reads as raw text, counting one
// forwarded under a name this receiver does not recognize, such as the
// SVG-cased textArea, which has no entry on the stack.
func (b *TagBalancingHTMLStreamEventReceiver) contentGoesIntoRawTextElement() bool {
	// Every forwarded element still open contains what arrives now, so one
	// anywhere above it decides, not only the innermost.  Keep a count as
	// starts and ends arrive: scanning here makes a long run of forwarded
	// elements followed by list items quadratic.
	return b.passthroughSpecialTextModeDepth != 0 || b.containerHasSpecialTextMode()
}

// containerIndex is the stack index of the element that content arriving
// now goes into: the top, unless a pushed-out table is at the top, in which
// case the content goes beside the table, so the element that contains the
// table is the one that contains the content.
func (b *TagBalancingHTMLStreamEventReceiver) containerIndex() int {
	retiredOutputlessSuffix := b.hasRetiredOutputlessTableSuffix()
	i := len(b.openElements) - 1
	// Skip a table closed in the output but still open here, and logical
	// descendants whose output was retired with such a table.
	for i >= 0 &&
		(b.pushedOut.get(i) ||
			(retiredOutputlessSuffix && b.outputElements[i] == tagBalancingHTMLStreamEventReceiverNoOutputElement)) {
		i--
	}
	return i
}

// hasRetiredOutputlessTableSuffix is whether the top suffix exists only
// logically above a retired table.
func (b *TagBalancingHTMLStreamEventReceiver) hasRetiredOutputlessTableSuffix() bool {
	for i := len(b.openElements) - 1; i >= 0; i-- {
		if b.openElements[i] == tagBalancingHTMLStreamEventReceiverTableTag &&
			b.pushedOut.get(i) &&
			b.outputTableUnavailable.get(i) {
			return true
		}
		if b.pushedOut.get(i) {
			continue
		}
		if b.outputElements[i] != tagBalancingHTMLStreamEventReceiverNoOutputElement {
			return false
		}
	}
	return false
}

// canHold is true if container can hold elIndex, with elements implied
// between them where it needs them.  The implied path has to run through
// the container: one that does not is a fresh table, or list, to open
// inside it rather than a way into the one that is already open.
func (b *TagBalancingHTMLStreamEventReceiver) canHold(elIndex, container, containerIndexOnStack int) bool {
	if containerIndexOnStack >= 0 && containerIndexOnStack < len(b.openElements) {
		container = b.effectiveContainer(elIndex, containerIndexOnStack)
	}
	// A col goes directly in a table's implicit colgroup.  The canned
	// implied path omits the table itself, unlike the other paths handled
	// below.
	if container == tagBalancingHTMLStreamEventReceiverTableTag && elIndex == tagBalancingHTMLStreamEventReceiverColTag {
		return true
	}
	implied := tagBalancingHTMLStreamEventReceiverMetadata.impliedElements(container, elIndex)
	if i := slices.Index(implied, container); i >= 0 {
		return i+1 < len(implied) || b.canContain(elIndex, container, containerIndexOnStack)
	}
	return len(implied) == 0 && b.canContain(elIndex, container, containerIndexOnStack)
}

// effectiveContainer is the element that the output treats as holding child
// where the entry at containerIndexOnStack is the logical container.  It
// uses a physically open mapped table for its input table-part tokens.
func (b *TagBalancingHTMLStreamEventReceiver) effectiveContainer(child, containerIndexOnStack int) int {
	onStack := containerIndexOnStack >= 0 && containerIndexOnStack < len(b.openElements)
	childIsTablePart := child >= 0 && tagBalancingHTMLStreamEventReceiverTableParts[child]
	if childIsTablePart &&
		onStack &&
		b.suppressedMappedForeignSubtrees.get(containerIndexOnStack) &&
		!(b.policyOnlyTableMayBeOpen &&
			b.openTagOutputPolicy != nil &&
			b.policyOnlyFormTableContext() == tagBalancingHTMLStreamEventReceiverPolicyOnlyTableContext &&
			b.outputContainerIs("table")) {
		return tagBalancingHTMLStreamEventReceiverBodyTag
	}
	if child == tagBalancingHTMLStreamEventReceiverOptionTag && b.outputContainerIs("select") {
		return tagBalancingHTMLStreamEventReceiverSelectTag
	}
	outputContainerName, hasOutputContainer := "", false
	if b.openTagOutputPolicy != nil {
		outputContainerName, hasOutputContainer = b.openTagOutputPolicy.outputContainerElementName()
	}
	if (child == tagBalancingHTMLStreamEventReceiverOptionTag || child == tagBalancingHTMLStreamEventReceiverOptgroupTag) &&
		hasOutputContainer &&
		onStack &&
		b.sentToUnderlying.get(containerIndexOnStack) &&
		b.outputElements[containerIndexOnStack] == tagBalancingHTMLStreamEventReceiverNoOutputElement &&
		(b.openElements[containerIndexOnStack] == tagBalancingHTMLStreamEventReceiverSelectTag ||
			b.openElements[containerIndexOnStack] == tagBalancingHTMLStreamEventReceiverOptgroupTag) {
		// A select the output parser closed is still present only as a
		// logical input entry.  Judge a later option where the output really
		// is, so it gets the wrapper that will also be present on the next
		// pass.
		return b.outputContainerIndexOrBody()
	}
	if child == tagBalancingHTMLStreamEventReceiverOptionTag &&
		b.openTagOutputPolicy != nil && !hasOutputContainer {
		if onStack &&
			(b.openElements[containerIndexOnStack] == tagBalancingHTMLStreamEventReceiverSelectTag ||
				b.openElements[containerIndexOnStack] == tagBalancingHTMLStreamEventReceiverOptgroupTag) {
			// The option's select is open in the input; the policy dropped it
			// and everything around it.  A browser reading the output finds an
			// option with no select, which the containment metadata answers
			// with an implied select that the same policy drops again.
			// Preparing that select under the dropped one also implied a list
			// item, which was emitted and held everything up to the enclosing
			// block.  Nothing needs implying: the option goes where its select
			// would have been.
			return b.openElements[containerIndexOnStack]
		}
		return tagBalancingHTMLStreamEventReceiverBodyTag
	}
	if child == tagBalancingHTMLStreamEventReceiverOptionTag && hasOutputContainer && outputContainerName == "noscript" {
		return tagBalancingHTMLStreamEventReceiverMetadata.IndexForName("noscript")
	}
	if child == tagBalancingHTMLStreamEventReceiverOptionTag &&
		b.isOutputInForeignContent() &&
		b.hasUnavailableInputTableInScope() {
		return tagBalancingHTMLStreamEventReceiverBodyTag
	}
	if child == tagBalancingHTMLStreamEventReceiverOptionTag &&
		!b.isOutputInForeignContent() &&
		b.hasDroppedTemplateAbove(-1) &&
		b.hasUnavailableOutputlessTable() {
		if outputContainer := b.outputContainerIndex(); outputContainer != tagBalancingHTMLStreamEventReceiverUnrecognizedTag {
			return outputContainer
		}
	}
	if child == tagBalancingHTMLStreamEventReceiverOptionTag &&
		!b.isOutputInForeignContent() &&
		onStack {
		inputContainer := b.openElements[containerIndexOnStack]
		if inputContainer == tagBalancingHTMLStreamEventReceiverTdTag || inputContainer == tagBalancingHTMLStreamEventReceiverThTag {
			if outputContainer := b.outputContainerIndex(); outputContainer != tagBalancingHTMLStreamEventReceiverUnrecognizedTag {
				return outputContainer
			}
		}
	}
	if child == tagBalancingHTMLStreamEventReceiverOptionTag &&
		onStack &&
		b.outputElements[containerIndexOnStack] == tagBalancingHTMLStreamEventReceiverNoOutputElement &&
		(!b.pushedOut.isEmpty() ||
			tagBalancingHTMLStreamEventReceiverTableParts[b.openElements[containerIndexOnStack]]) &&
		b.hasUnavailableOutputlessTable() {
		return tagBalancingHTMLStreamEventReceiverBodyTag
	}
	if child == tagBalancingHTMLStreamEventReceiverOptionTag &&
		!b.pushedOut.isEmpty() &&
		onStack &&
		b.openElements[containerIndexOnStack] == tagBalancingHTMLStreamEventReceiverTemplateTag &&
		b.outputElements[containerIndexOnStack] != tagBalancingHTMLStreamEventReceiverTemplateTag {
		return tagBalancingHTMLStreamEventReceiverBodyTag
	}
	if (child == tagBalancingHTMLStreamEventReceiverOptionTag ||
		child == tagBalancingHTMLStreamEventReceiverOptgroupTag ||
		child == tagBalancingHTMLStreamEventReceiverCaptionTag ||
		child == tagBalancingHTMLStreamEventReceiverColgroupTag ||
		child == tagBalancingHTMLStreamEventReceiverColTag) &&
		!b.isOutputInForeignContent() &&
		onStack &&
		b.openElements[containerIndexOnStack] == tagBalancingHTMLStreamEventReceiverTemplateTag &&
		b.outputElements[containerIndexOnStack] != tagBalancingHTMLStreamEventReceiverTemplateTag &&
		b.sentToUnderlying.get(containerIndexOnStack) {
		// A template holds an option, optgroup, caption, column group or col
		// directly, so the containment metadata implies no select or table
		// for one there, but a template the policy dropped or renamed
		// establishes none in the output: the element lands where the
		// template was, or in what the template became, and is judged there,
		// so it gets the select or table it gets in that place instead of
		// coming out bare, an orphan caption that the output parser drops,
		// for the next pass to wrap (#492, items 9 and 2).  The other table
		// parts already get their table under a template through the
		// metadata.
		return b.outputContainerIndexOrBody()
	}
	wrapperSensitiveChild := child >= 0 &&
		(tagBalancingHTMLStreamEventReceiverTableParts[child] || child == tagBalancingHTMLStreamEventReceiverOptionTag)
	if wrapperSensitiveChild &&
		onStack &&
		!b.sentToUnderlying.get(containerIndexOnStack) &&
		b.outputElements[containerIndexOnStack] != tagBalancingHTMLStreamEventReceiverNoOutputElement {
		for i := containerIndexOnStack - 1; i >= 0; i-- {
			if !b.sentToUnderlying.get(i) ||
				b.pushedOut.get(i) ||
				b.outputElements[i] == tagBalancingHTMLStreamEventReceiverNoOutputElement {
				continue
			}
			if b.outputElementsInForeignContent.get(i) {
				return b.openElements[containerIndexOnStack]
			}
			return b.outputElements[i]
		}
		return tagBalancingHTMLStreamEventReceiverBodyTag
	}
	if childIsTablePart &&
		b.policyOnlyTableMayBeOpen &&
		b.openTagOutputPolicy != nil &&
		b.policyOnlyFormTableContext() == tagBalancingHTMLStreamEventReceiverPolicyOnlyTableContext &&
		hasOutputContainer && outputContainerName == "table" {
		// An unrecognized input element can be kept as a table by policy.  It
		// has no balancer-stack entry, but its parts must use that physically
		// open table instead of implying a nested one beside the logical top.
		return tagBalancingHTMLStreamEventReceiverTableTag
	}
	if childIsTablePart &&
		onStack &&
		b.sentToUnderlying.get(containerIndexOnStack) &&
		!b.pushedOut.get(containerIndexOnStack) &&
		!b.outputTableUnavailable.get(containerIndexOnStack) &&
		!b.outputElementsInForeignContent.get(containerIndexOnStack) &&
		b.outputElements[containerIndexOnStack] == tagBalancingHTMLStreamEventReceiverTableTag {
		return tagBalancingHTMLStreamEventReceiverTableTag
	}
	if child >= 0 &&
		(childIsTablePart || child == tagBalancingHTMLStreamEventReceiverOptionTag) &&
		onStack &&
		b.sentToUnderlying.get(containerIndexOnStack) &&
		!b.pushedOut.get(containerIndexOnStack) &&
		!b.outputTableUnavailable.get(containerIndexOnStack) &&
		!b.outputElementsInForeignContent.get(containerIndexOnStack) &&
		!b.outputElementsStartForeignContent.get(containerIndexOnStack) {
		if _, ok := b.outputForeignContentRootName(); !ok {
			outputContainer := b.outputElements[containerIndexOnStack]
			inputContainer := b.openElements[containerIndexOnStack]
			if childIsTablePart &&
				inputContainer == tagBalancingHTMLStreamEventReceiverTableTag &&
				outputContainer != tagBalancingHTMLStreamEventReceiverTableTag &&
				outputContainer != tagBalancingHTMLStreamEventReceiverTemplateTag {
				// A table renamed to an ordinary HTML element cannot contain
				// its structural parts.  Keep using the logical table so those
				// parts are suppressed there instead of implying a second
				// renamed table.
				return tagBalancingHTMLStreamEventReceiverTableTag
			}
			if outputContainer != tagBalancingHTMLStreamEventReceiverNoOutputElement &&
				outputContainer != inputContainer &&
				!(outputContainer == tagBalancingHTMLStreamEventReceiverSelectTag && childIsTablePart) &&
				!(outputContainer == tagBalancingHTMLStreamEventReceiverTemplateTag &&
					inputContainer == tagBalancingHTMLStreamEventReceiverTableTag &&
					(childIsTablePart ||
						(child == tagBalancingHTMLStreamEventReceiverOptionTag &&
							!b.hasOutputlessTemplateBelow(containerIndexOnStack)))) &&
				b.impliedPathEndsInContainer(outputContainer, child) {
				return outputContainer
			}
		}
	}
	if containerIndexOnStack >= 0 {
		return b.openElements[containerIndexOnStack]
	}
	return tagBalancingHTMLStreamEventReceiverBodyTag
}

// outputContainerIndex is the index of the element the output is currently
// inside, as the policy reports it, or the unrecognized tag's index when
// there is no policy to ask, nothing is open in the output, or its name has
// no index.
func (b *TagBalancingHTMLStreamEventReceiver) outputContainerIndex() int {
	if b.openTagOutputPolicy == nil {
		return tagBalancingHTMLStreamEventReceiverUnrecognizedTag
	}
	name, ok := b.openTagOutputPolicy.outputContainerElementName()
	if !ok {
		return tagBalancingHTMLStreamEventReceiverUnrecognizedTag
	}
	return tagBalancingHTMLStreamEventReceiverMetadata.IndexForName(htmlLexerCanonicalElementName(name))
}

// outputContainerIndexOrBody is outputContainerIndex, or the body when that
// names no known element.
func (b *TagBalancingHTMLStreamEventReceiver) outputContainerIndexOrBody() int {
	if outputContainer := b.outputContainerIndex(); outputContainer != tagBalancingHTMLStreamEventReceiverUnrecognizedTag {
		return outputContainer
	}
	return tagBalancingHTMLStreamEventReceiverBodyTag
}

// impliedPathEndsInContainer is whether a generated wrapper path can
// actually contain the child.
func (b *TagBalancingHTMLStreamEventReceiver) impliedPathEndsInContainer(container, child int) bool {
	implied := tagBalancingHTMLStreamEventReceiverMetadata.impliedElements(container, child)
	innermost := container
	if len(implied) != 0 {
		innermost = implied[len(implied)-1]
	}
	return tagBalancingHTMLStreamEventReceiverMetadata.CanContain(innermost, child)
}

// isDroppedTemplate is whether the entry is a template the policy dropped.
func (b *TagBalancingHTMLStreamEventReceiver) isDroppedTemplate(stackIndex int) bool {
	return stackIndex >= 0 &&
		stackIndex < len(b.openElements) &&
		b.openElements[stackIndex] == tagBalancingHTMLStreamEventReceiverTemplateTag &&
		b.outputElements[stackIndex] == tagBalancingHTMLStreamEventReceiverNoOutputElement &&
		b.sentToUnderlying.get(stackIndex)
}

// hasOutputlessTemplateBelow is whether a dropped logical template contains
// the stack entry.
func (b *TagBalancingHTMLStreamEventReceiver) hasOutputlessTemplateBelow(stackIndex int) bool {
	for i := stackIndex - 1; i >= 0; i-- {
		if b.openElements[i] == tagBalancingHTMLStreamEventReceiverTemplateTag {
			return b.outputElements[i] == tagBalancingHTMLStreamEventReceiverNoOutputElement
		}
	}
	return false
}

// pushOutTable closes in the output, innermost first, the row, row group and
// table that the top of the stack is in, and marks them pushed out, keeping
// them here.  Entries already pushed out, by earlier content beside the same
// table, are left as they are.
func (b *TagBalancingHTMLStreamEventReceiver) pushOutTable(topIndex int) {
	reachesTable := false
	for i := topIndex; i >= 0 && tagBalancingHTMLStreamEventReceiverTableContext[b.openElements[i]]; i-- {
		if b.openElements[i] == tagBalancingHTMLStreamEventReceiverTableTag {
			reachesTable = true
			break
		}
	}
	if !reachesTable {
		b.closeStackFrom(topIndex, b.openElements[topIndex], true)
		return
	}
	policyPushedOutTableAroundRetiredForm := false
	if formPolicy := b.formPointerPolicy; formPolicy != nil && formPolicy.hasRetiredFormTextContext() {
		// Unrecognized descendants are forwarded without a balancer stack
		// entry.  End them first so the retired form is again the top
		// logical policy entry; this is the same close they would receive
		// below before the table itself is closed.
		b.closePassthroughsInside(topIndex, true)
		policyPushedOutTableAroundRetiredForm = formPolicy.pushOutTableAroundRetiredForm()
	}
	for i := topIndex; i >= 0; i-- {
		elIndex := b.openElements[i]
		if !tagBalancingHTMLStreamEventReceiverTableContext[elIndex] {
			break
		}
		if !b.pushedOut.get(i) {
			leaveMappedTemplateOpen := elIndex == tagBalancingHTMLStreamEventReceiverTableTag &&
				b.sentToUnderlying.get(i) &&
				b.outputElements[i] == tagBalancingHTMLStreamEventReceiverTemplateTag &&
				!b.outputElementsInForeignContent.get(i) &&
				b.hasOutputlessTemplateBelow(i)
			if b.sentToUnderlying.get(i) && !leaveMappedTemplateOpen &&
				!policyPushedOutTableAroundRetiredForm {
				b.closePassthroughsInside(i, true)
				b.underlying.CloseTag(tagBalancingHTMLStreamEventReceiverMetadata.CanonNameForIndex(elIndex))
			}
			b.pushedOut.set(i)
			b.pushedMappedTemplateOutputOpen.setTo(i, leaveMappedTemplateOpen)
		}
		if elIndex == tagBalancingHTMLStreamEventReceiverTableTag {
			break
		}
	}
}

// returnToPushedOutTable handles a table part, or a table, arriving while a
// table is pushed out, as a browser does: closes the content that was put in
// front of the nearest pushed-out table, pops the pushed-out entries that
// cannot hold the part, even by implying elements between, which for a
// table is all of them, and writes the rest again as a new table for the
// part to go in.
//
// Not across a boundary of table scope, such as a template in the pushed-out
// content: a browser looks for the table within that scope only, so the
// part is handled where it arrived, as it would be with no table pushed out.
func (b *TagBalancingHTMLStreamEventReceiver) returnToPushedOutTable(elIndex int) {
	metadata := tagBalancingHTMLStreamEventReceiverMetadata
	top := b.pushedOut.length() - 1 // The nearest pushed-out entry.
	pushedTable := top
	for pushedTable >= 0 &&
		b.pushedOut.get(pushedTable) &&
		b.openElements[pushedTable] != tagBalancingHTMLStreamEventReceiverTableTag {
		pushedTable--
	}
	tableWasPushedWithContext := pushedTable >= 0 && pushedTable < top
	tableScope := tagBalancingHTMLStreamEventReceiverScopeForEndTag[tagBalancingHTMLStreamEventReceiverTableTag]
	for i := len(b.openElements) - 1; i > top; i-- {
		if tagBalancingHTMLStreamEventReceiverScopesByElement[b.openElements[i]]&tableScope != 0 {
			return
		}
	}
	for i := len(b.openElements) - 1; i > top; i-- {
		b.closePassthroughsInside(i, true)
		b.forgetListOutputContextsFrom(i)
		resumedFromListItemStart := b.resumedFormattingFromListItemStart.get(i)
		sent := b.sentToUnderlying.get(i)
		unclosed := b.removeStackEntry(i)
		if sent {
			b.underlying.CloseTag(metadata.CanonNameForIndex(unclosed))
		}
		b.clearStackFlags(i)
		if metadata.Resumable(unclosed) {
			b.queueForResumption(unclosed, resumedFromListItemStart)
		}
	}
	for top >= 0 && b.pushedOut.get(top) {
		if b.canHold(elIndex, b.openElements[top], top) {
			break
		}
		b.closePassthroughsInside(top, true)
		if b.isRetiredInputTable(top) || b.pushedMappedTemplateOutputOpen.get(top) {
			b.underlying.CloseTag("table")
		}
		b.detachOutputlessTableWithEmittedParts(top)
		b.forgetListOutputContextsFrom(top)
		b.removeStackEntry(top)
		b.clearStackFlags(top)
		top--
	}
	if top < 0 || !b.pushedOut.get(top) {
		return
	}
	start := top
	for start > 0 && b.pushedOut.get(start-1) {
		start--
	}
	if pushedTable >= 0 &&
		b.outputElements[pushedTable] == tagBalancingHTMLStreamEventReceiverTableTag &&
		!b.outputTableUnavailable.get(pushedTable) &&
		!b.outputElementsInForeignContent.get(pushedTable) {
		// A browser clears its stack back to the table context before it
		// reprocesses the part, so elements forwarded in front of the table
		// are closed before the table reopens.
		b.closePassthroughsInside(start, true)
	} else {
		// No table reopens in the output, so the elements forwarded in front
		// of the logical table stay open below and now precede its reopened
		// entries.
		for i := len(b.passthroughDepths) - 1; i >= 0 && b.passthroughDepths[i] > start; i-- {
			b.passthroughDepths[i] = start
		}
	}
	// Pop the run and push it back, outermost first, opening each again.
	type runEntry struct {
		element                        int
		serial                         int
		inputForeign                   bool
		formPointerTarget              bool
		clearedFormPointerTarget       bool
		staleOutputFormPointerTarget   bool
		impliedInputTable              bool
		outputlessTableWithEmittedPart bool
		mappedTemplateOutputOpen       bool
		suppressedMappedForeignSubtree bool
		outputElement                  int
		outputForeign                  bool
		outputStartsForeign            bool
		formattingFromListItemStart    bool
	}
	n := top - start + 1
	run := make([]runEntry, n)
	for i := n - 1; i >= 0; i-- {
		s := start + i
		run[i] = runEntry{
			inputForeign:                   b.inputElementsInForeignContent.get(s),
			formPointerTarget:              b.formPointerTargets.get(s),
			clearedFormPointerTarget:       b.clearedFormPointerTargets.get(s),
			staleOutputFormPointerTarget:   b.staleOutputFormPointerTargets.get(s),
			impliedInputTable:              b.impliedInputTables.get(s),
			outputlessTableWithEmittedPart: b.outputlessTablesWithEmittedParts.get(s),
			mappedTemplateOutputOpen:       b.pushedMappedTemplateOutputOpen.get(s),
			suppressedMappedForeignSubtree: b.suppressedMappedForeignSubtrees.get(s),
			outputElement:                  b.outputElements[s],
			outputForeign:                  b.outputElementsInForeignContent.get(s),
			outputStartsForeign:            b.outputElementsStartForeignContent.get(s),
			formattingFromListItemStart:    b.resumedFormattingFromListItemStart.get(s),
		}
		if b.isRetiredInputTable(s) {
			b.underlying.CloseTag("table")
		}
		run[i].serial = b.inputElementSerials[s]
		b.forgetListOutputContextsFrom(s)
		run[i].element = b.removeStackEntry(s)
		b.clearStackFlags(s)
	}
	b.foreignRootPendingTableReturn = nil
	policy := b.pushedOutTablePolicy()
	for _, entry := range run {
		mappedTemplateStillOpen := entry.mappedTemplateOutputOpen
		outputElementIndex := tagBalancingHTMLStreamEventReceiverNoOutputElement
		if mappedTemplateStillOpen {
			outputElementIndex = entry.outputElement
		}
		sent := mappedTemplateStillOpen || b.effectiveNestingDepth() < b.nestingLimit
		if sent && !mappedTemplateStillOpen {
			attrs := newAttrList()
			if entry.element == tagBalancingHTMLStreamEventReceiverTableTag && policy != nil {
				policy.openReopenedTable(attrs)
				outputElementIndex = b.outputElementIndexForLastOpenTag(entry.element)
			} else {
				outputElementIndex = b.openElement(entry.element, attrs, false)
			}
		}
		outputElementIsForeign := entry.outputForeign
		outputStartsForeign := entry.outputStartsForeign
		if !mappedTemplateStillOpen {
			outputElementIsForeign = sent && b.lastOutputElementUsedForeignContentRules()
			outputStartsForeign = sent && outputElementIndex != tagBalancingHTMLStreamEventReceiverNoOutputElement &&
				b.lastOutputElementStartsForeignContent(metadata.CanonNameForIndex(entry.element))
		}
		stackIndex := len(b.openElements)
		b.openElements = append(b.openElements, entry.element)
		b.inputElementSerials = append(b.inputElementSerials, entry.serial)
		b.outputElements = append(b.outputElements, outputElementIndex)
		b.resumedFormattingFromListItemStart.setTo(stackIndex, entry.formattingFromListItemStart)
		b.sentToUnderlying.setTo(stackIndex, sent)
		b.inputElementsInForeignContent.setTo(stackIndex, entry.inputForeign)
		b.outputElementsInForeignContent.setTo(stackIndex, outputElementIsForeign)
		b.outputElementsStartForeignContent.setTo(stackIndex, outputStartsForeign)
		b.formPointerTargets.setTo(stackIndex, entry.formPointerTarget)
		b.clearedFormPointerTargets.setTo(stackIndex, entry.clearedFormPointerTarget)
		b.staleOutputFormPointerTargets.setTo(stackIndex, entry.staleOutputFormPointerTarget)
		b.impliedInputTables.setTo(stackIndex, entry.impliedInputTable)
		b.outputlessImpliedSelects.clear(stackIndex)
		b.pushedMappedTemplateOutputOpen.clear(stackIndex)
		b.suppressedMappedForeignSubtrees.setTo(stackIndex, entry.suppressedMappedForeignSubtree)
		if !mappedTemplateStillOpen &&
			policy != nil &&
			entry.element == tagBalancingHTMLStreamEventReceiverTableTag &&
			outputElementIndex != tagBalancingHTMLStreamEventReceiverTableTag &&
			(!entry.impliedInputTable ||
				tableWasPushedWithContext ||
				policy.reopenedTableWasRenamed()) {
			b.outputTableUnavailable.set(stackIndex)
		}
		b.outputlessTablesWithEmittedParts.setTo(stackIndex, entry.outputlessTableWithEmittedPart)
	}
}

// canContain takes into account transparency when figuring out what can be
// contained.  containerIndexOnStack must not be negative.
func (b *TagBalancingHTMLStreamEventReceiver) canContain(child, container, containerIndexOnStack int) bool {
	metadata := tagBalancingHTMLStreamEventReceiverMetadata
	if containerIndexOnStack < 0 {
		panic("negative container index")
	}
	if child == TextNode && tagBalancingHTMLStreamEventReceiverHasSpecialTextMode(container) {
		// If there's a select element on the stack, then we need to be extra
		// careful.
		selectElementIndex := metadata.IndexForName("select")
		for i := containerIndexOnStack - 1; i >= 0; i-- {
			if selectElementIndex == b.openElements[i] {
				return false
			}
		}
	}
	if child == tagBalancingHTMLStreamEventReceiverFormTag &&
		container == tagBalancingHTMLStreamEventReceiverFormTag &&
		(b.hasOpenHTMLOutputTemplate() ||
			(b.clearedFormPointerTargets.get(containerIndexOnStack) &&
				!b.staleOutputFormPointerTargets.get(containerIndexOnStack))) {
		// Template contents do not use the form pointer, and an out-of-scope
		// form end can clear the pointer without removing its old target.  In
		// either case a browser can insert this form inside the earlier one.
		return true
	}
	anc := container
	ancIndexOnStack := containerIndexOnStack
	for {
		if metadata.CanContain(anc, child) {
			return true
		}
		if !tagBalancingHTMLStreamEventReceiverTransparent[anc] {
			return false
		}
		if ancIndexOnStack == 0 {
			return metadata.CanContain(tagBalancingHTMLStreamEventReceiverBodyTag, child)
		}
		ancIndexOnStack--
		anc = b.openElements[ancIndexOnStack]
	}
}

// CloseTag balances an end tag: it closes the matching element in scope,
// and everything open inside it, or ignores a stray end tag.
func (b *TagBalancingHTMLStreamEventReceiver) CloseTag(elementName string) {
	if pending := b.pendingUnrecognizedHTMLTextElement; pending != nil {
		closesPendingTextElement := stringsToLowerCase(*pending) == stringsToLowerCase(elementName)
		b.retirePendingUnrecognizedHTMLTextElement()
		if closesPendingTextElement {
			return
		}
	}
	b.resetMappedForeignTableSuppressionIfPolicyEnded()
	b.resetDroppedSuppressedTableIfPolicyEnded()
	b.syncOutputSelectState()
	canonElementName := htmlLexerCanonicalElementName(elementName)

	elIndex := tagBalancingHTMLStreamEventReceiverMetadata.IndexForName(canonElementName)
	if elIndex == tagBalancingHTMLStreamEventReceiverSelectTag {
		b.retireOutputlessImpliedListBeforeContent()
		if !b.hasOpenTemplateElement() {
			b.htmlInputSelectIsOpen = false
		}
	}
	parsingTemplateContents := elIndex == tagBalancingHTMLStreamEventReceiverFormTag && b.hasOpenTemplateElement()
	formElementPointerWasSet := elIndex == tagBalancingHTMLStreamEventReceiverFormTag &&
		b.foreignContent.formElementPointerIsSet()
	var retiredFormPolicy tagBalancingHTMLStreamEventReceiverFormPointerPolicy
	if elIndex == tagBalancingHTMLStreamEventReceiverFormTag {
		retiredFormPolicy = b.formPointerPolicy
	}
	hasRetiredFormTextContext := retiredFormPolicy != nil && retiredFormPolicy.hasRetiredFormTextContext()
	retiredFormEndIsInScope := !hasRetiredFormTextContext || retiredFormPolicy.retiredFormTextContextAllowsEndTag()
	foreignRootBefore, hasForeignRootBefore := b.foreignContent.outermostForeignElementName()
	_, hasOutputForeignRootBefore := b.outputForeignContentRootName()
	forwardedPart := -1
	if tagBalancingHTMLStreamEventReceiverTableParts[elIndex] {
		forwardedPart = b.indexOfPassthroughNamed(canonElementName)
	}
	switch {
	case !b.pushedOut.isEmpty() &&
		b.foreignContent.isInForeignContent() &&
		!b.foreignContent.hasForeignElementNamed(canonElementName) &&
		!b.hasOpenElementInScope(elIndex):
		// The foreign end-tag algorithm reprocesses this under HTML rules, but
		// the pushed-out table bounds its scope and there is no target before
		// that boundary, so the end tag is ignored.  Keeping the known foreign
		// current node prevents later foreign names from being balanced as
		// HTML or spuriously returning to the table.
		b.foreignContent.ignoreEndTagUnderHTMLRules()
	case forwardedPart >= 0 &&
		b.passthroughSerials[forwardedPart] == 0 &&
		b.foreignContent.isInForeignContent() &&
		!b.foreignContent.hasForeignElementNamed(canonElementName):
		// A table part forwarded as the foreign element its output is, while
		// the input parser ignored its start at an integration point, has no
		// node in the input parser.  Its end tag is a stray table-scoped end
		// tag there, which a browser ignores without leaving the foreign
		// context, so the tracker is told so instead of giving up on the
		// context; giving up put the list item back inside the root for the
		// next foreign sibling (#492).  With a foreign node of that name open
		// further out, the foreign end-tag algorithm walks through the
		// integration point and pops that node instead, so the tracker
		// processes the end tag as usual.
		b.foreignContent.ignoreEndTagUnderHTMLRules()
	default:
		b.foreignContent.processEndTag(canonElementName)
	}
	usesForeignContentRules := b.foreignContent.lastTagUsedForeignContentRules()
	// As for a start tag, judged by the output once the tracker is unknown,
	// unless the form that holds the pointer is still open: this end tag then
	// closes it under the HTML rules its start was judged by, whatever the
	// output namespace is now, and the pointer goes with it.  Judging the end
	// afresh left the pointer set when a form in an integration point closed
	// after the tracker gave up, and every later form was dropped for it.
	formUsesHTMLPointerRules := elIndex == tagBalancingHTMLStreamEventReceiverFormTag &&
		!usesForeignContentRules &&
		!parsingTemplateContents &&
		(!(b.foreignContent.isUnknown() && hasOutputForeignRootBefore) ||
			b.formPointerTargets.previousSetBit(len(b.openElements)-1) >= 0)
	if formUsesHTMLPointerRules && retiredFormEndIsInScope {
		b.foreignContent.clearFormElementPointer()
	}
	if elIndex == tagBalancingHTMLStreamEventReceiverTableTag && b.droppedSuppressedTableDepth != 0 {
		if suppressedTable := b.suppressedMappedForeignTableIndex(); suppressedTable >= 0 &&
			!b.hasOpenTableAbove(suppressedTable) {
			b.droppedSuppressedTableDepth--
			return
		}
	}
	if !b.pushedOut.isEmpty() && hasForeignRootBefore && !usesForeignContentRules {
		if _, ok := b.foreignContent.outermostForeignElementName(); !ok {
			b.foreignRootPendingTableReturn = nil
			if hasOutputForeignRootBefore {
				b.foreignRootPendingTableReturn = &foreignRootBefore
			}
		}
	}
	if b.droppedSuppressedOptionDepth != 0 {
		if tablePolicy := b.pushedOutTablePolicy(); tablePolicy == nil || !tablePolicy.isSuppressingOutputAndContent() {
			b.resetDroppedSuppressedOption()
		} else if elIndex == tagBalancingHTMLStreamEventReceiverOptionTag &&
			!b.hasTrackedOptionAtOrAbove(b.droppedSuppressedOptionStackDepth) {
			b.droppedSuppressedOptionDepth--
			if b.droppedSuppressedOptionDepth == 0 {
				if b.droppedSuppressedOptionOwnsPolicyEntry {
					b.discardStackSuffix(b.droppedSuppressedOptionStackDepth)
					b.popPassthroughsForwardedSince(b.droppedSuppressedOptionPassthroughDepth)
					b.underlying.CloseTag(canonElementName)
				}
				b.resetDroppedSuppressedOption()
			}
			return
		}
	}
	if b.droppedSkippableDepth != 0 && b.contentIsSkippable(canonElementName) {
		b.droppedSkippableDepth--
	}

	if usesForeignContentRules {
		// The end tag matched a foreign node, and a browser pops that node
		// and every node above it.  Close the entries for the popped nodes by
		// identity, innermost first.  Local names are never searched: a node
		// dropped at the nesting limit, or already closed, matches nothing
		// and so cannot reach an older element with the same name.
		b.closeForeignElementsPoppedByLastEndTag()
		return
	}
	if elIndex == tagBalancingHTMLStreamEventReceiverFormTag &&
		formUsesHTMLPointerRules &&
		formElementPointerWasSet &&
		hasRetiredFormTextContext {
		if !retiredFormEndIsInScope {
			return
		}
		if retiredFormPolicy.closeRetiredFormTextContext() {
			// The input form was inserted outside the table this receiver
			// implied, then popped only from the serialized output.  The
			// policy kept its logical text context, and this effective form
			// end removes precisely that entry without disturbing descendants
			// left open by the browser.
			return
		}
	}
	if elIndex == tagBalancingHTMLStreamEventReceiverUnrecognizedTag {
		// Forwarded only for an element the receiver below still has open,
		// after everything opened inside it.  A stray end tag closes nothing.
		if passthrough := b.indexOfPassthroughNamed(canonElementName); passthrough >= 0 {
			b.closePassthroughByName(passthrough)
		}
		return
	}

	// Ensure that index is in the scope of closeable elements.
	// This approximates the "has an element in *** scope" predicates defined
	// at
	// http://www.whatwg.org/specs/web-apps/current-work/multipage/syntax.html
	// #has-an-element-in-the-specific-scope
	blockingScopes := tagBalancingHTMLStreamEventReceiverScopeForEndTag[elIndex]

	index := -1
	pointerTarget := -1
	formEndUsesPointer := formUsesHTMLPointerRules
	switch {
	case formEndUsesPointer && !formElementPointerWasSet:
		// A foreign form can have been popped from the browser's stack by an
		// HTML breakout while its lexical output still needs balancing.  With
		// no HTML form pointer to act on, close that logical entry by name as
		// the foreign end-tag path would have done.
		for i := len(b.openElements) - 1; i >= 0; i-- {
			if b.openElements[i] == tagBalancingHTMLStreamEventReceiverFormTag &&
				b.inputElementsInForeignContent.get(i) {
				index = i
				break
			}
		}
		if index < 0 {
			return
		}
	case formEndUsesPointer:
		pointerTarget = b.formPointerTargets.previousSetBit(len(b.openElements) - 1)
		if pointerTarget >= 0 {
			if foreignForm := b.emittedForeignFormAbove(pointerTarget); foreignForm >= 0 {
				// A later HTML breakout can leave a foreign form lexically open
				// after the browser has popped it.  Its explicit end tag closes
				// that lexical form but, under HTML rules, clears the older form
				// pointer without popping the descendants of the older form.
				// Mirror both effects.
				outputFormOwnsPointer := b.sentToUnderlying.get(pointerTarget) &&
					b.outputElements[pointerTarget] == tagBalancingHTMLStreamEventReceiverFormTag &&
					!b.outputElementsInForeignContent.get(pointerTarget)
				b.formPointerTargets.clear(pointerTarget)
				if outputFormOwnsPointer {
					b.clearedFormPointerTargets.set(pointerTarget)
					b.staleOutputFormPointerTargets.clear(pointerTarget)
				}
				b.closeStackFrom(foreignForm, tagBalancingHTMLStreamEventReceiverFormTag, true)
				return
			}
			inScope := true
			for i := len(b.openElements) - 1; i > pointerTarget; i-- {
				openElement := b.openElements[i]
				if !b.inputElementsInForeignContent.get(i) &&
					!b.isOutputlessSyntheticScopeBoundary(i) &&
					tagBalancingHTMLStreamEventReceiverScopesByElement[openElement]&blockingScopes != 0 {
					inScope = false
					break
				}
			}
			if inScope {
				index = pointerTarget
			}
		}
	case tagBalancingHTMLStreamEventReceiverIsHeaderElementName(canonElementName):
		// Let any of </h1>, </h2>, ... close other header tags.
		for i := len(b.openElements) - 1; i >= 0; i-- {
			openElementIndex := b.openElements[i]
			if tagBalancingHTMLStreamEventReceiverIsHeaderElement(openElementIndex) {
				elIndex = openElementIndex
				index = i
				// The forwarded-part lookup below goes by this name.
				canonElementName = tagBalancingHTMLStreamEventReceiverMetadata.CanonNameForIndex(openElementIndex)
				break
			}
			openElementScope := tagBalancingHTMLStreamEventReceiverScopesByElement[openElementIndex]
			if !b.isOutputlessSyntheticScopeBoundary(i) && openElementScope&blockingScopes != 0 {
				break
			}
		}
	default:
		for i := len(b.openElements) - 1; i >= 0; i-- {
			openElementIndex := b.openElements[i]
			if openElementIndex == elIndex {
				if elIndex == tagBalancingHTMLStreamEventReceiverSelectTag &&
					b.outputlessImpliedSelects.get(i) &&
					b.hasOpenHTMLOutputSelectBelow(i) {
					// This implied select established no scope in the output.
					// Its end tag reaches the physical select below, so close
					// both logical entries together.
					continue
				}
				index = i
				break
			}
			openElementScope := tagBalancingHTMLStreamEventReceiverScopesByElement[openElementIndex]
			if !b.isOutputlessSyntheticScopeBoundary(i) && openElementScope&blockingScopes != 0 {
				break
			}
		}
	}
	// A table part forwarded directly into foreign output is closed by name
	// when the foreign tracker no longer knows it, as after an HTML
	// breakout.  It is the innermost element of this name if it was
	// forwarded after the entry found above.
	if passthrough := b.indexOfPassthroughNamed(canonElementName); passthrough >= 0 &&
		(index < 0 || b.passthroughDepths[passthrough] > index) {
		b.closePassthroughByName(passthrough)
		return
	}
	if index < 0 {
		if formEndUsesPointer && pointerTarget >= 0 {
			b.formPointerTargets.clear(pointerTarget)
			outputFormOwnsPointer := b.sentToUnderlying.get(pointerTarget) &&
				b.outputElements[pointerTarget] == tagBalancingHTMLStreamEventReceiverFormTag &&
				!b.outputElementsInForeignContent.get(pointerTarget)
			if outputFormOwnsPointer {
				b.clearedFormPointerTargets.set(pointerTarget)
				paired := b.hasOpenHTMLOutputTableAbove(pointerTarget) &&
					b.clearFormPointerWithBalancedPair()
				if !paired {
					// Keep the form's extent unchanged unless a later output
					// form actually needs the pointer.  At that point the stale
					// form is closed immediately before the new one is emitted.
					b.staleOutputFormPointerTargets.set(pointerTarget)
				}
			}
		}
		// A formatting element closed with an earlier container and queued
		// to resume is not open, but the end tag is its: a browser drops such
		// an element from its list of active formatting elements, so it is
		// not reconstructed around later content.  Forget it here too.
		if tagBalancingHTMLStreamEventReceiverMetadata.Resumable(elIndex) {
			b.forgetQueuedFormatting(elIndex)
		}
		return // Don't close unopened tags.
	}

	b.closeStackFrom(index, elIndex, true)
}

// hasOpenHTMLOutputSelectBelow is whether an emitted HTML select is open
// below upperBound.
func (b *TagBalancingHTMLStreamEventReceiver) hasOpenHTMLOutputSelectBelow(upperBound int) bool {
	for i := upperBound - 1; i >= 0; i-- {
		if b.sentToUnderlying.get(i) &&
			!b.pushedOut.get(i) &&
			b.outputElements[i] == tagBalancingHTMLStreamEventReceiverSelectTag &&
			!b.outputElementsInForeignContent.get(i) {
			return true
		}
	}
	return false
}

// closeForeignElementsPoppedByLastEndTag closes, innermost first, the
// entries for the foreign nodes that the last end tag popped, found by the
// identity of each node.  A popped node whose entry is gone, or was never
// made because the nesting limit dropped it, matches nothing and is never
// mistaken for an older node of the same local name.  A popped node listed
// in passthroughNames has its end tag forwarded after everything inside it
// is closed; the end tag of a popped node with an entry in openElements is
// sent for that entry as usual.
func (b *TagBalancingHTMLStreamEventReceiver) closeForeignElementsPoppedByLastEndTag() {
	n := len(b.foreignContent.foreignElementsPoppedByLastEndTag())
	for j := 0; j < n; j++ {
		serial := b.foreignContent.foreignElementSerialPoppedByLastEndTag(j)
		if index := b.indexOfInputElementSerial(serial); index >= 0 {
			b.closeStackFrom(index, b.openElements[index], true)
			continue
		}
		if passthrough := b.indexOfPassthroughSerial(serial); passthrough >= 0 {
			b.closePassthrough(passthrough, true)
		}
	}
}

// indexOfInputElementSerial is the entry whose start tag pushed the node
// with this identity, or -1.
func (b *TagBalancingHTMLStreamEventReceiver) indexOfInputElementSerial(serial int) int {
	if serial == 0 {
		return -1
	}
	return slices.Index(b.inputElementSerials, serial)
}

// pushPassthrough records an element forwarded below with no entry in
// openElements.
func (b *TagBalancingHTMLStreamEventReceiver) pushPassthrough(canonElementName string, serial int) {
	index := len(b.passthroughNames)
	b.passthroughIndicesByName[canonElementName] = append(b.passthroughIndicesByName[canonElementName], index)
	b.passthroughNames = append(b.passthroughNames, canonElementName)
	passthroughElement := tagBalancingHTMLStreamEventReceiverMetadata.IndexForName(stringsToLowerCase(canonElementName))
	if tagBalancingHTMLStreamEventReceiverHasSpecialTextMode(passthroughElement) {
		b.passthroughSpecialTextModeDepth++
	}
	b.passthroughDepths = append(b.passthroughDepths, len(b.openElements))
	b.passthroughSerials = append(b.passthroughSerials, serial)
	b.passthroughOutputForeign.setTo(
		index, b.lastOutputElementUsedForeignContentRules() || b.lastOutputElementIsForeignRoot())
	if tagBalancingHTMLStreamEventReceiverIsForeignContentRoot(canonElementName) {
		b.passthroughForeignRoots = append(b.passthroughForeignRoots, index)
	}
}

// lastOutputElementIsForeignRoot is whether the most recently emitted
// element is an SVG or MathML root.
func (b *TagBalancingHTMLStreamEventReceiver) lastOutputElementIsForeignRoot() bool {
	if b.openTagOutputPolicy == nil {
		return false
	}
	outputName, ok := b.openTagOutputPolicy.outputElementNameForLastOpenTag()
	return ok && tagBalancingHTMLStreamEventReceiverIsForeignContentRoot(htmlLexerCanonicalElementName(outputName))
}

// forwardedForeignRootEnteredOutput is whether the output entered the
// input's current foreign region: the innermost forwarded SVG or MathML root
// was emitted as a foreign element.
func (b *TagBalancingHTMLStreamEventReceiver) forwardedForeignRootEnteredOutput() bool {
	return len(b.passthroughForeignRoots) != 0 &&
		b.passthroughOutputForeign.get(b.passthroughForeignRoots[len(b.passthroughForeignRoots)-1])
}

// indexOfPassthroughNamed is the innermost forwarded element with this
// canonical name, or -1.
func (b *TagBalancingHTMLStreamEventReceiver) indexOfPassthroughNamed(canonElementName string) int {
	indices := b.passthroughIndicesByName[canonElementName]
	if len(indices) == 0 {
		return -1
	}
	return indices[len(indices)-1]
}

// indexOfPassthroughSerial is the forwarded element whose start pushed the
// node with this identity, or -1.
func (b *TagBalancingHTMLStreamEventReceiver) indexOfPassthroughSerial(serial int) int {
	if serial == 0 {
		return -1
	}
	for i := len(b.passthroughSerials) - 1; i >= 0; i-- {
		if b.passthroughSerials[i] == serial {
			return i
		}
	}
	return -1
}

// closePassthroughsInside closes, innermost first, the forwarded elements
// opened inside the entry at stackIndex: those forwarded after it was added.
// Called before that entry's own close is sent, or before it is removed
// because the receiver below already closed it, in which case nothing is
// sent.
func (b *TagBalancingHTMLStreamEventReceiver) closePassthroughsInside(stackIndex int, emitCloseTags bool) {
	for len(b.passthroughDepths) != 0 && b.passthroughDepths[len(b.passthroughDepths)-1] > stackIndex {
		b.popPassthrough(emitCloseTags)
	}
}

// popPassthrough closes the innermost forwarded element, sending its end tag
// if asked.
func (b *TagBalancingHTMLStreamEventReceiver) popPassthrough(emitCloseTag bool) {
	last := len(b.passthroughNames) - 1
	canonElementName := b.passthroughNames[last]
	b.passthroughNames = b.passthroughNames[:last]
	passthroughElement := tagBalancingHTMLStreamEventReceiverMetadata.IndexForName(stringsToLowerCase(canonElementName))
	if tagBalancingHTMLStreamEventReceiverHasSpecialTextMode(passthroughElement) {
		b.passthroughSpecialTextModeDepth--
	}
	indices := b.passthroughIndicesByName[canonElementName]
	indices = indices[:len(indices)-1]
	if len(indices) == 0 {
		delete(b.passthroughIndicesByName, canonElementName)
	} else {
		b.passthroughIndicesByName[canonElementName] = indices
	}
	b.passthroughDepths = b.passthroughDepths[:len(b.passthroughDepths)-1]
	b.passthroughSerials = b.passthroughSerials[:len(b.passthroughSerials)-1]
	b.passthroughOutputForeign.clear(last)
	if len(b.passthroughForeignRoots) != 0 && b.passthroughForeignRoots[len(b.passthroughForeignRoots)-1] == last {
		b.passthroughForeignRoots = b.passthroughForeignRoots[:len(b.passthroughForeignRoots)-1]
	}
	if emitCloseTag {
		b.underlying.CloseTag(canonElementName)
	}
	if pending := b.foreignRootPendingTableReturn; pending != nil && *pending == canonElementName {
		b.foreignRootPendingTableReturn = nil
	}
}

// popPassthroughsForwardedSince forgets, without sending anything, the
// forwarded elements recorded after the first count: the receiver below has
// already popped them.
func (b *TagBalancingHTMLStreamEventReceiver) popPassthroughsForwardedSince(count int) {
	for count >= 0 && len(b.passthroughNames) > count {
		b.popPassthrough(false)
	}
}

// closePassthroughByName closes a forwarded element whose end tag the
// foreign tracker did not treat as popping it, either because HTML content
// was open inside an integration point, where a browser ignores the end tag,
// or because the tracker never knew the element.  The receiver below honors
// the end tag, so the tracker follows what was written.
func (b *TagBalancingHTMLStreamEventReceiver) closePassthroughByName(passthrough int) {
	serial := b.passthroughSerials[passthrough]
	b.closePassthrough(passthrough, true)
	b.foreignContent.popNodeWithSerial(serial)
}

// closePassthrough closes the forwarded element at passthrough, after every
// entry and forwarded element opened inside it, innermost first.  The
// entries inside it are closed implicitly, so formatting among them resumes
// around later content as a browser reconstructs it.
func (b *TagBalancingHTMLStreamEventReceiver) closePassthrough(passthrough int, emitCloseTags bool) {
	if depth := b.passthroughDepths[passthrough]; depth < len(b.openElements) {
		b.closeStackEntriesFrom(depth, emitCloseTags)
	}
	for len(b.passthroughNames)-1 > passthrough {
		b.popPassthrough(emitCloseTags)
	}
	b.popPassthrough(emitCloseTags)
}

// closeStackEntriesFrom implicitly closes every entry from fromIndex up,
// innermost first, along with the forwarded elements inside each, as the
// descendants of an explicitly closed element are closed in closeStackFrom.
func (b *TagBalancingHTMLStreamEventReceiver) closeStackEntriesFrom(fromIndex int, emitCloseTags bool) {
	closesTemplate := slices.Contains(b.openElements[fromIndex:], tagBalancingHTMLStreamEventReceiverTemplateTag)
	if closesTemplate {
		// Formatting inside template content must not resume outside it.
		b.toResumeInReverse = b.toResumeInReverse[:0]
		b.resumeOnlyOutsideRawText = b.resumeOnlyOutsideRawText[:0]
	}
	for i := len(b.openElements) - 1; i >= fromIndex; i-- {
		unclosed := b.openElements[i]
		resumedFromListItemStart := b.resumedFormattingFromListItemStart.get(i)
		b.closePassthroughsInside(i, emitCloseTags)
		if emitCloseTags && b.shouldSendClose(i) {
			b.underlying.CloseTag(tagBalancingHTMLStreamEventReceiverMetadata.CanonNameForIndex(unclosed))
		}
		if unclosed == tagBalancingHTMLStreamEventReceiverTemplateTag {
			closesTemplate = false
		} else if !closesTemplate && tagBalancingHTMLStreamEventReceiverMetadata.Resumable(unclosed) {
			b.queueForResumption(unclosed, resumedFromListItemStart)
		}
		b.discardStackSuffix(i)
	}
}

// emittedForeignFormAbove is the nearest emitted foreign form whose lexical
// close clears an older pointer, or -1.
func (b *TagBalancingHTMLStreamEventReceiver) emittedForeignFormAbove(pointerTarget int) int {
	for i := len(b.openElements) - 1; i > pointerTarget; i-- {
		if b.openElements[i] == tagBalancingHTMLStreamEventReceiverFormTag &&
			b.inputElementsInForeignContent.get(i) &&
			b.sentToUnderlying.get(i) &&
			b.outputElements[i] == tagBalancingHTMLStreamEventReceiverFormTag &&
			b.outputElementsInForeignContent.get(i) {
			return i
		}
	}
	return -1
}

// closeStackFrom closes and removes index and every logical descendant,
// emitting closes the policy has not already sent if emitCloseTags.
func (b *TagBalancingHTMLStreamEventReceiver) closeStackFrom(index, closedElement int, emitCloseTags bool) {
	metadata := tagBalancingHTMLStreamEventReceiverMetadata
	freeItemAfterSelect := -1
	for i, n := index, len(b.openElements); i < n; i++ {
		if b.sentToUnderlying.get(i) && !b.pushedOut.get(i) &&
			b.outputElements[i] == tagBalancingHTMLStreamEventReceiverSelectTag &&
			!b.outputElementsInForeignContent.get(i) {
			if candidate := b.freeOutputListItemBelow(i); candidate >= 0 && candidate < index {
				freeItemAfterSelect = candidate
			}
			break
		}
	}
	emittedItemList := -1
	if closedElement == tagBalancingHTMLStreamEventReceiverLiTag && index > 0 &&
		b.openElements[index] == tagBalancingHTMLStreamEventReceiverLiTag &&
		b.sentToUnderlying.get(index) && !b.pushedOut.get(index) &&
		b.outputElements[index] == tagBalancingHTMLStreamEventReceiverLiTag &&
		!b.outputElementsInForeignContent.get(index) {
		parent := index - 1
		parentElement := b.openElements[parent]
		if (parentElement == tagBalancingHTMLStreamEventReceiverUlTag ||
			parentElement == tagBalancingHTMLStreamEventReceiverOlTag) &&
			b.inputElementSerials[parent] == 0 &&
			b.sentToUnderlying.get(parent) && !b.pushedOut.get(parent) &&
			b.outputElements[parent] == tagBalancingHTMLStreamEventReceiverNoOutputElement {
			emittedItemList = parent
		}
	}
	b.forgetListOutputContextsFrom(index)
	if closedElement == tagBalancingHTMLStreamEventReceiverTableTag &&
		b.outputElements[index] == tagBalancingHTMLStreamEventReceiverTableTag &&
		b.sentToUnderlying.get(index) &&
		!b.pushedOut.get(index) &&
		!b.outputElementsInForeignContent.get(index) {
		b.outputlessTablePartsMayBeOpen = false
		b.outputlessTablePartsOpenedAtEvent = -1
	}
	if closedElement == tagBalancingHTMLStreamEventReceiverTableTag &&
		b.outputElements[index] != tagBalancingHTMLStreamEventReceiverTableTag {
		b.detachOutputlessTableWithEmittedParts(index)
		for i, n := index+1, len(b.openElements); i < n; i++ {
			outputElement := b.outputElements[i]
			if b.sentToUnderlying.get(i) &&
				!b.pushedOut.get(i) &&
				outputElement != tagBalancingHTMLStreamEventReceiverNoOutputElement &&
				tagBalancingHTMLStreamEventReceiverTableParts[outputElement] {
				b.markOutputlessTablePartsMayBeOpen()
				break
			}
		}
	}
	if closedElement == tagBalancingHTMLStreamEventReceiverTemplateTag {
		// Formatting inside template content must not resume outside it.
		b.toResumeInReverse = b.toResumeInReverse[:0]
		b.resumeOnlyOutsideRawText = b.resumeOnlyOutsideRawText[:0]
	}
	for last := len(b.openElements) - 1; last > index; last-- {
		unclosed := b.openElements[last]
		resumedFromListItemStart := b.resumedFormattingFromListItemStart.get(last)
		sendClose := emitCloseTags && b.shouldSendClose(last)
		b.closePassthroughsInside(last, emitCloseTags)
		b.removeStackEntry(last)
		if sendClose {
			b.underlying.CloseTag(metadata.CanonNameForIndex(unclosed))
		}
		b.clearStackFlags(last)
		if closedElement != tagBalancingHTMLStreamEventReceiverTemplateTag && metadata.Resumable(unclosed) {
			b.queueForResumption(unclosed, resumedFromListItemStart)
		}
	}
	b.closePassthroughsInside(index, emitCloseTags)
	if emitCloseTags && b.shouldSendClose(index) {
		b.underlying.CloseTag(metadata.CanonNameForIndex(closedElement))
	}
	b.clearStackFlags(index)
	b.removeStackEntry(index)
	if emittedItemList >= 0 {
		b.outputlessImpliedListAfterEmittedItem = emittedItemList
	}
	if freeItemAfterSelect >= 0 {
		b.outputListItemAfterClosedSelect = freeItemAfterSelect
	}
}

// formWillEmitAsHTML is whether the policy will emit this input form as an
// HTML form.  A policy prepares the form start, editing *attrs.
func (b *TagBalancingHTMLStreamEventReceiver) formWillEmitAsHTML(attrs *[]string) bool {
	if b.formPointerPolicy != nil {
		return b.formPointerPolicy.prepareForFormStart(attrs)
	}
	// Without policy feedback, names pass through unchanged.
	return b.openTagOutputPolicy == nil
}

// clearFormPointerWithBalancedPair emits the ignored start and
// pointer-clearing end as a balanced pair.
func (b *TagBalancingHTMLStreamEventReceiver) clearFormPointerWithBalancedPair() bool {
	if b.effectiveNestingDepth() >= b.nestingLimit {
		return false
	}
	if b.formPointerPolicy != nil {
		return b.formPointerPolicy.clearFormPointerWithBalancedPair()
	}
	if b.openTagOutputPolicy != nil {
		return false
	}
	b.underlying.OpenTag("form", newAttrList())
	b.underlying.CloseTag("form")
	return true
}

// retireClearedOutputFormPointer makes a later emitted HTML form stable
// against another sanitization.
func (b *TagBalancingHTMLStreamEventReceiver) retireClearedOutputFormPointer() {
	index := b.clearedFormPointerTargets.previousSetBit(len(b.openElements) - 1)
	if index < 0 {
		return
	}
	if !b.staleOutputFormPointerTargets.get(index) {
		// The serialized reset pair already clears this pointer.  Keep the
		// old form open: a browser can insert the new form inside it, and the
		// marker remains useful after that new form closes.
		return
	}
	if b.hasOpenHTMLOutputTableAbove(index) {
		if !b.clearFormPointerWithBalancedPair() {
			b.closeStackFrom(index, tagBalancingHTMLStreamEventReceiverFormTag, true)
		} else {
			b.staleOutputFormPointerTargets.clear(index)
		}
		return
	}
	b.retireOutputFormKeepingLogicalDescendants(index)
}

// retireOutputFormKeepingLogicalDescendants closes a form and its output
// descendants while retaining their logical input entries.  An input
// template or foreign element still determines how later input end tags
// are interpreted even when the policy dropped it or the output stack had
// to be retired first.
func (b *TagBalancingHTMLStreamEventReceiver) retireOutputFormKeepingLogicalDescendants(formIndex int) {
	metadata := tagBalancingHTMLStreamEventReceiverMetadata
	type descendant struct {
		element                       int
		serial                        int
		output                        int
		inputForeign                  bool
		outputForeign                 bool
		outputStartsForeign           bool
		sent                          bool
		formPointerTarget             bool
		clearedFormPointerTarget      bool
		staleFormPointerTarget        bool
		pushedOut                     bool
		impliedInputTable             bool
		outputlessImpliedSelect       bool
		outputTableUnavailable        bool
		outputlessTableHadEmittedPart bool
		suppressedMappedForeign       bool
		formattingFromListItemStart   bool
	}
	oldSize := len(b.openElements)
	descendants := make([]descendant, oldSize-formIndex-1)
	for i := range descendants {
		s := formIndex + 1 + i
		descendants[i] = descendant{
			element:                       b.openElements[s],
			serial:                        b.inputElementSerials[s],
			output:                        b.outputElements[s],
			inputForeign:                  b.inputElementsInForeignContent.get(s),
			outputForeign:                 b.outputElementsInForeignContent.get(s),
			outputStartsForeign:           b.outputElementsStartForeignContent.get(s),
			sent:                          b.sentToUnderlying.get(s),
			formPointerTarget:             b.formPointerTargets.get(s),
			clearedFormPointerTarget:      b.clearedFormPointerTargets.get(s),
			staleFormPointerTarget:        b.staleOutputFormPointerTargets.get(s),
			pushedOut:                     b.pushedOut.get(s),
			impliedInputTable:             b.impliedInputTables.get(s),
			outputlessImpliedSelect:       b.outputlessImpliedSelects.get(s),
			outputTableUnavailable:        b.outputTableUnavailable.get(s),
			outputlessTableHadEmittedPart: b.outputlessTablesWithEmittedParts.get(s),
			suppressedMappedForeign:       b.suppressedMappedForeignSubtrees.get(s),
			formattingFromListItemStart:   b.resumedFormattingFromListItemStart.get(s),
		}
	}
	// Close the output suffix explicitly.  The library policy would do this
	// itself when it sees </form>, but an arbitrary receiver only sees the
	// events we send it and must receive a balanced close for every open.
	for i := oldSize - 1; i > formIndex; i-- {
		b.closePassthroughsInside(i, true)
		if b.shouldSendClose(i) {
			b.underlying.CloseTag(metadata.CanonNameForIndex(b.openElements[i]))
		}
	}
	b.closePassthroughsInside(formIndex, true)
	if b.sentToUnderlying.get(formIndex) && !b.pushedOut.get(formIndex) {
		b.underlying.CloseTag("form")
	}
	b.forgetListOutputContextsFrom(formIndex)
	for i := oldSize - 1; i >= formIndex; i-- {
		b.removeStackEntry(i)
		b.clearStackFlags(i)
	}
	for i := len(descendants) - 1; i >= 0; i-- {
		if metadata.Resumable(descendants[i].element) {
			b.queueForResumption(descendants[i].element, descendants[i].formattingFromListItemStart)
		}
	}
	for _, d := range descendants {
		if metadata.Resumable(d.element) {
			continue
		}
		stackIndex := len(b.openElements)
		b.openElements = append(b.openElements, d.element)
		b.inputElementSerials = append(b.inputElementSerials, d.serial)
		b.outputElements = append(b.outputElements, d.output)
		b.resumedFormattingFromListItemStart.setTo(stackIndex, d.formattingFromListItemStart)
		b.sentToUnderlying.setTo(stackIndex, d.pushedOut && d.sent)
		b.inputElementsInForeignContent.setTo(stackIndex, d.inputForeign)
		b.outputElementsInForeignContent.setTo(stackIndex, d.outputForeign)
		b.outputElementsStartForeignContent.setTo(stackIndex, d.outputStartsForeign)
		b.formPointerTargets.setTo(stackIndex, d.formPointerTarget)
		b.clearedFormPointerTargets.setTo(stackIndex, d.clearedFormPointerTarget)
		b.staleOutputFormPointerTargets.setTo(stackIndex, d.staleFormPointerTarget)
		b.pushedOut.setTo(stackIndex, d.pushedOut)
		b.impliedInputTables.setTo(stackIndex, d.impliedInputTable)
		b.outputlessImpliedSelects.setTo(stackIndex, d.outputlessImpliedSelect)
		b.outputTableUnavailable.setTo(stackIndex, d.outputTableUnavailable)
		b.outputlessTablesWithEmittedParts.setTo(stackIndex, d.outputlessTableHadEmittedPart)
		b.pushedMappedTemplateOutputOpen.clear(stackIndex)
		b.suppressedMappedForeignSubtrees.setTo(stackIndex, d.suppressedMappedForeign)
	}
}

// hasOpenHTMLOutputTableAbove is whether an emitted HTML table is still
// physically open above the form, with no emitted HTML template changing the
// form-end-tag rules.
func (b *TagBalancingHTMLStreamEventReceiver) hasOpenHTMLOutputTableAbove(formIndex int) bool {
	sawTable := false
	for i, n := formIndex+1, len(b.openElements); i < n; i++ {
		if !b.sentToUnderlying.get(i) ||
			b.pushedOut.get(i) ||
			b.outputElementsInForeignContent.get(i) {
			continue
		}
		switch b.outputElements[i] {
		case tagBalancingHTMLStreamEventReceiverTemplateTag:
			return false
		case tagBalancingHTMLStreamEventReceiverTableTag:
			sawTable = true
		}
	}
	return sawTable
}

// hasOpenHTMLOutputTemplate is whether an emitted HTML template is open on
// the logical output stack.
func (b *TagBalancingHTMLStreamEventReceiver) hasOpenHTMLOutputTemplate() bool {
	for i := len(b.openElements) - 1; i >= 0; i-- {
		if b.sentToUnderlying.get(i) &&
			!b.pushedOut.get(i) &&
			!b.outputElementsInForeignContent.get(i) &&
			b.outputElements[i] == tagBalancingHTMLStreamEventReceiverTemplateTag {
			return true
		}
	}
	return false
}

// hasOpenElementInScope is whether elIndex occurs before its end-tag scope
// is bounded.
func (b *TagBalancingHTMLStreamEventReceiver) hasOpenElementInScope(elIndex int) bool {
	blockingScopes := tagBalancingHTMLStreamEventReceiverScopeForEndTag[elIndex]
	for i := len(b.openElements) - 1; i >= 0; i-- {
		openElementIndex := b.openElements[i]
		if openElementIndex == elIndex {
			return true
		}
		if tagBalancingHTMLStreamEventReceiverScopesByElement[openElementIndex]&blockingScopes != 0 {
			return false
		}
	}
	return false
}

// IsInterElementWhitespace is true if
// text is the value of an inter-element whitespace text node as defined by
// HTML5.
//
// This is the kind of text that is often inserted by HTML authors to nicely
// indent their HTML documents and which (modulo unconventional use of
// white-space:pre) are not apparent to the end-user.
func IsInterElementWhitespace(text string) bool {
	for _, ch := range text {
		if !stringsIsHTMLSpace(ch) {
			return false
		}
	}
	return true
}

// mayHavePhysicalOutputTable is whether downstream can still be in a
// physical table insertion mode.
func (b *TagBalancingHTMLStreamEventReceiver) mayHavePhysicalOutputTable() bool {
	return b.policyOnlyTableMayBeOpen || b.mayHavePhysicalOutputTableOnStack()
}

// outputTableNeedsTextPreparation is whether input balancing missed text
// foster-parenting in the output.
func (b *TagBalancingHTMLStreamEventReceiver) outputTableNeedsTextPreparation(tableContext int) bool {
	// A literal-content element above a table consumes text in its own
	// tokenizer state instead of applying the table insertion mode.
	last := max(tableContext, -1)
	for i := len(b.openElements) - 1; i > last; i-- {
		if !b.sentToUnderlying.get(i) || b.pushedOut.get(i) {
			continue
		}
		outputElement := b.outputElements[i]
		if outputElement == tagBalancingHTMLStreamEventReceiverNoOutputElement {
			continue
		}
		if tagBalancingHTMLStreamEventReceiverHasSpecialTextMode(outputElement) {
			return false
		}
		break
	}
	if tableContext == tagBalancingHTMLStreamEventReceiverPolicyOnlyTableContext {
		return true
	}
	return tableContext >= 0 &&
		tableContext < len(b.openElements) &&
		(b.openElements[tableContext] != b.outputElements[tableContext] ||
			!b.outputSuffixMatchesInput(tableContext))
}

// Text balances a text node: it opens what the text needs around it and
// forwards it unless the content of a dropped element is suppressed.
func (b *TagBalancingHTMLStreamEventReceiver) Text(text string) {
	b.resetMappedForeignTableSuppressionIfPolicyEnded()
	b.resetDroppedSuppressedTableIfPolicyEnded()
	b.syncOutputSelectState()
	isInterElementWhitespace := IsInterElementWhitespace(text)
	tablePolicy := b.pushedOutTablePolicy()
	suppressingPolicySubtree := tablePolicy != nil && tablePolicy.isSuppressingOutputAndContent()
	if isInterElementWhitespace {
		if nOpenElements := len(b.openElements); nOpenElements != 0 {
			top := b.openElements[nOpenElements-1]
			if !tagBalancingHTMLStreamEventReceiverMetadata.CanContainText(top) ||
				// Use this as a proxy for whether or not a manufactured node is
				// needed.  If it is, then skip the inter-element space and don't
				// manufacture a node.
				len(tagBalancingHTMLStreamEventReceiverMetadata.impliedElements(top, tagBalancingHTMLStreamEventReceiverATag)) != 0 {
				return
			}
		}
	} else if !suppressingPolicySubtree {
		b.insertionPointIsInForeignContent = b.textIsInForeignContent()
		b.prepareForNewContent(TextNode, true, false)
		if b.mayHavePhysicalOutputTable() {
			if outputTableContext := b.outputTableContextForStart(); outputTableContext != -1 &&
				b.outputTableNeedsTextPreparation(outputTableContext) {
				b.retireOutputTableForFosteredContent(outputTableContext)
			}
		}
	}

	// The nesting limit bounds how deep the *output* nests; it is not a
	// licence to drop content.  Suppressing the text here meant that markup
	// nested past the limit came out as a well-formed stack of empty elements
	// with the author's text deleted from the middle of it, silently.  Emit
	// the text and let it flatten into the deepest element we did open,
	// which is what a browser's own depth limit does.  Text is escaped
	// downstream, so it cannot become markup.
	//
	// The exception is content the policy would have suppressed had it seen
	// the start tag we dropped: a <script> body must not resurface as visible
	// text just because it sat below the limit.
	stackTopIndex := len(b.openElements) - 1
	if b.droppedSkippableDepth == 0 &&
		(stackTopIndex < 0 || !b.suppressedMappedForeignSubtrees.get(stackTopIndex)) {
		if !isInterElementWhitespace && b.hasOpenHTMLOutputSelect() {
			b.outputSelectHasText = true
		}
		b.underlying.Text(text)
	}
}

// tagBalancingHTMLStreamEventReceiverIsHeaderElement is whether the element
// is one of h1 to h6, or another element named like one.
func tagBalancingHTMLStreamEventReceiverIsHeaderElement(elIndex int) bool {
	canonElementName := tagBalancingHTMLStreamEventReceiverMetadata.CanonNameForIndex(elIndex)
	return tagBalancingHTMLStreamEventReceiverIsHeaderElementName(canonElementName)
}

// tagBalancingHTMLStreamEventReceiverIsHeaderElementName is whether the name
// is two characters, an h in either case and a character no greater than
// '9', as h1 to h6 are.
func tagBalancingHTMLStreamEventReceiverIsHeaderElementName(canonElementName string) bool {
	// Two UTF-16 code units whose second is at most '9' are two bytes.
	return len(canonElementName) == 2 &&
		canonElementName[0]|32 == 'h' &&
		canonElementName[1] <= '9'
}

// tagBalancingHTMLStreamEventReceiverWrittenAsRawTextElement is whether
// content this element holds is read as text in the output too.  The
// renderer writes xmp, listing and plaintext as pre, whose content a browser
// reads as markup, so formatting is reconstructed for them as it is for any
// other element; one of them, xmp, is also the one raw-text start tag whose
// own rule reconstructs it.
func tagBalancingHTMLStreamEventReceiverWrittenAsRawTextElement(elementIndex int) bool {
	name := tagBalancingHTMLStreamEventReceiverMetadata.CanonNameForIndex(elementIndex)
	return tagBalancingHTMLStreamEventReceiverHasSpecialTextMode(elementIndex) &&
		name == htmlStreamRendererSafeName(name)
}

// tagBalancingHTMLStreamEventReceiverHasSpecialTextMode is whether the
// lexer reads the content of the element as text rather than markup.
func tagBalancingHTMLStreamEventReceiverHasSpecialTextMode(elementIndex int) bool {
	name := tagBalancingHTMLStreamEventReceiverMetadata.CanonNameForIndex(elementIndex)
	switch EscapingModeForTag(name) {
	case HTMLTextEscapingModePcdata, HTMLTextEscapingModeVoid:
		return false
	case HTMLTextEscapingModeCdata, HTMLTextEscapingModeCdataSometimes,
		HTMLTextEscapingModeRcdata, HTMLTextEscapingModePlainText:
		return true
	}
	panic(name)
}

// The end-tag scopes, as bits: an element is in the scopes of
// tagBalancingHTMLStreamEventReceiverScopesByElement that it bounds, and an
// end tag searches within those of
// tagBalancingHTMLStreamEventReceiverScopeForEndTag.  See
// w3c.github.io/html/single-page.html#as-that-element-in-the-specific-scope
const (
	tagBalancingHTMLStreamEventReceiverScopeIn        byte = 1
	tagBalancingHTMLStreamEventReceiverScopeButton    byte = 2
	tagBalancingHTMLStreamEventReceiverScopeListItem  byte = 4
	tagBalancingHTMLStreamEventReceiverScopeTable     byte = 8
	tagBalancingHTMLStreamEventReceiverScopeSelect    byte = 16
	tagBalancingHTMLStreamEventReceiverScopeNofeature byte = 32

	tagBalancingHTMLStreamEventReceiverAllScopes = tagBalancingHTMLStreamEventReceiverScopeIn |
		tagBalancingHTMLStreamEventReceiverScopeButton |
		tagBalancingHTMLStreamEventReceiverScopeListItem |
		tagBalancingHTMLStreamEventReceiverScopeTable |
		tagBalancingHTMLStreamEventReceiverScopeSelect |
		tagBalancingHTMLStreamEventReceiverScopeNofeature
)

var (
	// tagBalancingHTMLStreamEventReceiverScopesByElement holds, by element
	// index, the scopes the element bounds.
	tagBalancingHTMLStreamEventReceiverScopesByElement = tagBalancingHTMLStreamEventReceiverNewScopesByElement()
	// tagBalancingHTMLStreamEventReceiverScopeForEndTag holds, by element
	// index, the scopes that bound the search for an end tag's element.
	tagBalancingHTMLStreamEventReceiverScopeForEndTag = tagBalancingHTMLStreamEventReceiverNewScopeForEndTag()
)

func tagBalancingHTMLStreamEventReceiverNewScopesByElement() []byte {
	metadata := tagBalancingHTMLStreamEventReceiverMetadata
	scopes := make([]byte, metadata.NElementTypes())
	inScopeElements := []string{
		"applet",
		"caption",
		"html",
		"table",
		"td",
		"th",
		"marquee",
		"object",
		"template",
	}
	for _, tn := range inScopeElements {
		scopes[metadata.IndexForName(tn)] |= tagBalancingHTMLStreamEventReceiverScopeIn
	}

	listItemScopeExtras := []string{
		"dir",
		"ol",
		"ul",
	}
	for _, tns := range [][]string{listItemScopeExtras, inScopeElements} {
		for _, tn := range tns {
			scopes[metadata.IndexForName(tn)] |= tagBalancingHTMLStreamEventReceiverScopeListItem
		}
	}
	buttonScopeExtras := []string{
		"button",
	}
	for _, tns := range [][]string{buttonScopeExtras, inScopeElements} {
		for _, tn := range tns {
			scopes[metadata.IndexForName(tn)] |= tagBalancingHTMLStreamEventReceiverScopeButton
		}
	}

	tableScopeElements := []string{
		"html",
		"table",
		"template",
	}
	for _, tn := range tableScopeElements {
		scopes[metadata.IndexForName(tn)] |= tagBalancingHTMLStreamEventReceiverScopeTable
	}

	selectScopeExceptions := []string{
		"optgroup",
		"option",
	}
	for i := range scopes {
		scopes[i] |= tagBalancingHTMLStreamEventReceiverScopeSelect
	}
	for _, tn := range selectScopeExceptions {
		scopes[metadata.IndexForName(tn)] &^= tagBalancingHTMLStreamEventReceiverScopeSelect
	}

	// The <nofeature> elements are weird.
	//     <table><noscript></table></noscript>...
	// is equivalent to
	//     <table>...
	// when scripts are enabled and is equivalent to
	//     <table></table>...
	// when not.
	//
	// We scope <noscript> so that, even when we parse and filter the content
	// as if it were tag content, we don't treat that content as escaping
	// which is consistent with the view that that content is ignored by the
	// browser as is usually the case.
	for _, tn := range []string{"noembed", "noframes", "noscript"} {
		scopes[metadata.IndexForName(tn)] = tagBalancingHTMLStreamEventReceiverAllScopes
	}
	return scopes
}

func tagBalancingHTMLStreamEventReceiverNewScopeForEndTag() []byte {
	metadata := tagBalancingHTMLStreamEventReceiverMetadata
	// Derived by looking at
	//     //dev.w3.org/html5/github-html/heartbeat/tokenization.html
	// and scanning for all lines matching one of
	//     "element in scope"
	//     "element in button scope"
	//     "element in list item scope"
	//     "element in select scope"
	//     "element in table scope"
	scopes := make([]byte, metadata.NElementTypes())
	for i := range scopes {
		scopes[i] = tagBalancingHTMLStreamEventReceiverScopeIn
	}
	for _, tn := range []string{
		"caption", "col", "colgroup", "table", "tbody", "tfoot", "thead", "tr", "td", "th",
	} {
		scopes[metadata.IndexForName(tn)] = tagBalancingHTMLStreamEventReceiverScopeTable
	}
	scopes[metadata.IndexForName("select")] = tagBalancingHTMLStreamEventReceiverScopeSelect
	scopes[metadata.IndexForName("p")] = tagBalancingHTMLStreamEventReceiverScopeButton // really.
	scopes[metadata.IndexForName("li")] = tagBalancingHTMLStreamEventReceiverScopeListItem
	// The in-head rule for </template> searches through table structure, but
	// a nofeature element remains a deliberate barrier so text its policy
	// suppresses cannot escape when a template end tag appears inside it.
	scopes[tagBalancingHTMLStreamEventReceiverTemplateTag] = tagBalancingHTMLStreamEventReceiverScopeNofeature
	return scopes
}

// stackFlags is a growable bit set of non-negative indices that holds the
// per-entry flags of a stack: an index past the end reads as clear, and a
// negative index is a programming error.
type stackFlags struct {
	words []uint64
}

func (f *stackFlags) checkIndex(i int) {
	if i < 0 {
		panic(fmt.Sprintf("bitIndex < 0: %d", i))
	}
}

// get reports whether i is in the set.
func (f *stackFlags) get(i int) bool {
	f.checkIndex(i)
	w := i >> 6
	return w < len(f.words) && f.words[w]&(1<<uint(i&63)) != 0
}

// set adds i to the set.
func (f *stackFlags) set(i int) {
	f.checkIndex(i)
	w := i >> 6
	for len(f.words) <= w {
		f.words = append(f.words, 0)
	}
	f.words[w] |= 1 << uint(i&63)
}

// setTo adds i to the set if v, and removes it otherwise.
func (f *stackFlags) setTo(i int, v bool) {
	if v {
		f.set(i)
	} else {
		f.clear(i)
	}
}

// clear removes i from the set.
func (f *stackFlags) clear(i int) {
	f.checkIndex(i)
	if w := i >> 6; w < len(f.words) {
		f.words[w] &^= 1 << uint(i&63)
	}
}

// clearRange removes the indices from from, inclusive, to to, exclusive.
func (f *stackFlags) clearRange(from, to int) {
	for i := from; i < to; i++ {
		f.clear(i)
	}
}

// clearAll empties the set.
func (f *stackFlags) clearAll() {
	clear(f.words)
}

// isEmpty reports whether the set is empty.
func (f *stackFlags) isEmpty() bool {
	for _, w := range f.words {
		if w != 0 {
			return false
		}
	}
	return true
}

// length is one more than the greatest index in the set, or zero for an
// empty set.
func (f *stackFlags) length() int {
	for w := len(f.words) - 1; w >= 0; w-- {
		if f.words[w] != 0 {
			return w<<6 + 64 - bits.LeadingZeros64(f.words[w])
		}
	}
	return 0
}

// nextSetBit is the least index in the set at or above from, or -1.
func (f *stackFlags) nextSetBit(from int) int {
	if from < 0 {
		panic(fmt.Sprintf("fromIndex < 0: %d", from))
	}
	for w := from >> 6; w < len(f.words); w++ {
		word := f.words[w]
		if w == from>>6 {
			word &= ^uint64(0) << uint(from&63)
		}
		if word != 0 {
			return w<<6 + bits.TrailingZeros64(word)
		}
	}
	return -1
}

// previousSetBit is the greatest index in the set at or below from, or -1.
// A from of -1 finds nothing.
func (f *stackFlags) previousSetBit(from int) int {
	if from < 0 {
		if from != -1 {
			panic(fmt.Sprintf("fromIndex < -1: %d", from))
		}
		return -1
	}
	for i := from; i >= 0; i-- {
		if f.get(i) {
			return i
		}
	}
	return -1
}
