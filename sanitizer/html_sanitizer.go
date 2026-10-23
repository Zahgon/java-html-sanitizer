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

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/HtmlSanitizer.java.

package sanitizer

import "slices"

// HTMLSanitizerPolicy receives events based on the HTML stream, and applies a
// policy to decide what HTML constructs to allow.
// Typically, implementations use an HTMLStreamRenderer to produce the
// sanitized output.
//
// Implementations of this interface are in the TCB.
//
// OpenTag is called when an HTML tag like <foo bar=baz> is seen in the input.
// Its element name is normalized (lower-case for non-namespaced names), and
// its attributes are a list of alternating attribute name and value pairs.
// The values are raw -- HTML entities have been decoded.  The policy may edit
// the list's elements during the call, but ownership reverts to the caller on
// return.
//
// CloseTag is called when an HTML tag like </foo> is seen in the input, and
// right after OpenTag for a self-closing tag like <path/> where browsers honor
// the self-closing flag: on <svg/> and <math/>, and on most tags inside them.
//
// Text is called when textual content is seen.  The chunk is raw content --
// HTML entities have been decoded.
type HTMLSanitizerPolicy interface {
	HTMLStreamEventReceiver
}

// Sanitize sanitizes the given HTML by applying the given policy
// to it.
//
// This function is not in the TCB.
//
// It has no return value since policies are assumed to render things they
// accept and do nothing on things they reject.  Use HTMLStreamRenderer to
// render content to an output buffer.
//
// html is a snippet of HTML to sanitize.  policy receives events based on
// the tokens in html; typically it ends up routing the events to an
// HTMLStreamRenderer after filtering, and HTMLPolicyBuilder provides an easy
// way to create one.  preprocessor may wrap the policy to reinterpret parse
// events; since the policy encapsulates its output buffer, it is not in the
// policy's TCB.  A nil preprocessor is the identity.
func Sanitize(
	html string, policy HTMLSanitizerPolicy,
	preprocessor HTMLStreamEventProcessor) {
	if preprocessor == nil {
		preprocessor = IdentityProcessor
	}
	receiver := htmlSanitizerInitializePolicy(policy, preprocessor)

	receiver.OpenDocument()

	lexer := newHTMLLexer(html)
	// One list is reused for every start tag, as policies may edit it in place
	// during the call that receives it.
	attrs := make([]string, 0, 16)
	foreignContent := newHTMLSanitizerForeignContentContext()
	for lexer.hasNext() {
		token := lexer.next()
		switch token.typ {
		case htmlTokenTypeText:
			receiver.Text(DecodeHTML(html[token.start:token.end], false))
		case htmlTokenTypeUnescaped:
			receiver.Text(encodingStripBannedCodeunits(html[token.start:token.end]))
		case htmlTokenTypeTagbegin:
			if html[token.start+1] == '/' { // A close tag.
				elementName := htmlLexerCanonicalElementName(
					html[token.start+2 : token.end])
				ended := false
				for lexer.hasNext() {
					// skip tokens until we see a ">"
					if lexer.next().typ == htmlTokenTypeTagend {
						ended = true
						break
					}
				}
				if !ended {
					// The input ended inside the tag.  A browser drops the tag
					// whole, so there is nothing to close.
					break
				}
				receiver.CloseTag(elementName)
				foreignContent.processEndTag(elementName)
			} else {
				attrs = attrs[:0]

				attrsReadyForName := true
				selfClosing := false
				ended := false
			tagBody:
				for lexer.hasNext() {
					tagBodyToken := lexer.next()
					switch tagBodyToken.typ {
					case htmlTokenTypeAttrname:
						if !attrsReadyForName {
							// Last attribute added was valueless.
							attrs = append(attrs, attrs[len(attrs)-1])
						} else {
							attrsReadyForName = false
						}
						attrs = append(attrs, htmlLexerCanonicalAttributeName(
							html[tagBodyToken.start:tagBodyToken.end]))
					case htmlTokenTypeAttrvalue:
						attributeContentRaw := htmlSanitizerStripQuotes(
							html[tagBodyToken.start:tagBodyToken.end])
						attrs = append(attrs, DecodeHTML(attributeContentRaw, true))
						attrsReadyForName = true
					case htmlTokenTypeTagend:
						// HtmlInputSplitter only combines the solidus with the
						// greater-than sign when the tokenizer is in a state where
						// the solidus sets the self-closing flag.
						selfClosing = html[tagBodyToken.start] == '/'
						ended = true
						break tagBody
					default:
						// Just drop anything not recognized
					}
				}
				if !ended {
					// The input ended inside the tag.  A browser drops the tag
					// whole, attributes and all; the text before it stands.
					break
				}
				if !attrsReadyForName {
					attrs = append(attrs, attrs[len(attrs)-1])
				}
				elementName := htmlLexerCanonicalElementName(
					html[token.start+1 : token.end])
				// Decided before the policy sees the attributes, since it may
				// edit them.
				closesItself := foreignContent.processStartTag(
					elementName, attrs, selfClosing)
				if closesItself &&
					IsTagFollowedByLiteralContent(elementName) {
					// The splitter tentatively chose an HTML raw-text or RCDATA
					// mode from the name alone.  Foreign elements stay in the data
					// state, and this one has already closed.
					lexer.cancelPendingLiteralContent()
				}
				receiver.OpenTag(elementName, attrs)
				if closesItself {
					receiver.CloseTag(elementName)
				}
			}
		default:
			// Ignore comments, XML prologues, processing instructions, and other
			// stuff that shouldn't show up in the output.
		}
	}

	receiver.CloseDocument()
}

// htmlSanitizerForeignContentContextMaxDepth matches the sanitizer's output
// nesting limit without growing unchecked.
const htmlSanitizerForeignContentContextMaxDepth = 256

// htmlSanitizerForeignContentContextMaxUntrackedTables bounds the memory spent
// on untracked tables that never close.
const htmlSanitizerForeignContentContextMaxUntrackedTables = 32

// htmlSanitizerForeignContentContext tracks the tree-construction context
// needed for self-closing flags.  The zero value is ready to use and is the
// context at the start of a document.
type htmlSanitizerForeignContentContext struct {
	// openElements holds the elements from the first open foreign root
	// through the current node.
	openElements []*htmlSanitizerOpenElement

	// formPointerSet records whether the known HTML context has a non-null
	// form element pointer.  The form pointer is not bounded by an
	// integration point.
	formPointerSet bool

	// trackedFormElement is the form pointer's target, when that element is
	// in the tracked region.
	trackedFormElement *htmlSanitizerOpenElement

	// simpleTable is a table inserted in known in-body mode, before any child
	// tag.
	simpleTable *htmlSanitizerOpenElement

	// simpleTableReturnMode is the mode to restore when simpleTable closes.
	simpleTableReturnMode htmlSanitizerHTMLInsertionMode

	// htmlInsertionMode is the HTML mode that remains in force while foreign
	// rules run.
	htmlInsertionMode htmlSanitizerHTMLInsertionMode

	// untrackedTables are the tables open below the tracked region, innermost
	// last.  Each is in table scope, since a template makes the context
	// unknown.
	untrackedTables []*htmlSanitizerUntrackedTable

	// unknown becomes true once the browser's context can no longer be derived
	// from the tracked elements: the bounded stack was exhausted, or a tag's
	// effect depended on untracked ancestors or on the insertion mode.  The
	// legacy HTML behavior is the conservative fallback for ordinary tags from
	// that point onward.
	unknown bool

	// usedForeignContentRules records whether the most recently processed tag
	// used foreign-content rules.
	usedForeignContentRules bool

	// lastForeignStartTagPushedElement records whether the most recent foreign
	// start pushed a tracked element.
	lastForeignStartTagPushedElement bool

	// pushedSerial is the opaque identity of the node pushed by the most
	// recent start, or zero.
	pushedSerial int32

	// nextElementSerial is the next opaque identity assigned to a tracked
	// tree-construction node.  Zero, which no node gets, stands for one.
	nextElementSerial int32

	// poppedForeignNames are the foreign element names popped by the most
	// recent end tag, inner first.
	poppedForeignNames []string

	// poppedForeignSerials are the identities parallel to poppedForeignNames.
	poppedForeignSerials []int32
}

// newHTMLSanitizerForeignContentContext returns the context at the start of a
// document.
func newHTMLSanitizerForeignContentContext() *htmlSanitizerForeignContentContext {
	return &htmlSanitizerForeignContentContext{}
}

// formElementPointerIsSet reports whether the known HTML context has a
// non-null form element pointer.
func (c *htmlSanitizerForeignContentContext) formElementPointerIsSet() bool {
	return c.formPointerSet
}

// isUnknown is true once the browser's context can no longer be derived from
// the tracked elements, after which tags are judged under the legacy HTML
// rules whatever namespace the browser is really in.
func (c *htmlSanitizerForeignContentContext) isUnknown() bool {
	return c.unknown
}

// markFormElementPointerSet records a form pointer whose target may be outside
// the tracked region.
func (c *htmlSanitizerForeignContentContext) markFormElementPointerSet() {
	c.formPointerSet = true
}

// clearFormElementPointer clears the form pointer and any target that is
// still tracked.
func (c *htmlSanitizerForeignContentContext) clearFormElementPointer() {
	c.formPointerSet = false
	c.trackedFormElement = nil
}

// lastTagUsedForeignContentRules is true when the most recent start or end tag
// was processed in SVG or MathML rather than under the HTML tree-building
// rules.
func (c *htmlSanitizerForeignContentContext) lastTagUsedForeignContentRules() bool {
	return c.usedForeignContentRules
}

// lastStartTagOpenedIntegrationPoint reports whether the most recent foreign
// start established an integration point.
func (c *htmlSanitizerForeignContentContext) lastStartTagOpenedIntegrationPoint() bool {
	if !c.usedForeignContentRules || !c.lastForeignStartTagPushedElement {
		return false
	}
	current := c.currentElement()
	return current != nil &&
		(current.mathTextIntegrationPoint || current.htmlIntegrationPoint)
}

// lastStartTagPushedSerial is the opaque identity of the tree-construction
// node pushed by the most recent start tag, in any namespace, or zero if that
// tag pushed nothing that is still tracked.  The balancer stores it with the
// logical entry it stacks for the same tag so a later foreign end tag can find
// that exact entry.
func (c *htmlSanitizerForeignContentContext) lastStartTagPushedSerial() int {
	return int(c.pushedSerial)
}

// popNodeWithSerial pops the node with this identity and every node above it.
// The balancer calls this after it has sent an end tag for a forwarded element
// that these rules ignored, so that this context keeps describing the output
// actually written rather than the tree a browser builds from the input,
// which the output no longer reproduces there.
func (c *htmlSanitizerForeignContentContext) popNodeWithSerial(serial int) {
	if c.unknown || serial == 0 {
		return
	}
	for i := len(c.openElements) - 1; i >= 0; i-- {
		if int(c.openElements[i].serial) != serial {
			continue
		}
		for _, popped := range c.openElements[i:] {
			if popped == c.trackedFormElement {
				c.trackedFormElement = nil
			}
			if popped == c.simpleTable {
				c.simpleTable = nil
				c.htmlInsertionMode = c.simpleTableReturnMode
			}
		}
		c.truncate(i)
		return
	}
}

// isNodeOpen reports whether the node with this identity is still on the
// tracked stack.  False once a breakout or an end tag has popped it, and when
// the context is unknown.
func (c *htmlSanitizerForeignContentContext) isNodeOpen(serial int) bool {
	if c.unknown || serial == 0 {
		return false
	}
	for i := len(c.openElements) - 1; i >= 0; i-- {
		if int(c.openElements[i].serial) == serial {
			return true
		}
	}
	return false
}

// foreignElementsPoppedByLastEndTag returns the foreign element names popped
// by the most recent end tag, inner first, ending with the end tag's own
// target.  Empty unless lastTagUsedForeignContentRules is true.  The caller
// must not modify the result.
func (c *htmlSanitizerForeignContentContext) foreignElementsPoppedByLastEndTag() []string {
	return c.poppedForeignNames
}

// foreignElementSerialPoppedByLastEndTag returns the opaque identity of the
// foreign element popped at index.
func (c *htmlSanitizerForeignContentContext) foreignElementSerialPoppedByLastEndTag(index int) int {
	return int(c.poppedForeignSerials[index])
}

// isInForeignContent reports whether a known current node is in SVG or MathML.
func (c *htmlSanitizerForeignContentContext) isInForeignContent() bool {
	current := c.currentElement()
	return !c.unknown && current != nil &&
		current.namespace != htmlSanitizerNamespaceHTML
}

// startTagUsesForeignContentRules reports whether this start tag would use
// foreign-content tree-building rules.
func (c *htmlSanitizerForeignContentContext) startTagUsesForeignContentRules(
	elementName string, attrs []string) bool {
	if c.unknown {
		return false
	}
	current := c.currentElement()
	return !htmlSanitizerUsesHTMLRulesForStartTag(current, elementName) &&
		!htmlSanitizerBreaksOutOfForeignContent(elementName, attrs)
}

// foreignElementsPoppedByStartTag returns the number of foreign elements an
// HTML breakout start would pop.
func (c *htmlSanitizerForeignContentContext) foreignElementsPoppedByStartTag(
	elementName string, attrs []string) int {
	if c.unknown {
		return 0
	}
	current := c.currentElement()
	if htmlSanitizerUsesHTMLRulesForStartTag(current, elementName) ||
		!htmlSanitizerBreaksOutOfForeignContent(elementName, attrs) {
		return 0
	}
	count := 0
	for i := len(c.openElements) - 1; i >= 0; i-- {
		open := c.openElements[i]
		if open.namespace == htmlSanitizerNamespaceHTML ||
			open.mathTextIntegrationPoint || open.htmlIntegrationPoint {
			break
		}
		count++
	}
	return count
}

// outermostForeignElementName returns the outermost SVG or MathML element in
// the tracked foreign region, and false if there is none.
func (c *htmlSanitizerForeignContentContext) outermostForeignElementName() (string, bool) {
	if c.unknown {
		return "", false
	}
	for _, open := range c.openElements {
		if open.namespace != htmlSanitizerNamespaceHTML {
			return open.elementName, true
		}
	}
	return "", false
}

// hasForeignElementNamed reports whether the foreign end-tag walk would find
// this local name.
func (c *htmlSanitizerForeignContentContext) hasForeignElementNamed(elementName string) bool {
	if !c.isInForeignContent() {
		return false
	}
	for i := len(c.openElements) - 1; i >= 0; i-- {
		open := c.openElements[i]
		if open.namespace == htmlSanitizerNamespaceHTML {
			return false
		}
		if htmlSanitizerAsciiEqualsIgnoreCase(open.elementName, elementName) {
			return true
		}
	}
	return false
}

// ignoreEndTagUnderHTMLRules records an HTML end tag known to be ignored
// without changing context.
func (c *htmlSanitizerForeignContentContext) ignoreEndTagUnderHTMLRules() {
	c.usedForeignContentRules = false
	c.clearPopped()
}

// processStartTag updates the context for a start tag and returns whether its
// self-closing flag is honored by tree construction.
func (c *htmlSanitizerForeignContentContext) processStartTag(
	elementName string, attrs []string, selfClosing bool) bool {
	c.usedForeignContentRules = false
	c.lastForeignStartTagPushedElement = false
	c.pushedSerial = 0
	c.clearPopped()
	if c.unknown {
		return selfClosing && htmlSanitizerIsForeignContentRoot(elementName)
	}

	current := c.currentElement()
	usesHTMLRules := htmlSanitizerUsesHTMLRulesForStartTag(current, elementName)
	if !usesHTMLRules &&
		htmlSanitizerBreaksOutOfForeignContent(elementName, attrs) {
		c.popToHTMLOrIntegrationPoint()
		usesHTMLRules = true
	}

	if usesHTMLRules {
		return c.processHTMLStartTag(elementName, attrs, selfClosing)
	}

	// Any other start tag in foreign content inherits the current
	// namespace, even one named "svg" or "math".
	c.usedForeignContentRules = true
	if !selfClosing {
		opened := newHTMLSanitizerOpenElement(elementName, current.namespace, attrs)
		c.push(opened)
		c.lastForeignStartTagPushedElement = !c.unknown &&
			c.currentElement() == opened
	}
	return selfClosing
}

// processEndTag updates the context using the foreign-content or HTML end-tag
// rules.
func (c *htmlSanitizerForeignContentContext) processEndTag(elementName string) {
	c.usedForeignContentRules = false
	c.clearPopped()
	if c.unknown {
		return
	}
	if len(c.openElements) == 0 {
		if elementName == "form" {
			c.formPointerSet = false
			c.trackedFormElement = nil
		}
		c.trackUntrackedHTMLEndTag(elementName)
		return
	}

	if c.currentElement().namespace == htmlSanitizerNamespaceHTML {
		c.processEndTagUnderHTMLRules(elementName)
		return
	}

	if elementName == "br" || elementName == "p" {
		c.popToHTMLOrIntegrationPoint()
		c.processEndTagUnderHTMLRules(elementName)
		return
	}

	// The foreign-content end-tag algorithm walks down from the current
	// node.  A foreign node with the tag name closes, along with every
	// node above it.  At the first HTML node the browser reprocesses the
	// token under the rules of its current HTML insertion mode instead.
	for i := len(c.openElements) - 1; i >= 0; i-- {
		open := c.openElements[i]
		if open.namespace == htmlSanitizerNamespaceHTML {
			break
		}
		if htmlSanitizerAsciiEqualsIgnoreCase(open.elementName, elementName) {
			c.usedForeignContentRules = true
			for j := len(c.openElements) - 1; j >= i; j-- {
				popped := c.openElements[j]
				c.poppedForeignNames = append(c.poppedForeignNames, popped.elementName)
				c.poppedForeignSerials = append(c.poppedForeignSerials, popped.serial)
			}
			c.truncate(i)
			return
		}
	}
	c.processEndTagUnderHTMLRules(elementName)
}

// processEndTagUnderHTMLRules applies an end tag that a browser processes
// under the rules of its current HTML insertion mode.  Only outcomes that
// follow from the tracked elements alone are modeled.  Anything that depends
// on the untracked ancestors of the foreign root, on the insertion mode, or on
// the list of active formatting elements makes the context unknown, which
// fails closed: self-closing flags are no longer honored.
func (c *htmlSanitizerForeignContentContext) processEndTagUnderHTMLRules(elementName string) {
	if c.simpleTable != nil {
		if elementName == "table" && c.currentElement() == c.simpleTable {
			c.truncate(len(c.openElements) - 1)
			c.simpleTable = nil
			c.htmlInsertionMode = c.simpleTableReturnMode
		} else {
			c.becomeUnknown()
		}
		return
	}
	if htmlSanitizerTableScopedElementNames.contains(elementName) ||
		elementName == "template" {
		// Table scope is bounded only by html, table and template, so these
		// end tags reach past integration points to untracked ancestors,
		// and what they close depends on the insertion mode.
		c.becomeUnknown()
		return
	}
	if htmlSanitizerIgnoredHTMLEndTagNames.contains(elementName) {
		return
	}
	if elementName == "form" {
		form := c.trackedFormElement
		c.formPointerSet = false
		c.trackedFormElement = nil
		if form != nil {
			formIndex := slices.Index(c.openElements, form)
			if formIndex >= 0 && c.isInDefaultScope(formIndex) {
				// Outside template contents, </form> removes the form without
				// popping the elements above it.
				c.generateImpliedEndTags("")
				c.openElements = slices.Delete(c.openElements, formIndex, formIndex+1)
			}
		}
		return
	}
	anyOther := !htmlSanitizerSpecificEndTagRuleNames.contains(elementName)
	formatting := htmlSanitizerFormattingElementNames.contains(elementName)
	heading := htmlSanitizerIsHeadingName(elementName)
	for i := len(c.openElements) - 1; i >= 0; i-- {
		open := c.openElements[i]
		if open.namespace != htmlSanitizerNamespaceHTML {
			// Integration points and annotation-xml are in the special
			// category and bound every scope.  Other foreign elements are
			// transparent to both kinds of search.
			if open.special {
				return
			}
			continue
		}
		openName := open.elementName
		if htmlSanitizerAsciiEqualsIgnoreCase(openName, elementName) ||
			(heading && htmlSanitizerIsHeadingName(openName)) {
			var oneFormattingEntryRemoved *htmlSanitizerOpenElement
			if formatting {
				oneFormattingEntryRemoved = open
			}
			c.popTrackedElementsFrom(
				i,
				htmlSanitizerActiveFormattingMarkerElementNames.contains(elementName),
				oneFormattingEntryRemoved)
			return
		}
		if anyOther {
			// "Any other end tag" stops at any element in the special
			// category.
			if htmlSanitizerAmbiguouslySpecialHTMLElementNamesSet.contains(openName) {
				c.becomeUnknown()
				return
			}
			if htmlSanitizerSpecialHTMLElementNamesSet.contains(openName) {
				return
			}
			continue
		}
		if htmlSanitizerDefaultScopeBoundaryNames.contains(openName) ||
			(elementName == "li" && (openName == "ol" || openName == "ul")) ||
			(elementName == "p" && openName == "button") {
			// Not in scope: the token is ignored, or for </p> an empty p is
			// inserted and closed at once.
			return
		}
		if formatting && htmlSanitizerSpecialHTMLElementNamesSet.contains(openName) {
			// The adoption agency algorithm restructures the stack around
			// this "furthest block", dropping the foreign nodes above it.
			c.becomeUnknown()
			return
		}
	}
	if len(c.openElements) == 0 {
		return
	}
	// Nothing tracked bounded the search, so whether the token closes the
	// whole foreign region depends on the untracked HTML ancestors.
	c.becomeUnknown()
}

// processHTMLStartTag applies a start tag that a browser processes under the
// HTML tree-building rules, and returns whether its self-closing flag is
// honored.
func (c *htmlSanitizerForeignContentContext) processHTMLStartTag(
	elementName string, attrs []string, selfClosing bool) bool {
	if c.simpleTable != nil {
		// A child start tag is where the in-table modes start implying or
		// foster-parenting elements.  Keep the empty-table case exact and
		// fail closed for the rest.
		c.becomeUnknown()
		return selfClosing && htmlSanitizerIsForeignContentRoot(elementName)
	}

	var namespace htmlSanitizerNamespace
	switch elementName {
	case "svg":
		namespace = htmlSanitizerNamespaceSvg
	case "math":
		namespace = htmlSanitizerNamespaceMathml
	default:
		return c.processHTMLStartTagInHTMLNamespace(elementName, attrs)
	}

	if !selfClosing {
		c.push(newHTMLSanitizerOpenElement(elementName, namespace, attrs))
	}
	return selfClosing
}

// processHTMLStartTagInHTMLNamespace is the part of processHTMLStartTag for
// the tags other than svg and math, which insert HTML elements and never
// honor the self-closing flag.
func (c *htmlSanitizerForeignContentContext) processHTMLStartTagInHTMLNamespace(
	elementName string, attrs []string) bool {
	if len(c.openElements) == 0 {
		c.trackUntrackedHTMLStartTag(elementName)
		if c.unknown {
			return false
		}
	}
	if htmlSanitizerUnmodeledContextChangingStartTagNames.contains(elementName) {
		c.becomeUnknown()
		return false
	}
	if elementName == "form" {
		if c.htmlInsertionMode == htmlSanitizerHTMLInsertionModeInTable {
			// "In table" inserts a new form and immediately pops it.
			if !c.formPointerSet {
				c.formPointerSet = true
				c.trackedFormElement = nil
			}
			return false
		}
		c.processFormStartTag(attrs)
		return false
	}
	if len(c.openElements) == 0 {
		return false
	}
	if htmlSanitizerTableStructureStartTagNames.contains(elementName) {
		if c.htmlInsertionMode != htmlSanitizerHTMLInsertionModeInBody {
			c.becomeUnknown()
		}
		return false
	}
	switch {
	case htmlSanitizerPClosingStartTagNames.contains(elementName),
		elementName == "pre", elementName == "listing",
		elementName == "plaintext", elementName == "xmp":
		if !c.closePIfInButtonScope() {
			return false
		}
	case htmlSanitizerIsHeadingName(elementName):
		if !c.closePIfInButtonScope() {
			return false
		}
		current := c.currentElement()
		if current.namespace == htmlSanitizerNamespaceHTML &&
			htmlSanitizerIsHeadingName(current.elementName) {
			c.truncate(len(c.openElements) - 1)
		}
	case elementName == "li":
		if !c.closeListOrDescriptionItemForStart(true) ||
			!c.closePIfInButtonScope() {
			return false
		}
	case elementName == "dd", elementName == "dt":
		if !c.closeListOrDescriptionItemForStart(false) ||
			!c.closePIfInButtonScope() {
			return false
		}
	case elementName == "button":
		buttonIndex := c.findHTMLElementInDefaultScope("button", true)
		if buttonIndex >= 0 {
			if !c.popTrackedElementsFrom(buttonIndex, false, nil) {
				return false
			}
		}
	case elementName == "a":
		if c.findOpenHTMLElement("a") >= 0 {
			c.becomeUnknown()
			return false
		}
	case elementName == "nobr":
		if c.findHTMLElementInDefaultScope("nobr", false) >= 0 {
			c.becomeUnknown()
			return false
		}
	case elementName == "select":
		selectIndex := c.findHTMLElementInDefaultScope("select", false)
		if selectIndex >= 0 {
			// A nested select start tag is ignored after popping the first.
			c.popTrackedElementsFrom(selectIndex, false, nil)
			return false
		}
	case elementName == "option":
		if c.findHTMLElementInDefaultScope("select", false) >= 0 {
			c.generateImpliedEndTags("optgroup")
		} else if c.isCurrentHTMLElement("option") {
			c.truncate(len(c.openElements) - 1)
		}
	case elementName == "optgroup":
		if c.findHTMLElementInDefaultScope("select", false) >= 0 {
			c.generateImpliedEndTags("")
		} else if c.isCurrentHTMLElement("option") {
			c.truncate(len(c.openElements) - 1)
		}
	case elementName == "input":
		if c.htmlInsertionMode == htmlSanitizerHTMLInsertionModeInTable &&
			htmlSanitizerHasHiddenInputType(attrs) {
			return false
		}
		selectIndex := c.findHTMLElementInDefaultScope("select", false)
		if selectIndex >= 0 {
			if !c.popTrackedElementsFrom(selectIndex, false, nil) {
				return false
			}
		}
	case elementName == "hr":
		if !c.closePIfInButtonScope() {
			return false
		}
		if c.findHTMLElementInDefaultScope("select", false) >= 0 {
			c.generateImpliedEndTags("")
		}
	case htmlSanitizerUnmodeledHTMLStartTagNames.contains(elementName):
		c.becomeUnknown()
		return false
	case elementName == "image":
		// The in-body rules rewrite image to the void img element.
		return false
	case elementName == "table":
		if c.htmlInsertionMode == htmlSanitizerHTMLInsertionModeInTable {
			c.becomeUnknown()
			return false
		}
		if c.findHTMLElementInDefaultScope("p", true) >= 0 {
			// Only a no-quirks document closes the p, and the sanitizer
			// cannot know the mode of the document that embeds its output.
			c.becomeUnknown()
			return false
		}
		table := newHTMLSanitizerOpenElement(elementName, htmlSanitizerNamespaceHTML, attrs)
		c.push(table)
		if !c.unknown {
			c.simpleTable = table
			c.simpleTableReturnMode = c.htmlInsertionMode
			c.htmlInsertionMode = htmlSanitizerHTMLInsertionModeInTable
		}
		return false
	}

	if !htmlSanitizerHTMLTreeBuilderVoidElementNames.contains(elementName) &&
		!htmlSanitizerIgnoredHTMLStartTagNames.contains(elementName) {
		c.push(newHTMLSanitizerOpenElement(elementName, htmlSanitizerNamespaceHTML, attrs))
	}
	// HTML ignores the self-closing flag on ordinary non-void elements.
	// Void elements are already empty and need no synthetic close event.
	return false
}

// currentUntrackedTable returns the innermost untracked table, or nil.
func (c *htmlSanitizerForeignContentContext) currentUntrackedTable() *htmlSanitizerUntrackedTable {
	if n := len(c.untrackedTables); n != 0 {
		return c.untrackedTables[n-1]
	}
	return nil
}

// syncInsertionMode derives the HTML insertion mode from the innermost
// untracked table.
func (c *htmlSanitizerForeignContentContext) syncInsertionMode() {
	table := c.currentUntrackedTable()
	switch {
	case table == nil:
		c.htmlInsertionMode = htmlSanitizerHTMLInsertionModeInBody
	case table.cellName != "":
		// The cell and caption modes hand everything else to the in-body
		// rules, but hand table structure to the table rules.
		c.htmlInsertionMode = htmlSanitizerHTMLInsertionModeInCell
	default:
		c.htmlInsertionMode = htmlSanitizerHTMLInsertionModeInTable
	}
}

// trackUntrackedHTMLStartTag follows the tables below the tracked region for
// a start tag seen while no element is tracked.
func (c *htmlSanitizerForeignContentContext) trackUntrackedHTMLStartTag(elementName string) {
	table := c.currentUntrackedTable()
	switch {
	case elementName == "table":
		if table != nil && table.cellName == "" {
			// The table modes pop the open table before reprocessing the
			// token; a cell or caption nests the new table instead.
			c.untrackedTables = c.untrackedTables[:len(c.untrackedTables)-1]
		}
		if len(c.untrackedTables) == htmlSanitizerForeignContentContextMaxUntrackedTables {
			c.becomeUnknown()
			return
		}
		c.untrackedTables = append(c.untrackedTables, &htmlSanitizerUntrackedTable{})
	case table == nil:
		return
	case elementName == "td" || elementName == "th":
		table.cellName = elementName
		if table.sectionName == "" {
			table.sectionName = "tbody"
		}
	case elementName == "caption":
		table.cellName = elementName
		table.sectionName = ""
	case elementName == "tr":
		table.cellName = ""
		if table.sectionName == "" {
			table.sectionName = "tbody"
		}
	case elementName == "tbody" || elementName == "thead" || elementName == "tfoot":
		table.cellName = ""
		table.sectionName = elementName
	case elementName == "col" || elementName == "colgroup":
		table.cellName = ""
		table.sectionName = ""
	}
	c.syncInsertionMode()
}

// trackUntrackedHTMLEndTag follows the tables below the tracked region for an
// end tag seen while no element is tracked.
func (c *htmlSanitizerForeignContentContext) trackUntrackedHTMLEndTag(elementName string) {
	table := c.currentUntrackedTable()
	if table == nil {
		return
	}
	switch elementName {
	case "table":
		c.untrackedTables = c.untrackedTables[:len(c.untrackedTables)-1]
	case "td", "th", "caption":
		// Ignored unless it names the open cell or caption.
		if elementName == table.cellName {
			table.cellName = ""
		}
	case "tr":
		// A caption ignores it; a cell closes along with the row.
		if table.cellName != "caption" {
			table.cellName = ""
		}
	case "tbody", "thead", "tfoot":
		// A caption ignores it, and so does a cell in another section.
		if table.cellName != "caption" && elementName == table.sectionName {
			table.cellName = ""
			table.sectionName = ""
		}
	}
	c.syncInsertionMode()
}

// processFormStartTag applies a form start tag in a mode that inserts it.
func (c *htmlSanitizerForeignContentContext) processFormStartTag(attrs []string) {
	if c.formPointerSet {
		return
	}
	c.formPointerSet = true
	if len(c.openElements) == 0 {
		return
	}
	if !c.closePIfInButtonScope() {
		return
	}
	form := newHTMLSanitizerOpenElement("form", htmlSanitizerNamespaceHTML, attrs)
	c.push(form)
	if !c.unknown {
		c.trackedFormElement = form
	}
}

// closePIfInButtonScope closes a p element in button scope, and returns false
// if doing so made the context unknown.
func (c *htmlSanitizerForeignContentContext) closePIfInButtonScope() bool {
	pIndex := c.findHTMLElementInDefaultScope("p", true)
	if pIndex >= 0 {
		return c.popTrackedElementsFrom(pIndex, false, nil)
	}
	return true
}

// closeListOrDescriptionItemForStart closes the list item, or description
// term or details, that an li, or a dd or dt, start tag closes, and returns
// false if doing so made the context unknown.
func (c *htmlSanitizerForeignContentContext) closeListOrDescriptionItemForStart(listItem bool) bool {
	for i := len(c.openElements) - 1; i >= 0; i-- {
		open := c.openElements[i]
		if open.namespace == htmlSanitizerNamespaceHTML {
			var closes bool
			if listItem {
				closes = open.elementName == "li"
			} else {
				closes = open.elementName == "dd" || open.elementName == "dt"
			}
			if closes {
				return c.popTrackedElementsFrom(i, false, nil)
			}
			if htmlSanitizerAmbiguouslySpecialHTMLElementNamesSet.contains(open.elementName) {
				c.becomeUnknown()
				return false
			}
		}
		if open.isSpecial() &&
			!open.isHTMLElement("address") &&
			!open.isHTMLElement("div") &&
			!open.isHTMLElement("p") {
			return true
		}
	}
	return true
}

// popTrackedElementsFrom pops a known suffix, or fails closed if doing so
// leaves formatting elements only in the active formatting list.  A later
// start tag could reconstruct those elements and put Chrome back in HTML
// content while this bounded tracker believed that the current node was
// foreign.
func (c *htmlSanitizerForeignContentContext) popTrackedElementsFrom(
	fromIndex int, allFormattingEntriesAreCleared bool,
	oneFormattingEntryRemoved *htmlSanitizerOpenElement) bool {
	if !allFormattingEntriesAreCleared {
		for i := len(c.openElements) - 1; i >= fromIndex; i-- {
			open := c.openElements[i]
			if open.namespace == htmlSanitizerNamespaceHTML &&
				htmlSanitizerFormattingElementNames.contains(open.elementName) &&
				open != oneFormattingEntryRemoved {
				c.becomeUnknown()
				return false
			}
		}
	}
	c.truncate(fromIndex)
	return true
}

// generateImpliedEndTags pops the elements whose end tags are implied, other
// than one named except.  An empty except excepts nothing.
func (c *htmlSanitizerForeignContentContext) generateImpliedEndTags(except string) {
	for len(c.openElements) != 0 {
		current := c.currentElement()
		if current.namespace != htmlSanitizerNamespaceHTML ||
			!htmlSanitizerImpliedEndTagNames.contains(current.elementName) ||
			current.elementName == except {
			return
		}
		c.truncate(len(c.openElements) - 1)
	}
}

// findHTMLElementInDefaultScope returns the index of the innermost HTML
// element with this name in the default scope, or in the button scope, or -1.
func (c *htmlSanitizerForeignContentContext) findHTMLElementInDefaultScope(
	elementName string, buttonScope bool) int {
	for i := len(c.openElements) - 1; i >= 0; i-- {
		open := c.openElements[i]
		if open.isHTMLElement(elementName) {
			return i
		}
		if open.namespace != htmlSanitizerNamespaceHTML {
			if open.special {
				return -1
			}
		} else if htmlSanitizerDefaultScopeBoundaryNames.contains(open.elementName) ||
			(buttonScope && open.elementName == "button") {
			return -1
		}
	}
	return -1
}

// isInDefaultScope reports whether the element at targetIndex is in the
// default scope.
func (c *htmlSanitizerForeignContentContext) isInDefaultScope(targetIndex int) bool {
	for i := len(c.openElements) - 1; i > targetIndex; i-- {
		open := c.openElements[i]
		if open.namespace != htmlSanitizerNamespaceHTML {
			if open.special {
				return false
			}
		} else if htmlSanitizerDefaultScopeBoundaryNames.contains(open.elementName) {
			return false
		}
	}
	return true
}

// findOpenHTMLElement returns the index of the innermost open HTML element
// with this name, or -1.
func (c *htmlSanitizerForeignContentContext) findOpenHTMLElement(elementName string) int {
	for i := len(c.openElements) - 1; i >= 0; i-- {
		if c.openElements[i].isHTMLElement(elementName) {
			return i
		}
	}
	return -1
}

// isCurrentHTMLElement reports whether the current node is the HTML element
// with this name.
func (c *htmlSanitizerForeignContentContext) isCurrentHTMLElement(elementName string) bool {
	return c.currentElement().isHTMLElement(elementName)
}

// becomeUnknown gives up tracking the browser's context.
func (c *htmlSanitizerForeignContentContext) becomeUnknown() {
	c.truncate(0)
	// Whether the browser has a form pointer does not become unknowable with
	// the stack.  Keep the bit so the balancer can apply the form start rule
	// after an unmodeled context such as template contents.  Its target can
	// no longer be located within this bounded stack.
	c.trackedFormElement = nil
	c.simpleTable = nil
	clear(c.untrackedTables)
	c.untrackedTables = c.untrackedTables[:0]
	c.unknown = true
}

// popToHTMLOrIntegrationPoint pops foreign elements until the current node is
// an HTML element or an integration point.
func (c *htmlSanitizerForeignContentContext) popToHTMLOrIntegrationPoint() {
	for len(c.openElements) != 0 {
		current := c.currentElement()
		if current.namespace == htmlSanitizerNamespaceHTML ||
			current.mathTextIntegrationPoint || current.htmlIntegrationPoint {
			return
		}
		c.truncate(len(c.openElements) - 1)
	}
}

// push opens an element, or makes the context unknown if the bounded stack
// is full.
func (c *htmlSanitizerForeignContentContext) push(element *htmlSanitizerOpenElement) {
	if len(c.openElements) == htmlSanitizerForeignContentContextMaxDepth {
		c.becomeUnknown()
		return
	}
	serial := c.nextElementSerial
	if serial == 0 {
		serial = 1
	}
	element.serial = serial
	c.nextElementSerial = serial + 1
	c.pushedSerial = element.serial
	c.openElements = append(c.openElements, element)
}

// currentElement returns the current node, or nil while nothing is tracked.
func (c *htmlSanitizerForeignContentContext) currentElement() *htmlSanitizerOpenElement {
	if n := len(c.openElements); n != 0 {
		return c.openElements[n-1]
	}
	return nil
}

// truncate pops every element at or above index n.
func (c *htmlSanitizerForeignContentContext) truncate(n int) {
	clear(c.openElements[n:])
	c.openElements = c.openElements[:n]
}

// clearPopped forgets the elements popped by the previous end tag.
func (c *htmlSanitizerForeignContentContext) clearPopped() {
	c.poppedForeignNames = c.poppedForeignNames[:0]
	c.poppedForeignSerials = c.poppedForeignSerials[:0]
}

// htmlSanitizerUsesHTMLRulesForStartTag reports whether a start tag under the
// current node is processed under the HTML tree-building rules.
func htmlSanitizerUsesHTMLRulesForStartTag(
	current *htmlSanitizerOpenElement, elementName string) bool {
	if current == nil || current.namespace == htmlSanitizerNamespaceHTML {
		return true
	}
	if current.mathTextIntegrationPoint &&
		elementName != "mglyph" && elementName != "malignmark" {
		return true
	}
	return current.htmlIntegrationPoint ||
		(current.namespace == htmlSanitizerNamespaceMathml &&
			current.elementName == "annotation-xml" &&
			elementName == "svg")
}

// htmlSanitizerHTMLInsertionMode is the part of the HTML insertion mode that
// the foreign-content context follows.
type htmlSanitizerHTMLInsertionMode int

const (
	htmlSanitizerHTMLInsertionModeInBody htmlSanitizerHTMLInsertionMode = iota
	htmlSanitizerHTMLInsertionModeInTable
	htmlSanitizerHTMLInsertionModeInCell
)

// htmlSanitizerNamespace is the namespace a browser puts an element in.
type htmlSanitizerNamespace int

const (
	htmlSanitizerNamespaceHTML htmlSanitizerNamespace = iota
	htmlSanitizerNamespaceSvg
	htmlSanitizerNamespaceMathml
)

// htmlSanitizerOpenElement is one element relevant to the foreign-content
// tree-construction state.
type htmlSanitizerOpenElement struct {
	elementName              string
	namespace                htmlSanitizerNamespace
	mathTextIntegrationPoint bool
	htmlIntegrationPoint     bool
	// special is true for an element in the special category, which bounds
	// every scope.
	special bool
	// serial is the opaque identity assigned when this node enters the
	// tracked stack.
	serial int32
}

// newHTMLSanitizerOpenElement describes an element about to be inserted.
func newHTMLSanitizerOpenElement(
	elementName string, namespace htmlSanitizerNamespace,
	attrs []string) *htmlSanitizerOpenElement {
	e := &htmlSanitizerOpenElement{
		elementName: elementName,
		namespace:   namespace,
		mathTextIntegrationPoint: namespace == htmlSanitizerNamespaceMathml &&
			htmlSanitizerMathmlTextIntegrationPointNames.contains(elementName),
		htmlIntegrationPoint: htmlSanitizerIsHTMLIntegrationPoint(
			elementName, namespace, attrs),
	}
	e.special = e.mathTextIntegrationPoint || e.htmlIntegrationPoint ||
		(namespace == htmlSanitizerNamespaceMathml && elementName == "annotation-xml")
	return e
}

// isHTMLElement reports whether e is the HTML element with this name.
func (e *htmlSanitizerOpenElement) isHTMLElement(elementName string) bool {
	return e.namespace == htmlSanitizerNamespaceHTML && elementName == e.elementName
}

// isSpecial reports whether e is in the special category.
func (e *htmlSanitizerOpenElement) isSpecial() bool {
	if e.namespace == htmlSanitizerNamespaceHTML {
		return htmlSanitizerSpecialHTMLElementNamesSet.contains(e.elementName)
	}
	return e.special
}

// htmlSanitizerUntrackedTable is a table open below the tracked region, and
// the part of it being filled.
type htmlSanitizerUntrackedTable struct {
	// cellName is td, th or caption while one is open, or empty.
	cellName string
	// sectionName is tbody, thead or tfoot while one is open, or empty.
	sectionName string
}

// htmlSanitizerIsForeignContentRoot reports whether a start tag with this
// canonical name opens SVG or MathML from HTML content.
func htmlSanitizerIsForeignContentRoot(canonElementName string) bool {
	return canonElementName == "svg" || canonElementName == "math"
}

// htmlSanitizerIsHTMLIntegrationPoint reports whether an element inserted
// with this name, namespace and attributes is an HTML integration point.
func htmlSanitizerIsHTMLIntegrationPoint(
	elementName string, namespace htmlSanitizerNamespace, attrs []string) bool {
	if namespace == htmlSanitizerNamespaceSvg {
		return elementName == "desc" || elementName == "title" ||
			htmlSanitizerAsciiEqualsIgnoreCase("foreignObject", elementName)
	}
	if namespace != htmlSanitizerNamespaceMathml || elementName != "annotation-xml" {
		return false
	}
	for i := 0; i < len(attrs); i += 2 {
		name := attrs[i]
		value := ""
		if i+1 < len(attrs) {
			value = attrs[i+1]
		}
		if name == "encoding" {
			return htmlSanitizerAsciiEqualsIgnoreCase("text/html", value) ||
				htmlSanitizerAsciiEqualsIgnoreCase("application/xhtml+xml", value)
		}
	}
	return false
}

// htmlSanitizerAsciiEqualsIgnoreCase reports whether a and b are equal when
// ASCII letters are compared without regard to case.
func htmlSanitizerAsciiEqualsIgnoreCase(a, b string) bool {
	length := len(a)
	return len(b) == length && stringsRegionMatchesIgnoreCase(a, 0, b, 0, length)
}

// htmlSanitizerBreaksOutOfForeignContent reports whether a start tag with
// these attributes pops back out of foreign content to HTML content.
func htmlSanitizerBreaksOutOfForeignContent(
	canonElementName string, attrs []string) bool {
	if htmlSanitizerForeignContentBreakoutElementNames.contains(canonElementName) {
		return true
	}
	if canonElementName == "font" {
		for i := 0; i < len(attrs); i += 2 {
			switch attrs[i] {
			case "color", "face", "size":
				return true
			}
		}
	}
	return false
}

// htmlSanitizerHasHiddenInputType reports whether an input start tag with
// these attributes has the hidden type.
func htmlSanitizerHasHiddenInputType(attrs []string) bool {
	for i := 0; i+1 < len(attrs); i += 2 {
		if attrs[i] == "type" {
			// The tokenizer drops all but the first of duplicate attributes.
			return htmlSanitizerAsciiEqualsIgnoreCase("hidden", attrs[i+1])
		}
	}
	return false
}

// htmlSanitizerIsHeadingName is true for h1 through h6, any of which an h1
// through h6 end tag closes.
func htmlSanitizerIsHeadingName(canonElementName string) bool {
	if len(canonElementName) != 2 || canonElementName[0] != 'h' {
		return false
	}
	digit := canonElementName[1]
	return '1' <= digit && digit <= '6'
}

// htmlSanitizerNameSet is a set of element names.  The sets below are built
// at init and never modified.
type htmlSanitizerNameSet map[string]struct{}

// newHTMLSanitizerNameSet returns a set holding names.
func newHTMLSanitizerNameSet(names ...string) htmlSanitizerNameSet {
	s := make(htmlSanitizerNameSet, len(names))
	for _, name := range names {
		s[name] = struct{}{}
	}
	return s
}

// contains reports whether name is in s.
func (s htmlSanitizerNameSet) contains(name string) bool {
	_, ok := s[name]
	return ok
}

var (
	// htmlSanitizerTableScopedElementNames are the end tags whose effect is
	// decided by table scope or the insertion mode.
	htmlSanitizerTableScopedElementNames = newHTMLSanitizerNameSet(
		"table", "caption", "tbody", "thead", "tfoot", "tr", "td", "th")

	// htmlSanitizerIgnoredHTMLEndTagNames are the HTML end tags that never
	// pop the stack.
	htmlSanitizerIgnoredHTMLEndTagNames = newHTMLSanitizerNameSet(
		"svg", "math", "body", "html", "br", "col", "colgroup", "frame",
		"head")

	// htmlSanitizerSpecificEndTagRuleNames are the end tags with their own
	// "in body" rules, which search a scope rather than stopping at the first
	// element in the special category.
	htmlSanitizerSpecificEndTagRuleNames = newHTMLSanitizerNameSet(
		"address", "article", "aside", "blockquote", "button", "center",
		"details", "dialog", "dir", "div", "dl", "fieldset", "figcaption",
		"figure", "footer", "header", "hgroup", "listing", "main", "menu",
		"nav", "ol", "pre", "search", "section", "select", "summary",
		"ul", "form", "p", "li", "dd", "dt", "h1", "h2", "h3", "h4",
		"h5", "h6",
		"a", "b", "big", "code", "em", "font", "i", "nobr", "s", "small",
		"strike", "strong", "tt", "u", "applet", "marquee", "object")

	// htmlSanitizerFormattingElementNames are the formatting elements.
	htmlSanitizerFormattingElementNames = newHTMLSanitizerNameSet(
		"a", "b", "big", "code", "em", "font", "i", "nobr", "s", "small",
		"strike", "strong", "tt", "u")

	// htmlSanitizerActiveFormattingMarkerElementNames are the elements whose
	// end tags clear the active formatting list to a marker.
	htmlSanitizerActiveFormattingMarkerElementNames = newHTMLSanitizerNameSet(
		"applet", "marquee", "object")

	// htmlSanitizerDefaultScopeBoundaryNames are the HTML elements that bound
	// the default scope.
	htmlSanitizerDefaultScopeBoundaryNames = newHTMLSanitizerNameSet(
		"applet", "caption", "html", "table", "td", "th", "marquee",
		"object", "select", "template")

	// htmlSanitizerSpecialHTMLElementNamesSet are the HTML elements in the
	// special category.
	htmlSanitizerSpecialHTMLElementNamesSet = newHTMLSanitizerNameSet(
		"address", "applet", "area", "article", "aside", "base",
		"basefont", "bgsound", "blockquote", "body", "br", "button",
		"caption", "center", "col", "colgroup", "dd", "details",
		"dialog", "dir", "div", "dl", "dt", "embed", "fieldset",
		"figcaption", "figure", "footer", "form", "frame", "frameset",
		"h1", "h2", "h3", "h4",
		"h5", "h6", "head", "header", "hgroup", "hr", "html", "iframe",
		"img", "input", "keygen", "li", "link", "listing", "main",
		"marquee", "menu", "meta", "nav", "noembed", "noframes",
		"noscript", "object", "ol", "p", "param", "plaintext", "pre",
		"script", "search", "section", "select", "source", "style",
		"summary", "table", "tbody", "td", "template", "textarea",
		"tfoot", "th", "thead", "title", "tr", "track", "ul", "wbr",
		"xmp")

	// htmlSanitizerAmbiguouslySpecialHTMLElementNamesSet are the elements the
	// specification puts in the special category but current Chrome does
	// not, so a walk that reaches one has an uncertain outcome.  dialog and
	// search are both special in the WHATWG parsing algorithm but absent from
	// Chrome's special-node set.
	htmlSanitizerAmbiguouslySpecialHTMLElementNamesSet = newHTMLSanitizerNameSet(
		"dialog", "search")

	// htmlSanitizerUnmodeledContextChangingStartTagNames are the start tags
	// whose HTML stack effect this bounded tracker cannot derive.
	htmlSanitizerUnmodeledContextChangingStartTagNames = newHTMLSanitizerNameSet(
		"template", "frameset")

	// htmlSanitizerUnmodeledHTMLStartTagNames are the ruby starts, which
	// generate implied end tags using state outside this tracker.
	htmlSanitizerUnmodeledHTMLStartTagNames = newHTMLSanitizerNameSet(
		"rb", "rtc", "rp", "rt")

	// htmlSanitizerPClosingStartTagNames are the start tags that close a p
	// element in button scope before insertion.
	htmlSanitizerPClosingStartTagNames = newHTMLSanitizerNameSet(
		"address", "article", "aside", "blockquote", "center", "details",
		"dialog", "dir", "div", "dl", "fieldset", "figcaption", "figure",
		"footer", "header", "hgroup", "main", "menu", "nav", "ol", "p",
		"search", "section", "summary", "ul")

	// htmlSanitizerImpliedEndTagNames are the elements whose end tags are
	// implied.
	htmlSanitizerImpliedEndTagNames = newHTMLSanitizerNameSet(
		"dd", "dt", "li", "optgroup", "option", "p", "rb", "rp", "rt",
		"rtc")

	// htmlSanitizerTableStructureStartTagNames are the table structure start
	// tags.
	htmlSanitizerTableStructureStartTagNames = newHTMLSanitizerNameSet(
		"caption", "col", "colgroup", "tbody", "thead", "tfoot", "tr",
		"td", "th")

	// htmlSanitizerHTMLTreeBuilderVoidElementNames are the start tags the
	// current HTML tree builder inserts and immediately pops.
	htmlSanitizerHTMLTreeBuilderVoidElementNames = newHTMLSanitizerNameSet(
		"area", "base", "basefont", "bgsound", "br", "embed", "hr",
		"img", "input", "keygen", "link", "meta", "param", "source",
		"track", "wbr")

	// htmlSanitizerIgnoredHTMLStartTagNames are the start tags that "in body"
	// ignores or merges rather than inserting.
	htmlSanitizerIgnoredHTMLStartTagNames = newHTMLSanitizerNameSet(
		"html", "body", "head", "frame", "caption", "col", "colgroup",
		"tbody", "thead", "tfoot", "tr", "td", "th")

	// htmlSanitizerMathmlTextIntegrationPointNames are the MathML text
	// integration points.
	htmlSanitizerMathmlTextIntegrationPointNames = newHTMLSanitizerNameSet(
		"mi", "mo", "mn", "ms", "mtext")

	// htmlSanitizerForeignContentBreakoutElementNames are the start tags that
	// end foreign content: inside <svg> or <math>, a browser pops back out to
	// HTML content and processes one of these as HTML.  A <font> tag with a
	// color, face or size attribute does the same.  See "The rules for
	// parsing tokens in foreign content" at
	// https://html.spec.whatwg.org/multipage/parsing.html#parsing-main-inforeign
	htmlSanitizerForeignContentBreakoutElementNames = newHTMLSanitizerNameSet(
		"b", "big", "blockquote", "body", "br", "center", "code", "dd",
		"div", "dl", "dt", "em", "embed", "h1", "h2", "h3", "h4", "h5",
		"h6", "head", "hr", "i", "img", "li", "listing", "menu", "meta",
		"nobr", "ol", "p", "pre", "ruby", "s", "small", "span", "strong",
		"strike", "sub", "sup", "table", "tt", "u", "ul", "var")
)

// htmlSanitizerSpecialHTMLElementNames returns the HTML elements in the
// special category, for the tag balancer, which walks its own stack by the
// same rule when a list item starts.  The caller must not modify the result.
func htmlSanitizerSpecialHTMLElementNames() map[string]struct{} {
	return htmlSanitizerSpecialHTMLElementNamesSet
}

// htmlSanitizerAmbiguouslySpecialHTMLElementNames returns the elements the
// specification puts in the special category but Chrome does not, for the tag
// balancer, which follows Chrome as this does.  The caller must not modify
// the result.
func htmlSanitizerAmbiguouslySpecialHTMLElementNames() map[string]struct{} {
	return htmlSanitizerAmbiguouslySpecialHTMLElementNamesSet
}

// htmlSanitizerStripQuotes removes the quotes around an attribute value.
func htmlSanitizerStripQuotes(encodedAttributeValue string) string {
	n := len(encodedAttributeValue)
	if n > 0 {
		last := encodedAttributeValue[n-1]
		if last == '"' || last == '\'' {
			start := 0
			if n != 1 && last == encodedAttributeValue[0] {
				start = 1
			}
			// Otherwise browsers deal with missing left quotes:
			// <img src=foo.png"> but generally do not deal with missing right:
			// <img src="foo.png>
			return encodedAttributeValue[start : n-1]
		}
	}
	return encodedAttributeValue
}

// htmlSanitizerInitializePolicy puts a tag balancer in front of the policy and
// lets the preprocessor wrap the result.
func htmlSanitizerInitializePolicy(
	policy HTMLSanitizerPolicy,
	preprocessor HTMLStreamEventProcessor) HTMLStreamEventReceiver {
	balancer := NewTagBalancingHTMLStreamEventReceiver(policy)

	// According to Opera the maximum table nesting depth seen in the wild is
	// 795, but 99.99% of documents have a table nesting depth of less than 22.
	// Since each table has a nesting depth of 4 (incl. TBODY), this leads to a
	// document depth of 90 (incl. HTML & BODY).
	// Obviously table nesting depth is not the same as whole document depth,
	// but it is the best proxy I have available.
	// See http://devfiles.myopera.com/articles/590/maxtabledepth-url.htm for
	// the original data.

	// Webkit defines the maximum HTML parser tree depth as 512.
	// http://trac.webkit.org/browser/trunk/Source/WebCore/page/Settings.h#L408
	// static const unsigned defaultMaximumHTMLParserDOMTreeDepth = 512;

	// The first number gives us a lower bound on the nesting depth we allow,
	// 90, and the second gives us an upper bound: 512.
	// We do not want to bump right up against that limit.
	// 256 is substantially larger than the lower bound and well clear of the
	// upper bound.
	balancer.SetNestingLimit(256)
	return preprocessor.Wrap(balancer)
}
