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

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/HtmlChangeReporter.java.

package sanitizer

import (
	"reflect"
	"slices"
)

// HTMLChangeReporter sits between the HTML parser, the policy, and the
// renderer so that it can report dropped elements, attributes and text to an
// HTMLChangeListener.
//
//	hcr := NewHTMLChangeReporter(renderer, htmlChangeListener, context)
//	hcr.SetPolicy(policyFactory.Apply(hcr.GetWrappedRenderer()))
//	Sanitize(html, hcr.GetWrappedPolicy(), nil)
//
// The renderer receives events from the policy unchanged, but the reporter
// notices differences between the events from the lexer and those from the
// policy, and receives notice of text the policy or renderer drops.
type HTMLChangeReporter struct {
	output *htmlChangeReporterOutputChannel
	input  *htmlChangeReporterInputChannel
}

// NewHTMLChangeReporter returns a reporter that forwards what the policy
// emits to renderer and reports what it drops to listener, along with
// context.
func NewHTMLChangeReporter(
	renderer HTMLStreamEventReceiver, listener HTMLChangeListener,
	context any) *HTMLChangeReporter {
	output := newHTMLChangeReporterOutputChannel(renderer)
	return &HTMLChangeReporter{
		output: output,
		input:  newHTMLChangeReporterInputChannel(output, listener, context),
	}
}

// SetPolicy associates an input channel.  The wrapped policy receives events
// and forwards them to policy.
func (r *HTMLChangeReporter) SetPolicy(policy HTMLSanitizerPolicy) {
	r.input.policy = policy
}

// GetWrappedRenderer returns the receiver the policy should write to, which
// forwards to the underlying renderer.
func (r *HTMLChangeReporter) GetWrappedRenderer() HTMLStreamEventReceiver {
	return r.output
}

// GetWrappedPolicy returns the policy to sanitize with, which forwards to the
// policy given to SetPolicy.
func (r *HTMLChangeReporter) GetWrappedPolicy() HTMLSanitizerPolicy {
	return r.input
}

// htmlChangeReporterAttributelessSkipPolicy is implemented by a policy that
// can say, after OpenTag, whether it allowed the element but emitted no tag
// because every attribute had been rejected and the element is skipped when
// it has none.  Attributes rejected from such an element are the policy's
// doing and are reported; attributes on a rejected element go with it and
// are not.
type htmlChangeReporterAttributelessSkipPolicy interface {
	// skippedLastTagAsAttributeless returns true if the most recent start tag
	// was allowed by the element policy and dropped only for having no
	// attributes left.
	skippedLastTagAsAttributeless() bool
}

// htmlChangeReporterDroppedTextSource is implemented by a policy that can
// report text it drops after keeping the element that contained it.
type htmlChangeReporterDroppedTextSource interface {
	// reportDroppedTextTo sends dropped text to listener, or to nobody when
	// nil.
	reportDroppedTextTo(listener htmlStreamRendererDroppedTextListener)
}

// htmlChangeReporterDiscardedAttributeListener receives exact input
// attributes rejected by an attribute policy.
type htmlChangeReporterDiscardedAttributeListener interface {
	discardedAttribute(name, value string)
}

// htmlChangeReporterDiscardedAttributeSource is implemented by a policy that
// can identify attribute-policy rejections.
type htmlChangeReporterDiscardedAttributeSource interface {
	// reportDiscardedAttributesTo sends rejections to listener, or to nobody
	// when nil.
	reportDiscardedAttributesTo(listener htmlChangeReporterDiscardedAttributeListener)
}

// htmlChangeReporterInputChannelOpenTagMode says which policy operation an
// open tag call forwards to.
type htmlChangeReporterInputChannelOpenTagMode int

const (
	htmlChangeReporterInputChannelOpenTagModeNormal htmlChangeReporterInputChannelOpenTagMode = iota
	htmlChangeReporterInputChannelOpenTagModeReopenedTable
	htmlChangeReporterInputChannelOpenTagModeSuppress
	htmlChangeReporterInputChannelOpenTagModeSuppressInheritTextGate
	htmlChangeReporterInputChannelOpenTagModeSuppressSubtree
	htmlChangeReporterInputChannelOpenTagModeEmitSuppressSubtree
	htmlChangeReporterInputChannelOpenTagModeInheritTextGate
)

// htmlChangeReporterInputChannel receives the parse events, forwards them to
// the policy, and reports what the policy and renderer drop.
type htmlChangeReporterInputChannel struct {
	policy   HTMLStreamEventReceiver
	output   *htmlChangeReporterOutputChannel
	context  any
	listener HTMLChangeListener
	// pendingDroppedText alternates element names and text, gathered before
	// user callbacks.
	pendingDroppedText []string
	// lastOpenOutputName is the output name produced in response to the most
	// recent input start tag.
	lastOpenOutputName optionalElementName
	// The start whose policy result was prepared before balancing output
	// context, valid while prepared is true.
	prepared             bool
	preparedElementName  string
	preparedElementAttrs []string
}

// newHTMLChangeReporterInputChannel returns a channel with no policy yet.
func newHTMLChangeReporterInputChannel(
	output *htmlChangeReporterOutputChannel, listener HTMLChangeListener,
	context any) *htmlChangeReporterInputChannel {
	return &htmlChangeReporterInputChannel{
		output:   output,
		context:  context,
		listener: listener,
	}
}

// nestingLimitReached reports a start tag the tag balancer dropped.  The
// balancer sits upstream of this channel, so a tag it drops for exceeding the
// nesting limit never reaches the policy and would otherwise go unreported.
// It tells us directly instead, under the canonical name it forwards every
// start tag under.  The same goes for a form start it ignores because the
// browser's form element pointer is set.
func (c *htmlChangeReporterInputChannel) nestingLimitReached(canonElementName string) {
	c.listener.DiscardedTag(c.context, canonElementName)
}

// suppressesTextWhenDropped asks the policy for the same reason: before
// dropping a start tag at the limit, the balancer asks whether the element's
// text is suppressed, and the policy that knows sits behind this channel.
func (c *htmlChangeReporterInputChannel) suppressesTextWhenDropped(canonElementName string) bool {
	tp, ok := c.policy.(tagBalancingHTMLStreamEventReceiverTextSuppressionPolicy)
	return ok && tp.suppressesTextWhenDropped(canonElementName)
}

// droppedText is called by the renderer, which sits downstream and drops
// literal content it cannot emit without a browser reading it differently.
// It tells us directly, as the balancer does for the nesting limit.
func (c *htmlChangeReporterInputChannel) droppedText(elementName, text string) {
	c.pendingDroppedText = append(c.pendingDroppedText, elementName, text)
}

// droppedTag is called when the renderer likewise refuses a start tag whose
// name it cannot write or that arrives inside literal content, after the
// policy has opened it.  No tag came out, so the input tag was discarded, and
// the report says so; the end tag the renderer refuses later is the same
// loss.
func (c *htmlChangeReporterInputChannel) droppedTag(elementName string) {
	c.output.refusedOpenedTag()
}

// droppedAttribute is called when the renderer leaves an attribute whose name
// it cannot write off a tag it does write.  The policy's own accounting had
// counted it as emitted; this returns it to the discarded.
func (c *htmlChangeReporterInputChannel) droppedAttribute(elementName, name, value string) {
	c.output.attributeLeftOff(name, value)
}

// openTagOutputPolicy returns the policy as the balancer's view of it, or
// nil.
func (c *htmlChangeReporterInputChannel) openTagOutputPolicy() tagBalancingHTMLStreamEventReceiverOpenTagOutputPolicy {
	tp, _ := c.policy.(tagBalancingHTMLStreamEventReceiverOpenTagOutputPolicy)
	return tp
}

// outputElementNameForLastOpenTag answers from the policy when it can say,
// not from what reached the renderer: the balancer mirrors the policy's own
// stack, a postprocessor between them can filter what reaches the renderer,
// and attaching a listener must not change how the output is balanced.
func (c *htmlChangeReporterInputChannel) outputElementNameForLastOpenTag() (string, bool) {
	if tp := c.openTagOutputPolicy(); tp != nil {
		return tp.outputElementNameForLastOpenTag()
	}
	return c.lastOpenOutputName.get()
}

func (c *htmlChangeReporterInputChannel) outputElementForLastOpenTagUsedForeignContentRules() bool {
	tp := c.openTagOutputPolicy()
	return tp != nil && tp.outputElementForLastOpenTagUsedForeignContentRules()
}

func (c *htmlChangeReporterInputChannel) outputSelectRetiredForLastOpenTag() bool {
	tp := c.openTagOutputPolicy()
	return tp != nil && tp.outputSelectRetiredForLastOpenTag()
}

func (c *htmlChangeReporterInputChannel) inputSelectRetiredForLastOpenTag() bool {
	tp := c.openTagOutputPolicy()
	return tp != nil && tp.inputSelectRetiredForLastOpenTag()
}

func (c *htmlChangeReporterInputChannel) hasOpenHTMLOutputSelect() bool {
	tp := c.openTagOutputPolicy()
	return tp != nil && tp.hasOpenHTMLOutputSelect()
}

func (c *htmlChangeReporterInputChannel) hasOpenHTMLOutputListItem() bool {
	tp := c.openTagOutputPolicy()
	return tp != nil && tp.hasOpenHTMLOutputListItem()
}

func (c *htmlChangeReporterInputChannel) hasOpenHTMLOutputList() bool {
	tp := c.openTagOutputPolicy()
	return tp != nil && tp.hasOpenHTMLOutputList()
}

func (c *htmlChangeReporterInputChannel) outputNestingDepth() int {
	if tp := c.openTagOutputPolicy(); tp != nil {
		return tp.outputNestingDepth()
	}
	return 0
}

func (c *htmlChangeReporterInputChannel) outputContainerElementName() (string, bool) {
	if tp := c.openTagOutputPolicy(); tp != nil {
		return tp.outputContainerElementName()
	}
	return "", false
}

func (c *htmlChangeReporterInputChannel) supportsPushedOutTableOperations() bool {
	tablePolicy := c.pushedOutTablePolicy()
	return tablePolicy != nil && tablePolicy.supportsPushedOutTableOperations()
}

func (c *htmlChangeReporterInputChannel) isOutputInForeignContent() bool {
	tablePolicy := c.pushedOutTablePolicy()
	return tablePolicy != nil && tablePolicy.isOutputInForeignContent()
}

func (c *htmlChangeReporterInputChannel) outputForeignContentRootName() (string, bool) {
	if tablePolicy := c.pushedOutTablePolicy(); tablePolicy != nil {
		return tablePolicy.outputForeignContentRootName()
	}
	return "", false
}

func (c *htmlChangeReporterInputChannel) outputStartTagUsesForeignContentRules(
	elementName string, attrs []string) bool {
	tablePolicy := c.pushedOutTablePolicy()
	return tablePolicy != nil &&
		tablePolicy.outputStartTagUsesForeignContentRules(elementName, attrs)
}

func (c *htmlChangeReporterInputChannel) outputTemplateStartTagUsesForeignContentRules(
	elementName string, attrs []string) bool {
	tablePolicy := c.pushedOutTablePolicy()
	return tablePolicy != nil &&
		tablePolicy.outputTemplateStartTagUsesForeignContentRules(elementName, attrs)
}

func (c *htmlChangeReporterInputChannel) outputStartTagUsesHTMLIntegrationPointRules(
	elementName string, attrs []string) bool {
	tablePolicy := c.pushedOutTablePolicy()
	return tablePolicy != nil &&
		tablePolicy.outputStartTagUsesHTMLIntegrationPointRules(elementName, attrs)
}

// pushedOutTablePolicy returns the policy as the balancer's view of it, or
// nil.
func (c *htmlChangeReporterInputChannel) pushedOutTablePolicy() tagBalancingHTMLStreamEventReceiverPushedOutTablePolicy {
	tablePolicy, _ := c.policy.(tagBalancingHTMLStreamEventReceiverPushedOutTablePolicy)
	return tablePolicy
}

// formPointerPolicy returns the policy as the balancer's view of it, or nil.
func (c *htmlChangeReporterInputChannel) formPointerPolicy() tagBalancingHTMLStreamEventReceiverFormPointerPolicy {
	formPolicy, _ := c.policy.(tagBalancingHTMLStreamEventReceiverFormPointerPolicy)
	return formPolicy
}

func (c *htmlChangeReporterInputChannel) formStartTagUsesTableRules() bool {
	formPolicy := c.formPointerPolicy()
	return formPolicy != nil && formPolicy.formStartTagUsesTableRules()
}

func (c *htmlChangeReporterInputChannel) outputFormElementPointerIsSet() bool {
	formPolicy := c.formPointerPolicy()
	return formPolicy != nil && formPolicy.outputFormElementPointerIsSet()
}

func (c *htmlChangeReporterInputChannel) clearFormPointerWithBalancedPair() bool {
	formPolicy := c.formPointerPolicy()
	return formPolicy != nil && formPolicy.clearFormPointerWithBalancedPair()
}

func (c *htmlChangeReporterInputChannel) retireOutputSelectForHTMLStart() bool {
	formPolicy := c.formPointerPolicy()
	return formPolicy != nil && formPolicy.retireOutputSelectForHTMLStart()
}

func (c *htmlChangeReporterInputChannel) retireOutputTableForForm(allowInputTable bool) bool {
	formPolicy := c.formPointerPolicy()
	return formPolicy != nil && formPolicy.retireOutputTableForForm(allowInputTable)
}

// prepareForFormStart prepares the policy's result for a form start, after
// noting the attributes it will be asked to account for.
func (c *htmlChangeReporterInputChannel) prepareForFormStart(attrs *[]string) bool {
	formPolicy := c.formPointerPolicy()
	if formPolicy == nil {
		return false
	}
	if c.prepared {
		panic("A start tag is already prepared")
	}
	c.output.expectAttributes(*attrs)
	result := formPolicy.prepareForFormStart(attrs)
	c.prepared = true
	c.preparedElementName = "form"
	c.preparedElementAttrs = *attrs
	return result
}

// prepareForStartTag prepares the policy's result for a start tag, after
// noting the attributes it will be asked to account for.
func (c *htmlChangeReporterInputChannel) prepareForStartTag(
	elementName string, attrs *[]string) (string, bool) {
	formPolicy := c.formPointerPolicy()
	if formPolicy == nil {
		return "", false
	}
	if c.prepared {
		panic("A start tag is already prepared")
	}
	// Attribute policies run during preparation.  Snapshot first so the
	// later open call reports the attributes they removed exactly once.
	c.output.expectAttributes(*attrs)
	outputName, ok := formPolicy.prepareForStartTag(elementName, attrs)
	c.prepared = true
	c.preparedElementName = elementName
	c.preparedElementAttrs = *attrs
	return outputName, ok
}

func (c *htmlChangeReporterInputChannel) isInKeptLiteralElement() bool {
	formPolicy := c.formPointerPolicy()
	return formPolicy != nil && formPolicy.isInKeptLiteralElement()
}

func (c *htmlChangeReporterInputChannel) preparedFormStartWillEmitAsHTML() bool {
	formPolicy := c.formPointerPolicy()
	return formPolicy != nil && formPolicy.preparedFormStartWillEmitAsHTML()
}

func (c *htmlChangeReporterInputChannel) discardPreparedFormStart() {
	c.clearPrepared()
	if formPolicy := c.formPointerPolicy(); formPolicy != nil {
		formPolicy.discardPreparedFormStart()
	}
}

func (c *htmlChangeReporterInputChannel) openRetiredFormTextContext() {
	if formPolicy := c.formPointerPolicy(); formPolicy != nil {
		formPolicy.openRetiredFormTextContext()
	}
}

func (c *htmlChangeReporterInputChannel) pushOutTableAroundRetiredForm() bool {
	formPolicy := c.formPointerPolicy()
	return formPolicy != nil && formPolicy.pushOutTableAroundRetiredForm()
}

func (c *htmlChangeReporterInputChannel) closeRetiredFormTextContext() bool {
	formPolicy := c.formPointerPolicy()
	return formPolicy != nil && formPolicy.closeRetiredFormTextContext()
}

func (c *htmlChangeReporterInputChannel) hasRetiredFormTextContext() bool {
	formPolicy := c.formPointerPolicy()
	return formPolicy != nil && formPolicy.hasRetiredFormTextContext()
}

func (c *htmlChangeReporterInputChannel) retiredFormTextContextAllowsEndTag() bool {
	formPolicy := c.formPointerPolicy()
	return formPolicy == nil || formPolicy.retiredFormTextContextAllowsEndTag()
}

func (c *htmlChangeReporterInputChannel) prepareOutputForHTMLStart(
	adjustedElementName string, attrs []string) {
	if formPolicy := c.formPointerPolicy(); formPolicy != nil {
		formPolicy.prepareOutputForHTMLStart(adjustedElementName, attrs)
	}
}

// clearPrepared forgets the prepared start.
func (c *htmlChangeReporterInputChannel) clearPrepared() {
	c.prepared = false
	c.preparedElementName = ""
	c.preparedElementAttrs = nil
}

// OpenDocument opens the policy's document and starts listening for what the
// policy and renderer drop.
func (c *htmlChangeReporterInputChannel) OpenDocument() {
	c.pendingDroppedText = c.pendingDroppedText[:0]
	c.lastOpenOutputName = optionalElementName{}
	c.clearPrepared()
	c.policy.OpenDocument()
	if source, ok := c.policy.(htmlChangeReporterDroppedTextSource); ok {
		source.reportDroppedTextTo(c)
	}
	if source, ok := c.policy.(htmlChangeReporterDiscardedAttributeSource); ok {
		source.reportDiscardedAttributesTo(c.output)
	}
	// The renderer decides on its own to drop literal content it cannot emit,
	// a tag it cannot write and an attribute it cannot write, so it has to
	// tell us; any other receiver keeps that to itself.  Bound once the
	// renderer has opened the document, which forgets any earlier listener,
	// and for this document only, so that a renderer reused without this
	// reporter does not go on reporting to it.
	c.output.listenForDrops(c)
}

// CloseDocument closes the policy's document and reports what it dropped.
func (c *htmlChangeReporterInputChannel) CloseDocument() {
	// Closing may flush and drop pending literal content, so listen until
	// the renderer is done.
	c.policy.CloseDocument()
	if source, ok := c.policy.(htmlChangeReporterDroppedTextSource); ok {
		source.reportDroppedTextTo(nil)
	}
	if source, ok := c.policy.(htmlChangeReporterDiscardedAttributeSource); ok {
		source.reportDiscardedAttributesTo(nil)
	}
	c.output.listenForDrops(nil)
	c.dispatchDroppedText()
	c.clearPrepared()
}

// OpenTag forwards a start tag to the policy and reports what it drops.
func (c *htmlChangeReporterInputChannel) OpenTag(elementName string, attrs []string) {
	c.openTagWithMode(elementName, attrs, htmlChangeReporterInputChannelOpenTagModeNormal)
}

func (c *htmlChangeReporterInputChannel) openTagWithoutOutput(elementName string, attrs []string) {
	c.openTagWithMode(elementName, attrs, htmlChangeReporterInputChannelOpenTagModeSuppress)
}

func (c *htmlChangeReporterInputChannel) openTagWithoutOutputWithInheritedTextGate(
	elementName string, attrs []string) {
	c.openTagWithMode(elementName, attrs,
		htmlChangeReporterInputChannelOpenTagModeSuppressInheritTextGate)
}

func (c *htmlChangeReporterInputChannel) openTagWithoutOutputOrContent(
	elementName string, attrs []string) {
	c.openTagWithMode(elementName, attrs,
		htmlChangeReporterInputChannelOpenTagModeSuppressSubtree)
}

func (c *htmlChangeReporterInputChannel) openTagWithSuppressedContent(
	elementName string, attrs []string) {
	c.openTagWithMode(elementName, attrs,
		htmlChangeReporterInputChannelOpenTagModeEmitSuppressSubtree)
}

func (c *htmlChangeReporterInputChannel) openTablePartWithInheritedTextGate(
	elementName string, attrs []string) {
	c.openTagWithMode(elementName, attrs,
		htmlChangeReporterInputChannelOpenTagModeInheritTextGate)
}

func (c *htmlChangeReporterInputChannel) isSuppressingOutputAndContent() bool {
	tablePolicy := c.pushedOutTablePolicy()
	return tablePolicy != nil && tablePolicy.isSuppressingOutputAndContent()
}

func (c *htmlChangeReporterInputChannel) isSuppressingText() bool {
	tablePolicy := c.pushedOutTablePolicy()
	return tablePolicy != nil && tablePolicy.isSuppressingText()
}

func (c *htmlChangeReporterInputChannel) openReopenedTable(attrs []string) {
	c.openTagWithMode("table", attrs, htmlChangeReporterInputChannelOpenTagModeReopenedTable)
}

func (c *htmlChangeReporterInputChannel) reopenedTableWasRenamed() bool {
	tablePolicy := c.pushedOutTablePolicy()
	return tablePolicy != nil && tablePolicy.reopenedTableWasRenamed()
}

// openTagWithMode forwards a start tag to the policy operation the mode names
// and reports what the policy and renderer drop.
func (c *htmlChangeReporterInputChannel) openTagWithMode(
	elementName string, attrs []string,
	mode htmlChangeReporterInputChannelOpenTagMode) {
	c.output.openedElementName = optionalElementName{}
	// The input attributes are copied before the policy runs: it removes
	// rejected attributes, and their values are wanted for the report.
	usesPreparedStart := mode != htmlChangeReporterInputChannelOpenTagModeReopenedTable &&
		c.prepared &&
		elementName == c.preparedElementName &&
		sameAttrList(attrs, c.preparedElementAttrs)
	// Balancing the prepared output name can insert or reopen elements before
	// the original input start is emitted.  Keep the prepared start's
	// attribute accounting across those nested events.
	var preparedAccounting *htmlChangeReporterOutputChannelAttributeAccounting
	if c.prepared && !usesPreparedStart {
		preparedAccounting = c.output.saveAttributeAccounting()
	}
	if !usesPreparedStart {
		c.output.expectAttributes(attrs)
	}
	switch mode {
	case htmlChangeReporterInputChannelOpenTagModeReopenedTable:
		tablePolicy := c.pushedOutTablePolicy()
		if tablePolicy == nil || !tablePolicy.supportsPushedOutTableOperations() {
			panic("Policy cannot safely reopen a table")
		}
		tablePolicy.openReopenedTable(attrs)
	case htmlChangeReporterInputChannelOpenTagModeSuppress,
		htmlChangeReporterInputChannelOpenTagModeSuppressInheritTextGate,
		htmlChangeReporterInputChannelOpenTagModeSuppressSubtree,
		htmlChangeReporterInputChannelOpenTagModeEmitSuppressSubtree,
		htmlChangeReporterInputChannelOpenTagModeInheritTextGate:
		tablePolicy := c.pushedOutTablePolicy()
		if tablePolicy == nil || !tablePolicy.supportsPushedOutTableOperations() {
			panic("Policy cannot suppress a table-structure tag")
		}
		switch mode {
		case htmlChangeReporterInputChannelOpenTagModeSuppressSubtree:
			tablePolicy.openTagWithoutOutputOrContent(elementName, attrs)
		case htmlChangeReporterInputChannelOpenTagModeEmitSuppressSubtree:
			tablePolicy.openTagWithSuppressedContent(elementName, attrs)
		case htmlChangeReporterInputChannelOpenTagModeInheritTextGate:
			tablePolicy.openTablePartWithInheritedTextGate(elementName, attrs)
		case htmlChangeReporterInputChannelOpenTagModeSuppressInheritTextGate:
			tablePolicy.openTagWithoutOutputWithInheritedTextGate(elementName, attrs)
		default:
			tablePolicy.openTagWithoutOutput(elementName, attrs)
		}
	default:
		c.policy.OpenTag(elementName, attrs)
	}

	// Gather the notification details to avoid any problems with the
	// listener re-entering the stream event receiver.  This shouldn't occur,
	// but if it does it will be a source of subtle confusing bugs.
	//
	// The tag survived if the policy opened anything in response and the
	// renderer wrote it.  Its name is not compared with the input name: an
	// ElementPolicy may rename an ordinary element, and that renamed element
	// was kept.  A synthetic table reopen is the exception: its policy result
	// is deliberately suppressed unless it remains a table, so it is reported
	// as discarded here.
	discarded := !c.output.openedElementName.valid
	c.lastOpenOutputName = c.output.openedElementName
	c.output.openedElementName = optionalElementName{}
	// Attributes go unreported with a tag the policy rejected: the tag report
	// covers them.  Not so when the policy allowed the element and dropped it
	// only because none of its attributes survived, or when the renderer
	// refused the tag the policy opened: rejecting them was the policy's
	// decision, and the tag went for another reason.
	attrsRejectedOnTheirOwn := !discarded || c.output.tagRefusedByRenderer
	if !attrsRejectedOnTheirOwn {
		skipPolicy, ok := c.policy.(htmlChangeReporterAttributelessSkipPolicy)
		attrsRejectedOnTheirOwn = ok && skipPolicy.skippedLastTagAsAttributeless()
	}
	var discardedAttrs []string
	if attrsRejectedOnTheirOwn {
		discardedAttrs = c.output.discardedAttributes()
	}
	nDiscarded := len(discardedAttrs) / 2
	c.output.clearExpectedAttributes()
	if usesPreparedStart {
		c.clearPrepared()
	}
	// Dispatch notifications to the listener under the name this channel
	// received, which is the canonical name the tag balancer forwards every
	// start tag under and reports its own drops under.
	if discarded {
		c.listener.DiscardedTag(c.context, elementName)
	}
	if nDiscarded != 0 {
		discardedAttrNames := make([]string, nDiscarded)
		for i := range discardedAttrNames {
			discardedAttrNames[i] = discardedAttrs[i*2]
		}
		c.listener.DiscardedAttributes(c.context, elementName, discardedAttrNames...)
		for i := 0; i < nDiscarded; i++ {
			c.listener.DiscardedAttribute(
				c.context, elementName, discardedAttrs[i*2], discardedAttrs[i*2+1])
		}
	}
	if preparedAccounting != nil {
		c.output.restoreAttributeAccounting(preparedAccounting)
	}
}

// CloseTag forwards an end tag to the policy and reports text it dropped.
func (c *htmlChangeReporterInputChannel) CloseTag(elementName string) {
	c.policy.CloseTag(elementName)
	c.dispatchDroppedText()
}

// Text forwards text to the policy and reports text it dropped.
func (c *htmlChangeReporterInputChannel) Text(textChunk string) {
	c.policy.Text(textChunk)
	c.dispatchDroppedText()
}

// dispatchDroppedText dispatches outside the policy call that decided to drop
// the text.
func (c *htmlChangeReporterInputChannel) dispatchDroppedText() {
	if len(c.pendingDroppedText) == 0 {
		return
	}
	dropped := slices.Clone(c.pendingDroppedText)
	clear(c.pendingDroppedText)
	c.pendingDroppedText = c.pendingDroppedText[:0]
	for i := 0; i < len(dropped); i += 2 {
		c.listener.DiscardedText(c.context, dropped[i], dropped[i+1])
	}
}

// htmlChangeReporterOutputChannel forwards to the renderer, and is one of the
// library's own decorators so that the policy can see the renderer behind it
// and know what it escapes.
type htmlChangeReporterOutputChannel struct {
	HTMLStreamEventReceiverWrapper
	// openedElementName is the name of the tag the policy has opened in
	// response to the tag being opened, absent while it has opened none.
	openedElementName optionalElementName
	// expectedAttrs are the attributes on the tag being opened, as original
	// name and value pairs.  A list rather than a map: a name repeated on one
	// tag is two attributes, and HTML forbids that, so the sanitizer keeps
	// the first and drops the rest.  Collapsing the copies here would leave
	// the surviving one accounting for all of them, and the drops would go
	// unreported.  The values ride along so that the drops can be reported
	// with them.
	expectedAttrs []string
	// rejectedAttrs marks the input pairs an attribute policy explicitly
	// rejected.
	rejectedAttrs []bool
	// emittedAttrs marks the input pairs accounted for by attributes the
	// policy emitted.
	emittedAttrs []bool
	// addedThenLeftOffAttrs are name and value pairs the policy added to the
	// tag, so that no input pair accounts for them, and the renderer then
	// left off.
	addedThenLeftOffAttrs []string
	// tagRefusedByRenderer is true if the renderer refused the tag the policy
	// opened.
	tagRefusedByRenderer bool
}

// htmlChangeReporterOutputChannelAttributeAccounting is the
// attribute-reporting state saved across a nested balancing event.
type htmlChangeReporterOutputChannelAttributeAccounting struct {
	expectedAttrs         []string
	rejectedAttrs         []bool
	emittedAttrs          []bool
	addedThenLeftOffAttrs []string
	tagRefusedByRenderer  bool
}

// newHTMLChangeReporterOutputChannel returns a channel that forwards to
// renderer.
func newHTMLChangeReporterOutputChannel(renderer HTMLStreamEventReceiver) *htmlChangeReporterOutputChannel {
	return &htmlChangeReporterOutputChannel{
		HTMLStreamEventReceiverWrapper: HTMLStreamEventReceiverWrapper{Underlying: renderer},
	}
}

// expectAttributes starts accounting for the attributes on one input start
// tag.
func (o *htmlChangeReporterOutputChannel) expectAttributes(attrs []string) {
	o.expectedAttrs = append(o.expectedAttrs[:0], attrs...)
	nPairs := len(attrs) / 2
	o.rejectedAttrs = append(o.rejectedAttrs[:0], make([]bool, nPairs)...)
	o.emittedAttrs = append(o.emittedAttrs[:0], make([]bool, nPairs)...)
	o.addedThenLeftOffAttrs = o.addedThenLeftOffAttrs[:0]
	o.tagRefusedByRenderer = false
}

// saveAttributeAccounting copies the attribute-reporting state.
func (o *htmlChangeReporterOutputChannel) saveAttributeAccounting() *htmlChangeReporterOutputChannelAttributeAccounting {
	return &htmlChangeReporterOutputChannelAttributeAccounting{
		expectedAttrs:         slices.Clone(o.expectedAttrs),
		rejectedAttrs:         slices.Clone(o.rejectedAttrs),
		emittedAttrs:          slices.Clone(o.emittedAttrs),
		addedThenLeftOffAttrs: slices.Clone(o.addedThenLeftOffAttrs),
		tagRefusedByRenderer:  o.tagRefusedByRenderer,
	}
}

// restoreAttributeAccounting puts back state saved by
// saveAttributeAccounting.
func (o *htmlChangeReporterOutputChannel) restoreAttributeAccounting(
	saved *htmlChangeReporterOutputChannelAttributeAccounting) {
	o.expectedAttrs = append(o.expectedAttrs[:0], saved.expectedAttrs...)
	o.rejectedAttrs = append(o.rejectedAttrs[:0], saved.rejectedAttrs...)
	o.emittedAttrs = append(o.emittedAttrs[:0], saved.emittedAttrs...)
	o.addedThenLeftOffAttrs = append(o.addedThenLeftOffAttrs[:0], saved.addedThenLeftOffAttrs...)
	o.tagRefusedByRenderer = saved.tagRefusedByRenderer
}

// refusedOpenedTag records that the renderer wrote no tag for the one the
// policy opened.
func (o *htmlChangeReporterOutputChannel) refusedOpenedTag() {
	o.openedElementName = optionalElementName{}
	o.tagRefusedByRenderer = true
}

// attributeLeftOff records that the renderer left an attribute off the tag it
// wrote.  The input copy that the policy's emitting it accounted for, if any,
// is discarded after all, with the value the author wrote; a pair the policy
// added is reported as the renderer received it.
func (o *htmlChangeReporterOutputChannel) attributeLeftOff(name, value string) {
	for i := range o.emittedAttrs {
		if o.emittedAttrs[i] && name == o.expectedAttrs[i*2] {
			o.emittedAttrs[i] = false
			return
		}
	}
	o.addedThenLeftOffAttrs = append(o.addedThenLeftOffAttrs, name, value)
}

// discardedAttribute records an input pair that an attribute policy rejected.
func (o *htmlChangeReporterOutputChannel) discardedAttribute(name, value string) {
	for i := range o.rejectedAttrs {
		pair := i * 2
		if !o.rejectedAttrs[i] && !o.emittedAttrs[i] &&
			name == o.expectedAttrs[pair] && value == o.expectedAttrs[pair+1] {
			o.rejectedAttrs[i] = true
			return
		}
	}
}

// discardedAttributes returns the original pairs not accounted for by emitted
// attributes, then any pairs the policy added and the renderer left off.
func (o *htmlChangeReporterOutputChannel) discardedAttributes() []string {
	var discarded []string
	for i, emitted := range o.emittedAttrs {
		if !emitted {
			discarded = append(discarded, o.expectedAttrs[i*2], o.expectedAttrs[i*2+1])
		}
	}
	return append(discarded, o.addedThenLeftOffAttrs...)
}

// clearExpectedAttributes ends the accounting for a start tag.
func (o *htmlChangeReporterOutputChannel) clearExpectedAttributes() {
	o.expectedAttrs = o.expectedAttrs[:0]
	o.rejectedAttrs = o.rejectedAttrs[:0]
	o.emittedAttrs = o.emittedAttrs[:0]
	o.addedThenLeftOffAttrs = o.addedThenLeftOffAttrs[:0]
	o.tagRefusedByRenderer = false
}

// listenForDrops has the renderer report what it drops to listener, or to
// nobody when nil, if it is one that can.  The library's own decorator,
// which a postprocessor or a logging wrapper is likely to extend, is seen
// through.
func (o *htmlChangeReporterOutputChannel) listenForDrops(listener htmlStreamRendererDropListener) {
	if renderer, ok := receiverBehindWrappers(o.Underlying).(*HTMLStreamRenderer); ok {
		renderer.reportDropsTo(listener)
	}
}

// OpenTag accounts for the attributes the policy emits and forwards the tag
// to the renderer.
func (o *htmlChangeReporterOutputChannel) OpenTag(elementName string, attrs []string) {
	o.openedElementName = someElementName(elementName)
	for i := 0; i < len(attrs); i += 2 {
		// Accounts for one copy of the name, so repeats the policy dropped
		// stay behind to be reported.
		o.markFirstEmitted(attrs[i])
	}
	o.Underlying.OpenTag(elementName, attrs)
}

// markFirstEmitted accounts for the first eligible input copy of an emitted
// name.
func (o *htmlChangeReporterOutputChannel) markFirstEmitted(name string) {
	for i := range o.emittedAttrs {
		if !o.rejectedAttrs[i] && !o.emittedAttrs[i] && name == o.expectedAttrs[i*2] {
			o.emittedAttrs[i] = true
			return
		}
	}
}

// htmlStreamEventReceiverWrapperType is the type a decorator embeds to be
// one of the library's own.
var htmlStreamEventReceiverWrapperType = reflect.TypeOf(HTMLStreamEventReceiverWrapper{})

// receiverBehindWrappers returns the receiver that r forwards to through any
// number of the library's own decorators: values that are, or embed,
// HTMLStreamEventReceiverWrapper.
func receiverBehindWrappers(r HTMLStreamEventReceiver) HTMLStreamEventReceiver {
	for {
		underlying, ok := wrappedReceiver(r)
		if !ok {
			return r
		}
		r = underlying
	}
}

// wrappedReceiver returns the receiver that r forwards to, and false if r is
// not one of the library's own decorators.
func wrappedReceiver(r HTMLStreamEventReceiver) (HTMLStreamEventReceiver, bool) {
	switch w := r.(type) {
	case nil:
		return nil, false
	case HTMLStreamEventReceiverWrapper:
		return w.Underlying, true
	case *HTMLStreamEventReceiverWrapper:
		return w.Underlying, true
	case *htmlChangeReporterOutputChannel:
		return w.Underlying, true
	}
	v := reflect.ValueOf(r)
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil, false
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil, false
	}
	field, ok := v.Type().FieldByName(htmlStreamEventReceiverWrapperType.Name())
	if !ok || !field.Anonymous {
		return nil, false
	}
	wrapper, err := v.FieldByIndexErr(field.Index)
	if err != nil {
		return nil, false
	}
	if wrapper.Kind() == reflect.Pointer {
		if wrapper.IsNil() {
			return nil, false
		}
		wrapper = wrapper.Elem()
	}
	if wrapper.Type() != htmlStreamEventReceiverWrapperType {
		return nil, false
	}
	underlying := wrapper.FieldByName("Underlying")
	if !underlying.CanInterface() {
		return nil, false
	}
	receiver, _ := underlying.Interface().(HTMLStreamEventReceiver)
	return receiver, true
}
