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

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/HtmlChangeListener.java.

package sanitizer

// HTMLChangeListener receives events when an HTML tag, attribute, or text is
// discarded.  This can be hooked into an intrusion detection system to alert
// code when suspicious HTML passes through the sanitizer.
//
// Each method receives the context value that was passed along with the
// listener, for example to PolicyFactory.SanitizeWithListener.
//
// Note: If a string sanitizes with no change notifications, it is not the
// case that the input string is necessarily safe to use.  Only use the
// output of the sanitizer.  The sanitizer ensures that the output is in a
// sub-set of HTML that commonly used HTML parsers will agree on the meaning
// of, but the absence of notifications does not mean that the input is in
// such a sub-set, only that it does not contain structural features that
// were removed.
//
// Listeners that need neither attribute values nor discarded text can embed
// NopHTMLChangeListener to get no-op DiscardedAttribute and
// DiscardedText methods.
type HTMLChangeListener interface {
	// DiscardedTag is called when a tag is discarded from the input, by the
	// policy, by the tag balancer, or by the renderer.  The tag balancer
	// drops a start tag that would nest the output past its limit, and a
	// form start tag a browser ignores because its form element pointer is
	// already set.  The renderer writes no tag whose name is not one HTML
	// allows, which an ElementPolicy can produce by renaming, and none that
	// arrives inside literal content it is writing, such as the tags inside
	// an element a policy renamed into a style.  Its drops are reported under
	// the same conditions as its dropped text: see DiscardedText.
	//
	// elementName is the tag's name as a policy is asked about it: lower case
	// unless it is a namespaced or mixed-case SVG or MathML name, however the
	// input or a pre-processor spelled it.  A tag the renderer drops is named
	// as the policy emitted it.
	DiscardedTag(context any, elementName string)

	// DiscardedAttributes is called when attributes are discarded from a tag
	// that the policy allowed.
	//
	// Usually the tag itself survives without them.  When every attribute is
	// rejected and the element is one the policy skips when it has none, the
	// default set DefaultSkipIfEmpty unless
	// HTMLPolicyBuilder.AllowWithoutAttributes or
	// HTMLPolicyBuilder.DisallowWithoutAttributes said otherwise, the tag is
	// discarded as a consequence: DiscardedTag reports the tag, and this
	// method still reports the attributes, since rejecting them is what the
	// policy did.  Attributes on a tag that the policy did not allow are not
	// reported; DiscardedTag covers the whole tag.  An attribute the renderer
	// leaves off a tag it writes, because its name is not one HTML allows, is
	// reported here too, under the same conditions as the renderer's dropped
	// text: see DiscardedText.
	//
	// A repeated attribute name counts once per dropped copy.
	DiscardedAttributes(context any, tagName string, attributeNames ...string)

	// DiscardedAttribute is called once for each attribute named in a
	// DiscardedAttributes report, after that report, with the value the
	// attribute had in the input.  The value is as the author wrote it, after
	// character references have been decoded, and has not been vetted by any
	// policy, so treat it as untrusted.
	DiscardedAttribute(context any, tagName, attributeName, attributeValue string)

	// DiscardedText is called when text is discarded from an element the
	// policy kept.  The policy removes tag-shaped ranges from literal content
	// such as <style>x<div>y</div></style>, because a browser would receive
	// those ranges as markup without their passing through element and
	// attribute policies.  The renderer may instead drop all the remaining
	// content when a browser would read it differently, such as a --> with no
	// <!-- before it.
	//
	// Text inside a discarded element is not reported here; the DiscardedTag
	// report covers it.  Policy drops are reported with any output receiver.
	// Renderer drops are reported only with an HTMLStreamRenderer, seen
	// through any HTMLStreamEventReceiverWrapper around it;
	// PolicyFactory.SanitizeWithListener always uses one.
	//
	// One input text chunk may result in multiple calls.  Callers must not
	// rely on the boundaries between calls.  Treat the text as untrusted; it
	// may contain attacker-controlled markup.
	//
	// elementName is the name under which the policy kept the element, and
	// text is the content that was dropped.
	DiscardedText(context any, elementName, text string)
}

// NopHTMLChangeListener provides the default, no-op implementations of
// HTMLChangeListener.DiscardedAttribute and HTMLChangeListener.DiscardedText.
// Embed it in a listener that does not need attribute values or discarded
// text.
type NopHTMLChangeListener struct{}

// DiscardedAttribute does nothing.  Listeners that do not need values need not
// override this.
func (NopHTMLChangeListener) DiscardedAttribute(context any, tagName, attributeName, attributeValue string) {
}

// DiscardedText does nothing.  Listeners that do not need text need not
// override this.
func (NopHTMLChangeListener) DiscardedText(context any, elementName, text string) {
}
