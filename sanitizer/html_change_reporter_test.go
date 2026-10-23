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

// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/HtmlChangeReporterTest.java.

package sanitizer

import (
	"slices"
	"strings"
	"testing"
)

// hcrtContext is an opaque test value compared by identity.
type hcrtContext struct {
	// name keeps the type from having size zero, so that distinct values
	// have distinct addresses.
	name string
}

func TestChangeReporting(t *testing.T) {
	result := hcrtSanitize(t,
		Formatting,
		"<textarea>Hello</textarea>,<b onclick=alert(42)>World</B>!"+
			"<Script type=text/javascript>doEvil()</script><PLAINTEXT>")

	hstAssertEqual(t, "Hello,<b>World</b>!", result.html)
	hstAssertEqual(t, "<textarea> <b onclick> <script> <plaintext> ", result.log)
}

// TestDuplicateAttributesAreReported: HTML forbids repeating an attribute
// name on one tag, so the sanitizer keeps the first and drops the rest.
// Those drops used to be invisible to the listener because the surviving
// attribute left the name in the output.
func TestDuplicateAttributesAreReported(t *testing.T) {
	result := hcrtSanitize(t,
		Links,
		"<a href=\"https://www.example.org/\" HREF=\"javascript:alert(1)\">"+
			"legal link</a>")

	hstAssertEqual(t,
		"<a href=\"https://www.example.org/\" rel=\"nofollow\">legal link</a>",
		result.html)
	hstAssertEqual(t, "<a href> ", result.log)
}

func TestDuplicateAttributesReportedOncePerExtraCopy(t *testing.T) {
	result := hcrtSanitize(t,
		Links,
		"<a href=\"https://www.example.org/\" href=\"/one\" href=\"/two\">"+
			"link</a>")

	hstAssertEqual(t,
		"<a href=\"https://www.example.org/\" rel=\"nofollow\">link</a>",
		result.html)
	hstAssertEqual(t, "<a href href> ", result.log)
}

// TestRejectedAndDuplicateAttributesReportedTogether: attributes the policy
// rejects and duplicates arrive in one report.
func TestRejectedAndDuplicateAttributesReportedTogether(t *testing.T) {
	result := hcrtSanitize(t,
		Links,
		"<a onclick=alert(42) href=\"https://www.example.org/\" href=\"/x\">"+
			"link</a>")

	hstAssertEqual(t,
		"<a href=\"https://www.example.org/\" rel=\"nofollow\">link</a>",
		result.html)
	hstAssertEqual(t, "<a onclick href> ", result.log)
}

// TestDuplicateAttributesOnADiscardedTagReportOnlyTheTag: when the whole tag
// goes, it is reported as a discarded tag and its attributes are not
// reported separately, duplicates included.
func TestDuplicateAttributesOnADiscardedTagReportOnlyTheTag(t *testing.T) {
	result := hcrtSanitize(t,
		Formatting,
		"<script src=\"a.js\" SRC=\"b.js\">doEvil()</script>")

	hstAssertEqual(t, "", result.html)
	hstAssertEqual(t, "<script> ", result.log)
}

// TestRepeatsThePolicyKeepsAreNotReported: the report is a diff against what
// the policy actually emitted, not a prediction from the input, so a policy
// that keeps a repeated attribute is not reported as having dropped one.
func TestRepeatsThePolicyKeepsAreNotReported(t *testing.T) {
	testContext := &hcrtContext{}
	var out, log strings.Builder
	renderer := NewHTMLStreamRendererToBuilder(&out, DoNothing[string])
	hcr := NewHTMLChangeReporter(
		renderer, hcrtLoggingListener(t, testContext, &log), testContext)
	// A policy that forwards every event through untouched, deduping
	// nothing.
	hcr.SetPolicy(hcrtForwardingPolicy{hcr.GetWrappedRenderer()})

	Sanitize("<b id=one id=two>x</b>", hcr.GetWrappedPolicy(), nil)

	hstAssertEqual(t, "<b id=\"one\" id=\"two\">x</b>", out.String())
	hstAssertEqual(t, "", log.String())
}

// TestPolicyDecoratorDoesNotClaimPushedOutTableOperations: a public policy
// decorator cannot implement the package-private feedback.
func TestPolicyDecoratorDoesNotClaimPushedOutTableOperations(t *testing.T) {
	testContext := &hcrtContext{}
	var out, log strings.Builder
	renderer := NewHTMLStreamRendererToBuilder(&out, DoNothing[string])
	hcr := NewHTMLChangeReporter(
		renderer, hcrtLoggingListener(t, testContext, &log), testContext)
	delegate := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tbody", "tr", "td", "div")).
		Apply(hcr.GetWrappedRenderer())
	hcr.SetPolicy(hcrtForwardingPolicy{delegate})

	Sanitize(
		"<table><div>x<tr><td>y</td></tr></table>tail",
		hcr.GetWrappedPolicy(), nil)

	hstAssertEqual(t,
		"<table></table><div>x</div>"+
			"<table><tbody><tr><td>y</td></tr></tbody></table>tail",
		out.String())
	hstAssertEqual(t, "", log.String())
}

// TestRenamedElementIsNotReportedAsDiscarded: ElementPolicy.Apply may return
// another element name, and the reporter used to decide whether a tag
// survived by comparing names, so a renamed element was reported as
// discarded and, because a discarded tag's attributes are not reported, its
// attribute drops went unreported too (#435).
func TestRenamedElementIsNotReportedAsDiscarded(t *testing.T) {
	result := hcrtSanitize(t,
		hcrtRenamingSpanToDiv(t), "<span id=a id=b>hi</span>")

	hstAssertEqual(t, "<div id=\"a\">hi</div>", result.html)
	hstAssertEqual(t, "<span id> ", result.log)
}

// TestRejectedAttributesOnARenamedElementAreReported: attribute reports on a
// renamed element carry the input element name.
func TestRejectedAttributesOnARenamedElementAreReported(t *testing.T) {
	result := hcrtSanitize(t,
		hcrtRenamingSpanToDiv(t), "<span id=a onclick=alert(1)>hi</span>")

	hstAssertEqual(t, "<div id=\"a\">hi</div>", result.html)
	hstAssertEqual(t, "<span onclick> ", result.log)
}

func TestRenamedElementWithNothingDroppedReportsNothing(t *testing.T) {
	result := hcrtSanitize(t, hcrtRenamingSpanToDiv(t), "<span id=a>hi</span>")

	hstAssertEqual(t, "<div id=\"a\">hi</div>", result.html)
	hstAssertEqual(t, "", result.log)
}

// TestDroppedFormattingMarkerDoesNotProtectLinksWithAReporter: reporter
// indirection preserves output-aware nested-link balancing.
func TestDroppedFormattingMarkerDoesNotProtectLinksWithAReporter(t *testing.T) {
	result := hcrtSanitize(t,
		Links,
		"<a href=u><marquee><a href=v>x</a></marquee>y</a>")

	hstAssertEqual(t,
		"<a href=\"u\" rel=\"nofollow\"></a>"+
			"<a href=\"v\" rel=\"nofollow\">x</a>y",
		result.html)
	hstAssertEqual(t, "<marquee> ", result.log)
}

// hcrtRenamingSpanToDiv renames span to div.  div is allowed as well so that
// text inside the renamed element is kept: the policy decides whether an
// element may hold text by the name it is emitted under.
func hcrtRenamingSpanToDiv(t testing.TB) *PolicyFactory {
	t.Helper()
	return hstFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(hstRenamingPolicy("div"), "span").
		AllowElements("div").
		AllowAttributes("id").OnElements("span"))
}

// TestAttributesRejectedFromAnElementThenSkippedAreReported: an element the
// policy allows but skips when attribute-less goes when every attribute on
// it is rejected.  The attributes are still reported: rejecting them was the
// policy's decision, and the tag went as a consequence (#447).  Each is also
// reported with its value (#243).
func TestAttributesRejectedFromAnElementThenSkippedAreReported(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("span").
		AllowAttributes("id").OnElements("span"))
	result := hcrtSanitizeVerbose(t, p, "<span onclick=x>hi</span>")

	hstAssertEqual(t, "hi", result.html)
	hstAssertEqual(t, "<span> <span onclick> span.onclick=\"x\" ", result.log)
}

// TestRejectedURLOnASkippedLinkIsReportedWithItsValue: the
// intrusion-detection case from #447: the rejected URL is the signal.
func TestRejectedURLOnASkippedLinkIsReportedWithItsValue(t *testing.T) {
	result := hcrtSanitizeVerbose(t,
		Links, "<a href=\"javascript:alert(1)\">x</a>")

	hstAssertEqual(t, "x", result.html)
	hstAssertEqual(t,
		"<a> <a href> a.href=\"javascript:alert(1)\" ", result.log)
}

// TestAttributesOnADisallowedElementAreNotReported: attributes on an element
// the policy does not allow go with the tag.
func TestAttributesOnADisallowedElementAreNotReported(t *testing.T) {
	result := hcrtSanitizeVerbose(t,
		Formatting, "<div onclick=x>hi</div>")

	hstAssertEqual(t, "hi", result.html)
	hstAssertEqual(t, "<div> ", result.log)
}

// TestSkippedAttributelessElementReportsOnlyTheTag: nothing to report but
// the tag when it had no attributes to begin with.
func TestSkippedAttributelessElementReportsOnlyTheTag(t *testing.T) {
	result := hcrtSanitizeVerbose(t, Links, "<a>x</a>")

	hstAssertEqual(t, "x", result.html)
	hstAssertEqual(t, "<a> ", result.log)
}

// TestRejectedAttributesOnAKeptElementAreReportedWithValues: a kept element
// reports as before, and now with the values.
func TestRejectedAttributesOnAKeptElementAreReportedWithValues(t *testing.T) {
	result := hcrtSanitizeVerbose(t,
		Formatting, "<b onclick=\"alert(42)\" title=t>x</b>")

	hstAssertEqual(t, "<b>x</b>", result.html)
	hstAssertEqual(t,
		"<b onclick title> b.onclick=\"alert(42)\" b.title=\"t\" ",
		result.log)
}

// TestEachDroppedCopyOfARepeatedAttributeReportsItsOwnValue: each dropped
// copy of a repeated attribute carries its own value.
func TestEachDroppedCopyOfARepeatedAttributeReportsItsOwnValue(t *testing.T) {
	result := hcrtSanitizeVerbose(t,
		Links,
		"<a href=\"https://www.example.org/\" href=\"/one\" href=\"/two\">"+
			"link</a>")

	hstAssertEqual(t,
		"<a href=\"https://www.example.org/\" rel=\"nofollow\">link</a>",
		result.html)
	hstAssertEqual(t,
		"<a href href> a.href=\"/one\" a.href=\"/two\" ", result.log)
}

// TestRejectedDuplicateReportsTheRejectedValue: a rejected first copy must
// not borrow a surviving duplicate's value.
func TestRejectedDuplicateReportsTheRejectedValue(t *testing.T) {
	result := hcrtSanitizeVerbose(t,
		Links,
		"<a href=\"javascript:alert(1)\" "+
			"href=\"https://safe.example/\">link</a>")

	hstAssertEqual(t,
		"<a href=\"https://safe.example/\" rel=\"nofollow\">link</a>",
		result.html)
	hstAssertEqual(t,
		"<a href> a.href=\"javascript:alert(1)\" ", result.log)
}

// TestReportedValueIsTheDecodedInputValue: the value reported is the input
// value after character references.
func TestReportedValueIsTheDecodedInputValue(t *testing.T) {
	result := hcrtSanitizeVerbose(t,
		Formatting, "<b onclick=\"a&amp;b&lt;c\">x</b>")

	hstAssertEqual(t, "<b>x</b>", result.html)
	hstAssertEqual(t, "<b onclick> b.onclick=\"a&b<c\" ", result.log)
}

// TestARewrittenAttributeIsNotReported: an attribute the policy rewrote was
// kept, so nothing is reported.
func TestARewrittenAttributeIsNotReported(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a").
		AllowAttributes("href").
		Matching(AttributePolicyFunc(func(element, attribute, url string) (string, bool) {
			return "https://example.com/go?u=" + url, true
		})).
		OnElements("a").
		AllowURLProtocols("https"))
	result := hcrtSanitizeVerbose(t, p, "<a href=\"x\">l</a>")

	hstAssertEqual(t,
		"<a href=\"https://example.com/go?u&#61;x\">l</a>", result.html)
	hstAssertEqual(t, "", result.log)
}

// TestUnrenderableScriptContentIsReported: the renderer drops the content of
// a script or style element that it cannot emit without a browser reading it
// differently, such as a --> with no comment open.  That loss happens
// downstream of the policy and used to be invisible to the listener (#155,
// from #153).
func TestUnrenderableScriptContentIsReported(t *testing.T) {
	result := hcrtSanitizeVerbose(t,
		hcrtScriptAndStyleWithText(t), "<script>x --> y</script>")

	hstAssertEqual(t, "<script></script>", result.html)
	hstAssertEqual(t, "script{x --> y} ", result.log)
}

// TestUnrenderableStyleContentIsReported: a comment opened and never closed
// is the other unrenderable shape.
func TestUnrenderableStyleContentIsReported(t *testing.T) {
	result := hcrtSanitizeVerbose(t,
		hcrtScriptAndStyleWithText(t), "<style>a{} <!-- b > c</style>")

	hstAssertEqual(t, "<style></style>", result.html)
	hstAssertEqual(t, "style{a{} <!-- b > c} ", result.log)
}

// TestRenderableScriptContentIsNotReported: content the renderer can emit is
// not reported.
func TestRenderableScriptContentIsNotReported(t *testing.T) {
	result := hcrtSanitizeVerbose(t,
		hcrtScriptAndStyleWithText(t), "<script><!-- x --></script>")

	hstAssertEqual(t, "<script><!-- x --></script>", result.html)
	hstAssertEqual(t, "", result.log)
}

// TestTagRemovedFromKeptLiteralContentIsReportedAsText: a tag in kept
// literal content reaches the policy as text, so the policy's removal of it
// must use the text channel rather than the tag channel.  Issue #468.
func TestTagRemovedFromKeptLiteralContentIsReportedAsText(t *testing.T) {
	result := hcrtSanitizeVerbose(t,
		hcrtScriptAndStyleWithText(t),
		"<style>.x{}<div id=\"evil\">XSS?</div>y{}</style>")

	hstAssertEqual(t, "<style>.x{}y{}</style>", result.html)
	hstAssertEqual(t, "style{<div id=\"evil\">XSS?</div>} ", result.log)
}

// TestPolicyReportsSeparateLiteralTextDropsExactly: each report contains only
// the exact input range the policy removed.
func TestPolicyReportsSeparateLiteralTextDropsExactly(t *testing.T) {
	result := hcrtSanitizeVerbose(t,
		hcrtScriptAndStyleWithText(t),
		"<style>a<div>x</div>b</noscript>c</style>")

	hstAssertEqual(t, "<style>abc</style>", result.html)
	hstAssertEqual(t,
		"style{<div>x</div>} style{</noscript>} ", result.log)
}

// TestPolicyReportsLiteralTextBackstopDropsExactly: the filter also reports
// brackets removed to prevent assembled tags.
func TestPolicyReportsLiteralTextBackstopDropsExactly(t *testing.T) {
	result := hcrtSanitizeVerbose(t,
		hcrtScriptAndStyleWithText(t),
		"<style>a<</noscript>b<</style>")

	hstAssertEqual(t, "<style>ab</style>", result.html)
	hstAssertEqual(t, "style{<</noscript>} style{<} ", result.log)
}

// TestPolicyReportsAllAdjacentBracketsRemovedWithATag: every adjacent
// bracket removed with a tag belongs to the same report.
func TestPolicyReportsAllAdjacentBracketsRemovedWithATag(t *testing.T) {
	result := hcrtSanitizeVerbose(t,
		hcrtScriptAndStyleWithText(t), "<style><<<b>payload</style>")

	hstAssertEqual(t, "<style>payload</style>", result.html)
	hstAssertEqual(t, "style{<<<b>} ", result.log)
}

// TestPolicyAndRendererTextDropsAreBothReported: policy and renderer drops
// are both reported, without overlap.
func TestPolicyAndRendererTextDropsAreBothReported(t *testing.T) {
	result := hcrtSanitizeVerbose(t,
		hcrtScriptAndStyleWithText(t),
		"<style>a<div>x</div>-->b</style>")

	hstAssertEqual(t, "<style></style>", result.html)
	hstAssertEqual(t, "style{<div>x</div>} style{a-->b} ", result.log)
}

// hcrtRecoloringWrapper is a postprocessor that rewrites red to blue in
// text.
type hcrtRecoloringWrapper struct{ HTMLStreamEventReceiverWrapper }

func (w hcrtRecoloringWrapper) Text(text string) {
	w.Underlying.Text(strings.ReplaceAll(text, "red", "blue"))
}

// TestPostprocessorTextRewriteIsNotReported: a postprocessor rewrite is not a
// policy rejection and is not reported.
func TestPostprocessorTextRewriteIsNotReported(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("style").
		AllowTextIn("style").
		WithPostprocessor(HTMLStreamEventProcessorFunc(
			func(r HTMLStreamEventReceiver) HTMLStreamEventReceiver {
				return hcrtRecoloringWrapper{HTMLStreamEventReceiverWrapper{Underlying: r}}
			})))
	result := hcrtSanitizeVerbose(t, policy, "<style>.x{color:red}</style>")

	hstAssertEqual(t, "<style>.x{color:blue}</style>", result.html)
	hstAssertEqual(t, "", result.log)
}

// hcrtDivDroppingWrapper is a postprocessor that drops div tags.
type hcrtDivDroppingWrapper struct{ HTMLStreamEventReceiverWrapper }

func (w hcrtDivDroppingWrapper) OpenTag(elementName string, attrs []string) {
	if elementName != "div" {
		w.Underlying.OpenTag(elementName, attrs)
	}
}

func (w hcrtDivDroppingWrapper) CloseTag(elementName string) {
	if elementName != "div" {
		w.Underlying.CloseTag(elementName)
	}
}

// TestListenerDoesNotChangeOutputBehindAPostprocessor: the balancer asks this
// channel what the policy emitted, and the channel used to answer from what
// reached the renderer.  Behind a postprocessor that drops an element the
// two differ, so merely attaching a listener changed the sanitized output.
// An audit listener must never do that.
func TestListenerDoesNotChangeOutputBehindAPostprocessor(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(
			"table", "colgroup", "col", "ul", "li", "div", "textarea", "tr",
			"td").
		WithPostprocessor(HTMLStreamEventProcessorFunc(
			func(r HTMLStreamEventReceiver) HTMLStreamEventReceiver {
				return hcrtDivDroppingWrapper{HTMLStreamEventReceiverWrapper{Underlying: r}}
			})))
	input := "<table><col><li><div></tr><textarea><foreignObject>"
	plain := policy.Sanitize(input)
	result := hcrtSanitizeVerbose(t, policy, input)

	hstAssertEqual(t, plain, result.html)
}

// TestFormStartIgnoredForTheFormPointerIsReported: a form start the balancer
// ignores because the form element pointer is already set never reaches the
// policy, so, as for a tag dropped at the nesting limit, the balancer
// reports it here itself.  It used to vanish without a notification.
func TestFormStartIgnoredForTheFormPointerIsReported(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("form").
		AllowAttributes("id").OnElements("form"))
	result := hcrtSanitize(t, policy, "<form id=a><form id=b>x</form></form>")

	hstAssertEqual(t, "<form id=\"a\">x</form>", result.html)
	hstAssertEqual(t, "<form> ", result.log)
}

// TestPolicyDropUsesAdjustedLiteralElementName: the reported container is
// the literal name emitted by an element policy.
func TestPolicyDropUsesAdjustedLiteralElementName(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(hstRenamingPolicy("style"), "div").
		AllowTextIn("style"))
	result := hcrtSanitizeVerbose(t,
		policy, "<div>a&lt;img onerror=alert(1)&gt;b</div>")

	hstAssertEqual(t, "<style>ab</style>", result.html)
	hstAssertEqual(t, "style{<img onerror=alert(1)>} ", result.log)
}

// hcrtForeignReceiver returns a receiver of some other kind than the
// library's own, which forwards to renderer but cannot be seen through.
func hcrtForeignReceiver(renderer *HTMLStreamRenderer) HTMLStreamEventReceiver {
	return &hstReceiverFuncs{
		openDocument:  renderer.OpenDocument,
		closeDocument: renderer.CloseDocument,
		openTag:       renderer.OpenTag,
		closeTag:      renderer.CloseTag,
		text:          renderer.Text,
	}
}

// TestPolicyDroppedTextReachesListenerWithAForeignReceiver: policy-side
// drops do not depend on HTMLStreamRenderer's callback.
func TestPolicyDroppedTextReachesListenerWithAForeignReceiver(t *testing.T) {
	var dropped, tags []string
	listener := &hcrtTextAndTagCollector{dropped: &dropped, tags: &tags}
	var out strings.Builder
	renderer := NewHTMLStreamRendererToBuilder(&out, DoNothing[string])
	foreign := hcrtForeignReceiver(renderer)

	Sanitize(
		"<style>a<div>x</div>b</style>",
		hcrtScriptAndStyleWithText(t).ApplyWithListener(foreign, listener, nil), nil)

	hstAssertEqual(t, "<style>ab</style>", out.String())
	hcrtAssertStrings(t, []string{"style:<div>x</div>"}, dropped)
}

// hcrtPlainWrapper forwards everything; only its type differs from the
// renderer's.
type hcrtPlainWrapper struct{ HTMLStreamEventReceiverWrapper }

// TestDroppedTextReachesTheListenerOnlyThroughTheRenderer: the convenience
// method renders with HTMLStreamRenderer, so dropped content reaches the
// listener, as it does through the library's own receiver wrapper around
// one.  A sanitizer built on some other receiver has no renderer to hear
// from and reports tags and attributes only.
func TestDroppedTextReachesTheListenerOnlyThroughTheRenderer(t *testing.T) {
	var dropped, tags []string
	listener := &hcrtTextAndTagCollector{dropped: &dropped, tags: &tags}
	p := hcrtScriptAndStyleWithText(t)
	html := "<script>x --> y</script><b>z</b>"

	hstAssertEqual(t, "<script></script>z", p.SanitizeWithListener(html, listener, nil))
	hcrtAssertStrings(t, []string{"script:x --> y"}, dropped)
	hcrtAssertStrings(t, []string{"b"}, tags)

	// Through the library's wrapper, which a postprocessor would extend.
	dropped = nil
	tags = nil
	var out strings.Builder
	wrapped := hcrtPlainWrapper{HTMLStreamEventReceiverWrapper{
		Underlying: NewHTMLStreamRendererToBuilder(&out, DoNothing[string]),
	}}
	Sanitize(html, p.ApplyWithListener(wrapped, listener, nil), nil)

	hstAssertEqual(t, "<script></script>z", out.String())
	hcrtAssertStrings(t, []string{"script:x --> y"}, dropped)
	hcrtAssertStrings(t, []string{"b"}, tags)

	// Through a receiver of some other kind, which cannot be seen through.
	dropped = nil
	tags = nil
	var out2 strings.Builder
	renderer := NewHTMLStreamRendererToBuilder(&out2, DoNothing[string])
	foreign := hcrtForeignReceiver(renderer)
	Sanitize(html, p.ApplyWithListener(foreign, listener, nil), nil)

	hstAssertEqual(t, "<script></script>z", out2.String())
	hcrtAssertStrings(t, nil, dropped)
	hcrtAssertStrings(t, []string{"b"}, tags)
}

// TestARenderersNextDocumentDoesNotReportToTheLastReporter: a reporter
// listens to the renderer for one document.  The renderer, reused for
// another document without that reporter, must not go on reporting to it
// under the old context.
func TestARenderersNextDocumentDoesNotReportToTheLastReporter(t *testing.T) {
	var dropped, tags []string
	listener := &hcrtTextAndTagCollector{dropped: &dropped, tags: &tags}
	p := hcrtScriptAndStyleWithText(t)
	var out strings.Builder
	renderer := NewHTMLStreamRendererToBuilder(&out, DoNothing[string])
	html := "<script>x --> y</script>"

	Sanitize(html, p.ApplyWithListener(renderer, listener, nil), nil)
	hcrtAssertStrings(t, []string{"script:x --> y"}, dropped)

	dropped = nil
	Sanitize(html, p.Apply(renderer), nil)
	hstAssertEqual(t, "<script></script><script></script>", out.String())
	hcrtAssertStrings(t, nil, dropped)
}

// hcrtTextAndTagCollector collects dropped text as element:text and
// discarded tags.
type hcrtTextAndTagCollector struct {
	NopHTMLChangeListener
	dropped, tags *[]string
}

func (c *hcrtTextAndTagCollector) DiscardedTag(context any, elementName string) {
	*c.tags = append(*c.tags, elementName)
}

func (c *hcrtTextAndTagCollector) DiscardedAttributes(
	context any, tagName string, attributeNames ...string) {
	// Not under test.
}

func (c *hcrtTextAndTagCollector) DiscardedText(context any, elementName, text string) {
	*c.dropped = append(*c.dropped, elementName+":"+text)
}

// hcrtAssertStrings fails the test unless got holds the strings in want, in
// order.
func hcrtAssertStrings(t testing.TB, want, got []string) {
	t.Helper()
	if !slices.Equal(want, got) {
		t.Errorf("want %q\ngot  %q", want, got)
	}
}

// hcrtScriptAndStyleWithText keeps script and style with their content, as a
// template host might.
func hcrtScriptAndStyleWithText(t testing.TB) *PolicyFactory {
	t.Helper()
	return hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("script", "style").
		AllowTextIn("script", "style"))
}

// hcrtResult is the sanitized HTML and the log of what the listener was told
// about it.
type hcrtResult struct {
	html string
	log  string
}

// hcrtSanitize sanitizes html under policy, recording every listener
// notification.
func hcrtSanitize(t testing.TB, policy *PolicyFactory, html string) hcrtResult {
	t.Helper()
	return hcrtSanitizeWith(t, policy, html, false)
}

// TestTagRenamedToAnInvalidNameIsReported: the renderer writes no tag whose
// name is not one HTML allows, which an element policy can produce by
// renaming (#469).  The policy had opened the tag, so the reporter counted it
// as kept and the listener heard nothing.  The attributes the policy rejected
// on it were its own decisions and are still reported, as for a tag skipped
// for having none.
func TestTagRenamedToAnInvalidNameIsReported(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(hstRenamingPolicy("a@b"), "b").
		AllowElements("p"))
	result := hcrtSanitizeVerbose(t, policy, "<p><b onclick=x>hi</b>y</p>")

	hstAssertEqual(t, "<p>hiy</p>", result.html)
	hstAssertEqual(t, "<b> <b onclick> b.onclick=\"x\" ", result.log)
}

// TestAttributeWithAnInvalidNameIsReported: the renderer leaves an attribute
// whose name is not one HTML allows off the tag it writes.  It is reported
// with the value the author wrote.
func TestAttributeWithAnInvalidNameIsReported(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("b").
		AllowAttributes("x@y", "title").OnElements("b"))
	result := hcrtSanitizeVerbose(t, policy, "<b x@y=1 title=t>hi</b>")

	hstAssertEqual(t, "<b title=\"t\">hi</b>", result.html)
	hstAssertEqual(t, "<b x@y> b.x@y=\"1\" ", result.log)
}

// TestAddedAttributeWithAnInvalidNameIsReported: an attribute a policy added
// is reported as the renderer received it.
func TestAddedAttributeWithAnInvalidNameIsReported(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(
			ElementPolicyFunc(func(elementName string, attrs *[]string) (string, bool) {
				*attrs = append(*attrs, "x@y", "1")
				return elementName, true
			}),
			"b"))
	result := hcrtSanitizeVerbose(t, policy, "<b>hi</b>")

	hstAssertEqual(t, "<b>hi</b>", result.html)
	hstAssertEqual(t, "<b x@y> b.x@y=\"1\" ", result.log)
}

// TestTagInsideRenamedLiteralContentElementIsReported: a tag arriving inside
// literal content the renderer is writing is dropped before its attributes
// are judged, which a policy that renames an element into style brings
// about.  Reported under the input name.
func TestTagInsideRenamedLiteralContentElementIsReported(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(hstRenamingPolicy("style"), "div").
		AllowElements("b").
		AllowTextIn("style"))
	result := hcrtSanitizeVerbose(t,
		policy, "<div>a<b onclick=alert(1)>bold</b>c</div>")

	hstAssertEqual(t, "<style>aboldc</style>", result.html)
	hstAssertEqual(t, "<b> ", result.log)
}

// hcrtSanitizeVerbose is like hcrtSanitize but also records each discarded
// attribute's value and any dropped text; see hcrtVerboseListener.
func hcrtSanitizeVerbose(t testing.TB, policy *PolicyFactory, html string) hcrtResult {
	t.Helper()
	return hcrtSanitizeWith(t, policy, html, true)
}

// hcrtSanitizeWith sanitizes html under policy through a change reporter.
func hcrtSanitizeWith(
	t testing.TB, policy *PolicyFactory, html string, verbose bool) hcrtResult {
	t.Helper()
	testContext := &hcrtContext{}
	var out, log strings.Builder
	renderer := NewHTMLStreamRendererToBuilder(&out, DoNothing[string])
	var listener HTMLChangeListener
	if verbose {
		listener = hcrtVerboseListener(t, testContext, &log)
	} else {
		listener = hcrtLoggingListener(t, testContext, &log)
	}
	hcr := NewHTMLChangeReporter(renderer, listener, testContext)
	hcr.SetPolicy(policy.Apply(hcr.GetWrappedRenderer()))
	Sanitize(html, hcr.GetWrappedPolicy(), nil)
	return hcrtResult{html: out.String(), log: log.String()}
}

// hcrtLogger appends each notification to log as <tag> for a discarded tag
// or <tag attr...> for discarded attributes.  When verbose, it also logs each
// discarded attribute's value as tag.attr="value" and dropped text as
// element{text}.  Every notification must carry the expected context.
type hcrtLogger struct {
	t               testing.TB
	expectedContext *hcrtContext
	log             *strings.Builder
	verbose         bool
}

// hcrtLoggingListener returns a listener that logs tags and attributes.
func hcrtLoggingListener(
	t testing.TB, expectedContext *hcrtContext, log *strings.Builder) HTMLChangeListener {
	return &hcrtLogger{t: t, expectedContext: expectedContext, log: log}
}

// hcrtVerboseListener returns a listener that logs as hcrtLoggingListener
// does, and additionally attribute values and dropped text.
func hcrtVerboseListener(
	t testing.TB, expectedContext *hcrtContext, log *strings.Builder) HTMLChangeListener {
	return &hcrtLogger{t: t, expectedContext: expectedContext, log: log, verbose: true}
}

// assertSame fails the test unless context is the expected context.
func (l *hcrtLogger) assertSame(context any) {
	l.t.Helper()
	if c, ok := context.(*hcrtContext); !ok || c != l.expectedContext {
		l.t.Errorf("unexpected context %v", context)
	}
}

func (l *hcrtLogger) DiscardedTag(context any, elementName string) {
	l.assertSame(context)
	l.log.WriteString("<" + elementName + "> ")
}

func (l *hcrtLogger) DiscardedAttributes(
	context any, tagName string, attributeNames ...string) {
	l.assertSame(context)
	l.log.WriteString("<" + tagName)
	for _, attributeName := range attributeNames {
		l.log.WriteString(" " + attributeName)
	}
	l.log.WriteString("> ")
}

func (l *hcrtLogger) DiscardedAttribute(
	context any, tagName, attributeName, attributeValue string) {
	if !l.verbose {
		return
	}
	l.assertSame(context)
	l.log.WriteString(tagName + "." + attributeName + "=\"" + attributeValue + "\" ")
}

func (l *hcrtLogger) DiscardedText(context any, elementName, text string) {
	if !l.verbose {
		return
	}
	l.assertSame(context)
	l.log.WriteString(elementName + "{" + text + "} ")
}

// hcrtForwardingPolicy is a policy decorator that forwards every event to a
// receiver.  Embedding the interface promotes only its exported methods, so
// the decorator implements none of the library's package-private feedback.
type hcrtForwardingPolicy struct{ HTMLStreamEventReceiver }
