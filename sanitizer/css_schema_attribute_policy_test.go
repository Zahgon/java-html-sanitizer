// Copyright (c) 2013, Mike Samuel
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
// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/CssSchemaAttributePolicyTest.java.

package sanitizer

import (
	"strings"
	"testing"
)

// Tests CSSSchema.ToAttributePolicy.

var (
	cssSchemaAttributePolicyTestTextSchema = cssSchemaMustWithProperties(
		[]string{"color", "background-color"})
	cssSchemaAttributePolicyTestBoxSchema = cssSchemaMustWithProperties(
		[]string{"width", "height"})
	cssSchemaAttributePolicyTestImageSchema = cssSchemaMustWithProperties(
		[]string{"background-image", "background-position"})
)

// cssSchemaAttributePolicyTestFactory finishes a builder, failing the test
// on error.
func cssSchemaAttributePolicyTestFactory(t *testing.T, b *HTMLPolicyBuilder) *PolicyFactory {
	t.Helper()
	policy, err := b.ToFactory()
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func cssSchemaAttributePolicyTestAssertSanitized(
	t *testing.T, policy *PolicyFactory, want, html string,
) {
	t.Helper()
	if got := policy.Sanitize(html); got != want {
		t.Errorf("%s:\ngot  %s\nwant %s", html, got, want)
	}
}

// TestCSSSchemaAttributePolicyDifferentSchemasOnDifferentElements: the
// motivating use case from issue #381: a schema per element.
func TestCSSSchemaAttributePolicyDifferentSchemasOnDifferentElements(t *testing.T) {
	policy := cssSchemaAttributePolicyTestFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(IdentityElementPolicy, "span", "div").
		AllowAttributes("style").
		Matching(cssSchemaAttributePolicyTestTextSchema.ToAttributePolicy(nil)).
		OnElements("span").
		AllowAttributes("style").
		Matching(cssSchemaAttributePolicyTestBoxSchema.ToAttributePolicy(nil)).
		OnElements("div"))

	cssSchemaAttributePolicyTestAssertSanitized(t, policy,
		"<span style=\"color:red\">x</span>",
		"<span style=\"color: red; width: 10px\">x</span>")
	cssSchemaAttributePolicyTestAssertSanitized(t, policy,
		"<div style=\"width:10px\">x</div>",
		"<div style=\"color: red; width: 10px\">x</div>")
}

// TestCSSSchemaAttributePolicyStyleDroppedEntirelyWhenNothingSurvives: a
// property allowed on one element does not leak onto an element whose own
// schema omits it, and a style attribute left with nothing goes away.
func TestCSSSchemaAttributePolicyStyleDroppedEntirelyWhenNothingSurvives(t *testing.T) {
	policy := cssSchemaAttributePolicyTestFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(IdentityElementPolicy, "span", "div").
		AllowAttributes("style").
		Matching(cssSchemaAttributePolicyTestBoxSchema.ToAttributePolicy(nil)).
		OnElements("div"))

	cssSchemaAttributePolicyTestAssertSanitized(t, policy,
		"<div>x</div>",
		"<div style=\"color: red\">x</div>")
	// No policy at all for style on span, so it is not allowed there, and a
	// span with no attributes is elided by default.
	cssSchemaAttributePolicyTestAssertSanitized(t, policy,
		"x",
		"<span style=\"width: 10px\">x</span>")
}

// TestCSSSchemaAttributePolicyURLsDroppedByDefault: without a rewriter the
// policy is not wired to any URL policy, so it drops URLs.
func TestCSSSchemaAttributePolicyURLsDroppedByDefault(t *testing.T) {
	policy := cssSchemaAttributePolicyTestFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(IdentityElementPolicy, "div").
		AllowStandardURLProtocols().
		AllowAttributes("style").
		Matching(cssSchemaAttributePolicyTestImageSchema.ToAttributePolicy(nil)).
		OnElements("div"))

	// The url() token goes, and with it the only value of the property.
	cssSchemaAttributePolicyTestAssertSanitized(t, policy,
		"<div>x</div>",
		"<div style=\"background-image: url(http://example.com/i.png)\">"+
			"x</div>")
	// Surviving values of an allowed property are kept.
	cssSchemaAttributePolicyTestAssertSanitized(t, policy,
		"<div style=\"background-position:left\">x</div>",
		"<div style=\"background-image: url(http://example.com/i.png);"+
			" background-position: left\">x</div>")
}

// TestCSSSchemaAttributePolicyURLRewriterHonored: the caller's rewriter sees
// the URL and decides.
func TestCSSSchemaAttributePolicyURLRewriterHonored(t *testing.T) {
	rewriter := func(url string) string {
		if strings.HasPrefix(url, "http://example.com/") {
			return url + "?vetted"
		}
		return ""
	}
	policy := cssSchemaAttributePolicyTestFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(IdentityElementPolicy, "div").
		AllowAttributes("style").
		Matching(cssSchemaAttributePolicyTestImageSchema.ToAttributePolicy(rewriter)).
		OnElements("div"))

	cssSchemaAttributePolicyTestAssertSanitized(t, policy,
		"<div style=\"background-image:url(&#39;"+
			"http://example.com/i.png?vetted&#39;)\">x</div>",
		"<div style=\"background-image: url(http://example.com/i.png)\">"+
			"x</div>")
	// Returning the empty string drops the URL.
	cssSchemaAttributePolicyTestAssertSanitized(t, policy,
		"<div>x</div>",
		"<div style=\"background-image: url(http://evil.example/i.png)\">"+
			"x</div>")
}

func TestCSSSchemaAttributePolicyCSSEscapedQuoteStaysInsideURL(t *testing.T) {
	urlPolicy := NewFilterURLByProtocolAttributePolicy([]string{"https"})
	policy := cssSchemaAttributePolicyTestFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(IdentityElementPolicy, "div").
		AllowAttributes("style").
		Matching(cssSchemaAttributePolicyTestImageSchema.ToAttributePolicy(
			func(url string) string {
				safe, _ := urlPolicy.Apply("img", "src", url)
				return safe
			})).
		OnElements("div"))

	sanitized := policy.Sanitize(
		"<div style=\"background-image:url('https://example.com/i\\27)" +
			";color:red;x:(')\">x</div>")
	if want := "<div style=\"background-image:url(&#39;" +
		"https://example.com/i%27%29;color:red;x:%28&#39;)\">x</div>"; sanitized != want {
		t.Errorf("got  %s\nwant %s", sanitized, want)
	}
	cssSchemaAttributePolicyTestAssertSanitized(t, policy, sanitized, sanitized)
}

func TestCSSSchemaAttributePolicyURLRewriterOutputIsCSSEncoded(t *testing.T) {
	policy := cssSchemaAttributePolicyTestFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(IdentityElementPolicy, "div").
		AllowAttributes("style").
		Matching(cssSchemaAttributePolicyTestImageSchema.ToAttributePolicy(
			func(url string) string { return "https://example.com/a'\\\r\n b" })).
		OnElements("div"))

	cssSchemaAttributePolicyTestAssertSanitized(t, policy,
		"<div style=\"background-image:url(&#39;"+
			"https://example.com/a%27%5c%0d%0a%20b&#39;)\">x</div>",
		"<div style=\"background-image:url(https://example.com/i.png)\">"+
			"x</div>")
}

// TestCSSSchemaAttributePolicyNilURLRewriterDropsURLs: a rewriter never has
// to cope with a dropped URL.  A nil rewriter asks for the policy that drops
// every URL.
func TestCSSSchemaAttributePolicyNilURLRewriterDropsURLs(t *testing.T) {
	policy := cssSchemaAttributePolicyTestTextSchema.ToAttributePolicy(nil).(*stylingPolicy)
	if policy.urlRewriter != cssSchemaRejectAllURLs {
		t.Errorf("urlRewriter = %#v", policy.urlRewriter)
	}
}

// TestCSSSchemaAttributePolicyJoinsWithGlobalAllowStyling: a per-element
// schema and a global AllowStyling schema join to the intersection of the
// two, on that element only.  Joining narrows, as it does for every other
// attribute policy, so attaching a per-element schema restricts that element
// rather than granting it extra properties.
func TestCSSSchemaAttributePolicyJoinsWithGlobalAllowStylingWithSchema(t *testing.T) {
	policy := cssSchemaAttributePolicyTestFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(IdentityElementPolicy, "span", "div").
		AllowStylingWithSchema(cssSchemaAttributePolicyTestBoxSchema).
		AllowAttributes("style").
		Matching(cssSchemaAttributePolicyTestTextSchema.ToAttributePolicy(nil)).
		OnElements("span"))

	// The text and box schemas have no property in common, so a span that is
	// subject to both keeps no style at all -- and a span left with no
	// attributes is dropped, since span is skipped if empty by default.
	cssSchemaAttributePolicyTestAssertSanitized(t, policy,
		"x",
		"<span style=\"color: red; width: 10px\">x</span>")
	// Other elements see the global schema alone.
	cssSchemaAttributePolicyTestAssertSanitized(t, policy,
		"<div style=\"width:10px\">x</div>",
		"<div style=\"color: red; width: 10px\">x</div>")

	// Where the two schemas do overlap, the shared property survives.
	overlapping := cssSchemaAttributePolicyTestFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(IdentityElementPolicy, "span").
		AllowStylingWithSchema(cssSchemaMustWithProperties([]string{"color", "width"})).
		AllowAttributes("style").
		Matching(cssSchemaMustWithProperties([]string{"color"}).ToAttributePolicy(nil)).
		OnElements("span"))
	cssSchemaAttributePolicyTestAssertSanitized(t, overlapping,
		"<span style=\"color:red\">x</span>",
		"<span style=\"color: red; width: 10px\">x</span>")
}

// TestCSSSchemaAttributePolicyJoiningDoesNotWidenURLPolicy: joining
// intersects the schemas and runs both URL rewriters in turn, so a
// URL-dropping per-element policy is not widened by a permissive global one.
func TestCSSSchemaAttributePolicyJoiningDoesNotWidenURLPolicy(t *testing.T) {
	policy := cssSchemaAttributePolicyTestFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(IdentityElementPolicy, "p", "div").
		AllowStandardURLProtocols().
		AllowStylingWithSchema(cssSchemaAttributePolicyTestImageSchema).
		AllowURLsInStyles(IdentityAttributePolicy).
		AllowAttributes("style").
		Matching(cssSchemaAttributePolicyTestImageSchema.ToAttributePolicy(nil)).
		OnElements("div"))

	// The global policy alone still lets the URL through.
	cssSchemaAttributePolicyTestAssertSanitized(t, policy,
		"<p style=\"background-image:url(&#39;http://example.com/i.png&#39;)\">"+
			"x</p>",
		"<p style=\"background-image: url(http://example.com/i.png)\">"+
			"x</p>")
	// On div, the per-element policy's veto wins.
	cssSchemaAttributePolicyTestAssertSanitized(t, policy,
		"<div>x</div>",
		"<div style=\"background-image: url(http://example.com/i.png)\">"+
			"x</div>")
}

// TestCSSSchemaAttributePolicyCallerRewriterNeverSeesADroppedURL: a rewriter
// signals "dropped" by returning the empty string, which is not a URL, so a
// joined rewriter is never handed one.
func TestCSSSchemaAttributePolicyCallerRewriterNeverSeesADroppedURL(t *testing.T) {
	rewriter := func(url string) string {
		if url == "" {
			t.Error("rewriter handed a dropped URL")
		}
		if strings.HasPrefix(url, "http://example.com/") {
			return url
		}
		return ""
	}
	policy := cssSchemaAttributePolicyTestFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(IdentityElementPolicy, "div").
		AllowStandardURLProtocols().
		// No AllowURLsInStyles, so the global guard vetoes every URL.
		AllowStylingWithSchema(cssSchemaAttributePolicyTestImageSchema).
		AllowAttributes("style").
		Matching(cssSchemaAttributePolicyTestImageSchema.ToAttributePolicy(rewriter)).
		OnElements("div"))

	cssSchemaAttributePolicyTestAssertSanitized(t, policy,
		"<div>x</div>",
		"<div style=\"background-image: url(http://example.com/i.png)\">"+
			"x</div>")
}

// TestCSSSchemaAttributePolicyReusingFilterURLByProtocol: the documented
// recipe for reusing the library's own protocol filter.
func TestCSSSchemaAttributePolicyReusingFilterURLByProtocol(t *testing.T) {
	urlPolicy := NewFilterURLByProtocolAttributePolicy([]string{"https", "mailto"})
	policy := cssSchemaAttributePolicyTestFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(IdentityElementPolicy, "div").
		AllowAttributes("style").
		Matching(cssSchemaAttributePolicyTestImageSchema.ToAttributePolicy(
			func(url string) string {
				safe, _ := urlPolicy.Apply("img", "src", url)
				return safe
			})).
		OnElements("div"))

	cssSchemaAttributePolicyTestAssertSanitized(t, policy,
		"<div style=\"background-image:url(&#39;"+
			"https://example.com/i.png&#39;)\">x</div>",
		"<div style=\"background-image: url(https://example.com/i.png)\">"+
			"x</div>")
	cssSchemaAttributePolicyTestAssertSanitized(t, policy,
		"<div>x</div>",
		"<div style=\"background-image: url(http://example.com/i.png)\">"+
			"x</div>")
}

// TestCSSSchemaAttributePolicyJoinedRewritersRunInTurn: joined rewriters run
// in turn, each seeing the previous one's output.
func TestCSSSchemaAttributePolicyJoinedRewritersRunInTurn(t *testing.T) {
	rewriter := func(url string) string { return url + "?vetted" }
	policy := cssSchemaAttributePolicyTestFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(IdentityElementPolicy, "div").
		AllowStandardURLProtocols().
		AllowStylingWithSchema(cssSchemaAttributePolicyTestImageSchema).
		AllowURLsInStyles(IdentityAttributePolicy).
		AllowAttributes("style").
		Matching(cssSchemaAttributePolicyTestImageSchema.ToAttributePolicy(rewriter)).
		OnElements("div"))

	// The caller's rewrite survives, and the global protocol policy still
	// gets to veto what comes out of it.
	cssSchemaAttributePolicyTestAssertSanitized(t, policy,
		"<div style=\"background-image:url(&#39;"+
			"http://example.com/i.png?vetted&#39;)\">x</div>",
		"<div style=\"background-image: url(http://example.com/i.png)\">"+
			"x</div>")
	cssSchemaAttributePolicyTestAssertSanitized(t, policy,
		"<div>x</div>",
		"<div style=\"background-image: url(javascript:alert%281%29)\">"+
			"x</div>")
}
