// Copyright (c) 2019, Mike Samuel
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

// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/PolicyFactoryTest.java.

package sanitizer

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

// pfToFactory builds b, failing the test on a configuration error.
func pfToFactory(t *testing.T, b *HTMLPolicyBuilder) *PolicyFactory {
	t.Helper()
	f, err := b.ToFactory()
	if err != nil {
		t.Fatalf("ToFactory: %v", err)
	}
	return f
}

// pfSchema returns the CSS schema with the given properties, failing the test
// if one is unknown.
func pfSchema(t *testing.T, propertyNames ...string) *CSSSchema {
	t.Helper()
	schema, err := CSSSchemaWithProperties(propertyNames)
	if err != nil {
		t.Fatalf("CSSSchemaWithProperties(%q): %v", propertyNames, err)
	}
	return schema
}

// pfAssertSanitize checks that f sanitizes html to want.
func pfAssertSanitize(t *testing.T, want string, f *PolicyFactory, html string, msg string) {
	t.Helper()
	if got := f.Sanitize(html); got != want {
		t.Errorf("%s: Sanitize(%q)\n got: %q\nwant: %q", msg, html, got, want)
	}
}

// pfLinks returns a factory for links, with the given protocols allowed.
func pfLinks(t *testing.T, protocols ...string) *PolicyFactory {
	t.Helper()
	return pfToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a").
		AllowAttributes("href").OnElements("a").
		AllowURLProtocols(protocols...))
}

// pfRelativeOnlyLinks returns a factory for links whose hrefs must have
// neither a protocol nor an authority.
func pfRelativeOnlyLinks(t *testing.T) *PolicyFactory {
	t.Helper()
	return pfToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a").
		AllowAttributes("href").OnElements("a").
		AllowOnlyRelativeURLs())
}

// pfImages returns a factory for images with src and srcset, with the given
// protocols allowed.
func pfImages(t *testing.T, protocols ...string) *PolicyFactory {
	t.Helper()
	return pfToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("img").
		AllowAttributes("src", "srcset").OnElements("img").
		AllowURLProtocols(protocols...))
}

// pfRelativeOnlyImages returns a factory for images whose src and srcset URLs
// must be relative.
func pfRelativeOnlyImages(t *testing.T) *PolicyFactory {
	t.Helper()
	return pfToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("img").
		AllowAttributes("src", "srcset").OnElements("img").
		AllowOnlyRelativeURLs())
}

// pfStyled returns a factory for styled divs that allow URLs in styles, with
// the given protocols allowed.
func pfStyled(t *testing.T, schema *CSSSchema, protocols ...string) *PolicyFactory {
	t.Helper()
	return pfToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("div").
		AllowAttributes("style").OnElements("div").
		AllowStylingWithSchema(schema).
		AllowURLsInStyles(IdentityAttributePolicy).
		AllowURLProtocols(protocols...))
}

// pfRelativeOnlyStyled returns a factory for styled divs whose CSS URLs must
// be relative.
func pfRelativeOnlyStyled(t *testing.T, schema *CSSSchema) *PolicyFactory {
	t.Helper()
	return pfToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("div").
		AllowAttributes("style").OnElements("div").
		AllowStylingWithSchema(schema).
		AllowURLsInStyles(IdentityAttributePolicy).
		AllowOnlyRelativeURLs())
}

// Issue #423.  And is documented to intersect policies where they overlap.
// For the style attribute it used to union the CSS schemas, so combining two
// factories allowed properties that neither one allowed on its own.
func TestPolicyFactoryAndIntersectsCSSSchemas(t *testing.T) {
	css := "color: red; width: 10px"
	html := "<div style=\"" + css + "\">x</div>"

	styled := func(properties ...string) *PolicyFactory {
		return pfToFactory(t, NewHTMLPolicyBuilder().
			AllowElements("div").
			AllowAttributes("style").OnElements("div").
			AllowStylingWithSchema(pfSchema(t, properties...)))
	}
	colorOnly := styled("color")
	widthOnly := styled("width")
	both := styled("color", "width")

	pfAssertSanitize(t, "<div style=\"color:red\">x</div>", colorOnly, html, "colorOnly")
	pfAssertSanitize(t, "<div style=\"width:10px\">x</div>", widthOnly, html, "widthOnly")

	// Neither allows the other's property, so together they allow neither.
	pfAssertSanitize(t, "<div>x</div>", colorOnly.And(widthOnly), html, "colorOnly.And(widthOnly)")
	pfAssertSanitize(t, "<div>x</div>", widthOnly.And(colorOnly), html, "widthOnly.And(colorOnly)")

	// Where they overlap, the shared property survives, and the order of the
	// operands does not matter.
	pfAssertSanitize(t, "<div style=\"color:red\">x</div>", both.And(colorOnly), html, "both.And(colorOnly)")
	pfAssertSanitize(t, "<div style=\"color:red\">x</div>", colorOnly.And(both), html, "colorOnly.And(both)")
}

// Two AllowStylingWithSchema calls on one builder still accumulate: the
// builder unions them into a single schema before any joining happens, so
// making the join narrow does not change this.
func TestPolicyFactoryTwoAllowStylingCallsStillAccumulate(t *testing.T) {
	p := pfToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("div").
		AllowAttributes("style").OnElements("div").
		AllowStylingWithSchema(pfSchema(t, "color")).
		AllowStylingWithSchema(pfSchema(t, "width")))
	pfAssertSanitize(t,
		"<div style=\"color:red;width:10px\">x</div>",
		p, "<div style=\"color: red; width: 10px\">x</div>", "two schemas")
}

// Issue #204.  A builder that never allowed a URL protocol guards its URL
// attributes with a default that rejects every absolute URL.  Joined with a
// factory that did allow some, that default used to be intersected as though
// it were a policy, so the combination rejected the protocols the other
// factory allowed, in either order.  The default now yields to an allowlist.
func TestPolicyFactoryAndDefaultURLProtocolGuardYieldsToAnAllowlist(t *testing.T) {
	links := strings.Join([]string{
		"<a href='http://example.com/'>http</a>",
		"<a href='HTTP://example.com/'>HTTP</a>",
		"<a href='https://example.com/'>https</a>",
		"<a href='//example.com/'>scheme-relative</a>",
		"<a href='/local'>relative</a>",
		"<a href='javascript:alert(1)'>js</a>",
		"<a href='jAvAsCrIpT:alert(1)'>JS</a>",
		"<a href='\tjavascript:alert(1)'>tab js</a>",
		"<a href='java&#9;script:alert(1)'>split js</a>",
		"<a href='data:text/html,x'>data</a>",
		"<a href='vbscript:x'>vbs</a>",
	}, "\n")
	relativeOnly := strings.Join([]string{
		"http",
		"HTTP",
		"https",
		"scheme-relative",
		"<a href=\"/local\">relative</a>",
		"js",
		"JS",
		"tab js",
		"split js",
		"data",
		"vbs",
	}, "\n")
	httpOnly := strings.Join([]string{
		"<a href=\"http://example.com/\">http</a>",
		"<a href=\"HTTP://example.com/\">HTTP</a>",
		"https",
		"scheme-relative",
		"<a href=\"/local\">relative</a>",
		"js",
		"JS",
		"tab js",
		"split js",
		"data",
		"vbs",
	}, "\n")

	noProtocols := pfLinks(t)
	http := pfLinks(t, "http")
	disallowedBackToDefault := pfToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a").
		AllowAttributes("href").OnElements("a").
		AllowURLProtocols("http").
		DisallowURLProtocols("http"))

	tests := []struct {
		name string
		f    *PolicyFactory
		want string
	}{
		{"noProtocols", noProtocols, relativeOnly},
		{"disallowedBackToDefault", disallowedBackToDefault, relativeOnly},
		{"http", http, httpOnly},
		{"noProtocols.And(http)", noProtocols.And(http), httpOnly},
		{"http.And(noProtocols)", http.And(noProtocols), httpOnly},
		{"disallowedBackToDefault.And(http)", disallowedBackToDefault.And(http), httpOnly},
		{"http.And(disallowedBackToDefault)", http.And(disallowedBackToDefault), httpOnly},
	}
	for _, tc := range tests {
		pfAssertSanitize(t, tc.want, tc.f, links, tc.name)
	}
}

// Issue #453.  A caller can choose an explicit empty protocol allowlist when a
// factory must keep allowing only relative URLs after And combines it with a
// factory that allows protocols.  The restriction is independent of operand
// grouping and of calls to AllowURLProtocols on the same builder.
func TestPolicyFactoryAndExplicitRelativeOnlyURLGuardIntersectsAnAllowlist(t *testing.T) {
	links := strings.Join([]string{
		"<a href='http://example.com/'>http</a>",
		"<a href='HTTPS://example.com/'>https</a>",
		"<a href='//example.com/'>scheme-relative</a>",
		"<a href='/local'>root-relative</a>",
		"<a href='child'>path-relative</a>",
		"<a href='?q=1'>query</a>",
		"<a href='#fragment'>fragment</a>",
		"<a href='jAvAsCrIpT:alert(1)'>js</a>",
		"<a href='java&#9;script:alert(1)'>split js</a>",
		"<a href='data:text/html,x'>data</a>",
	}, "\n")
	expected := strings.Join([]string{
		"http",
		"https",
		"scheme-relative",
		"<a href=\"/local\">root-relative</a>",
		"<a href=\"child\">path-relative</a>",
		"<a href=\"?q&#61;1\">query</a>",
		"<a href=\"#fragment\">fragment</a>",
		"js",
		"split js",
		"data",
	}, "\n")

	relativeOnly := pfRelativeOnlyLinks(t)
	defaultGuard := pfLinks(t)
	web := pfLinks(t, "http", "https")

	relativeThenWeb := pfToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a").
		AllowAttributes("href").OnElements("a").
		AllowOnlyRelativeURLs().
		AllowURLProtocols("http", "https"))
	webThenRelative := pfToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a").
		AllowAttributes("href").OnElements("a").
		AllowURLProtocols("http", "https").
		AllowOnlyRelativeURLs())

	tests := []struct {
		name string
		f    *PolicyFactory
	}{
		{"relativeOnly", relativeOnly},
		{"relativeOnly.And(web)", relativeOnly.And(web)},
		{"web.And(relativeOnly)", web.And(relativeOnly)},
		{"defaultGuard.And(relativeOnly).And(web)", defaultGuard.And(relativeOnly).And(web)},
		{"defaultGuard.And(relativeOnly.And(web))", defaultGuard.And(relativeOnly.And(web))},
		{"relativeThenWeb", relativeThenWeb},
		{"webThenRelative", webThenRelative},
	}
	for _, tc := range tests {
		pfAssertSanitize(t, expected, tc.f, links, tc.name)
	}
}

// Browsers resolving against an HTTP(S) page treat a backslash as a slash, so
// each pair below introduces an authority.  The relative-only and default
// empty guards reject every spelling, including after entity decoding, while
// a policy that allows both web protocols may keep them.
func TestPolicyFactoryRelativeOnlyRejectsBrowserAuthoritySpellings(t *testing.T) {
	authoritySpellings := []struct{ written, decoded string }{
		{"//evil.example/path", "//evil.example/path"},
		{"/\\evil.example/path", "/\\evil.example/path"},
		{"\\/evil.example/path", "\\/evil.example/path"},
		{"\\\\evil.example/path", "\\\\evil.example/path"},
		{"&#47;&#47;evil.example/path", "//evil.example/path"},
		{"&#47;&#92;evil.example/path", "/\\evil.example/path"},
		{"&#92;&#47;evil.example/path", "\\/evil.example/path"},
		{"&#92;&#92;evil.example/path", "\\\\evil.example/path"},
	}
	defaultGuard := pfLinks(t)
	relativeOnly := pfRelativeOnlyLinks(t)
	httpOnly := pfLinks(t, "http")
	mailtoOnly := pfLinks(t, "mailto")
	web := pfLinks(t, "http", "https")
	relativeAndWeb := relativeOnly.And(web)
	webAndRelative := web.And(relativeOnly)

	for _, spelling := range authoritySpellings {
		html := "<a href='" + spelling.written + "'>external</a>"
		webAllowed := "<a href=\"" + spelling.decoded + "\">external</a>"
		pfAssertSanitize(t, "external", defaultGuard, html, spelling.written+" defaultGuard")
		pfAssertSanitize(t, "external", relativeOnly, html, spelling.written+" relativeOnly")
		pfAssertSanitize(t, "external", httpOnly, html, spelling.written+" httpOnly")
		pfAssertSanitize(t, "external", mailtoOnly, html, spelling.written+" mailtoOnly")
		pfAssertSanitize(t, "external", relativeAndWeb, html, spelling.written+" relativeAndWeb")
		pfAssertSanitize(t, "external", webAndRelative, html, spelling.written+" webAndRelative")
		pfAssertSanitize(t, webAllowed, web, html, spelling.written+" web")
	}
}

// The relative-only restriction reaches only the URL attributes its builder
// allows.  And unions grants, so an attribute that only the other factory
// allows keeps that factory's protocols.
func TestPolicyFactoryRelativeOnlyDoesNotReachAttributesOnlyTheOtherFactoryAllows(t *testing.T) {
	html := "<a href='https://example.com/'>abs</a>" +
		"<a href='/local'>rel</a>" +
		"<img src='https://example.com/a.png'" +
		" srcset='//example.com/b.png 2x'>"
	expected := "abs<a href=\"/local\">rel</a>" +
		"<img src=\"https://example.com/a.png\"" +
		" srcset=\"//example.com/b.png 2x\" />"

	relativeLinks := pfRelativeOnlyLinks(t)
	webImages := pfImages(t, "http", "https")

	pfAssertSanitize(t, expected, relativeLinks.And(webImages), html, "relativeLinks.And(webImages)")
	pfAssertSanitize(t, expected, webImages.And(relativeLinks), html, "webImages.And(relativeLinks)")
}

// Two factories that allowed no protocol still allow none together.
func TestPolicyFactoryAndOfTwoDefaultURLProtocolGuardsAllowsNoProtocol(t *testing.T) {
	noProtocols := pfLinks(t)
	noProtocolsWithTitle := pfToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a").
		AllowAttributes("href", "title").OnElements("a"))
	links := strings.Join([]string{
		"<a href='http://example.com/' title='t'>http</a>",
		"<a href='/local' title='t'>relative</a>",
	}, "\n")
	expected := strings.Join([]string{
		"<a title=\"t\">http</a>",
		"<a href=\"/local\" title=\"t\">relative</a>",
	}, "\n")

	pfAssertSanitize(t, expected, noProtocols.And(noProtocolsWithTitle), links, "noProtocols.And(noProtocolsWithTitle)")
	pfAssertSanitize(t, expected, noProtocolsWithTitle.And(noProtocols), links, "noProtocolsWithTitle.And(noProtocols)")
}

// Two allowlists intersect, as And documents.  An empty intersection is an
// allowlist too, not the default, so it does not yield to a third factory:
// the same factories allow the same URLs however they are grouped.
func TestPolicyFactoryAndIntersectsURLProtocolAllowlists(t *testing.T) {
	http := pfLinks(t, "http")
	https := pfLinks(t, "https")
	both := pfLinks(t, "http", "https")

	links := strings.Join([]string{
		"<a href='http://example.com/'>http</a>",
		"<a href='https://example.com/'>https</a>",
		"<a href='//example.com/'>scheme-relative</a>",
		"<a href='/local'>relative</a>",
		"<a href='javascript:alert(1)'>js</a>",
	}, "\n")
	bothKept := strings.Join([]string{
		"<a href=\"http://example.com/\">http</a>",
		"<a href=\"https://example.com/\">https</a>",
		"<a href=\"//example.com/\">scheme-relative</a>",
		"<a href=\"/local\">relative</a>",
		"js",
	}, "\n")
	httpKept := strings.Join([]string{
		"<a href=\"http://example.com/\">http</a>",
		"https",
		"scheme-relative",
		"<a href=\"/local\">relative</a>",
		"js",
	}, "\n")
	noneKept := strings.Join([]string{
		"http",
		"https",
		"scheme-relative",
		"<a href=\"/local\">relative</a>",
		"js",
	}, "\n")

	tests := []struct {
		name string
		f    *PolicyFactory
		want string
	}{
		{"both", both, bothKept},
		{"both.And(http)", both.And(http), httpKept},
		{"http.And(both)", http.And(both), httpKept},
		{"http.And(https)", http.And(https), noneKept},
		{"https.And(http)", https.And(http), noneKept},
		{"http.And(https).And(both)", http.And(https).And(both), noneKept},
		{"both.And(http.And(https))", both.And(http.And(https)), noneKept},
		{"http.And(both.And(https))", http.And(both.And(https)), noneKept},
		{"http.And(https).And(links())", http.And(https).And(pfLinks(t)), noneKept},
	}
	for _, tc := range tests {
		pfAssertSanitize(t, tc.want, tc.f, links, tc.name)
	}
}

// The case that bites in practice: Links combined with a factory
// that only meant to restrict href to a pattern, and so never mentioned
// protocols, used to lose every absolute link.
func TestPolicyFactoryAndLinksWithAFactoryThatRestrictsHrefButAllowedNoProtocol(t *testing.T) {
	exampleOnly := pfToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a").
		AllowAttributes("href").
		MatchingPattern(regexp.MustCompile(`(?:https?://example\.com)?/.*`)).
		OnElements("a"))
	links := strings.Join([]string{
		"<a href='http://example.com/a'>example</a>",
		"<a href='https://example.com/b'>secure example</a>",
		"<a href='http://evil.example/c'>elsewhere</a>",
		"<a href='/d'>local</a>",
		"<a href='javascript:alert(1)'>js</a>",
		"<a href='mailto:x@example.com'>mail</a>",
	}, "\n")
	expected := strings.Join([]string{
		"<a href=\"http://example.com/a\" rel=\"nofollow\">example</a>",
		"<a href=\"https://example.com/b\" rel=\"nofollow\">secure example</a>",
		"elsewhere",
		"<a href=\"/d\" rel=\"nofollow\">local</a>",
		"js",
		"mail",
	}, "\n")

	pfAssertSanitize(t,
		strings.Join([]string{
			"example",
			"secure example",
			"elsewhere",
			"<a href=\"/d\">local</a>",
			"js",
			"mail",
		}, "\n"),
		exampleOnly, links, "exampleOnly")
	pfAssertSanitize(t, expected, Links.And(exampleOnly), links, "Links.And(exampleOnly)")
	pfAssertSanitize(t, expected, exampleOnly.And(Links), links, "exampleOnly.And(Links)")
}

// A global href grant that allowed no protocol does not veto either.
func TestPolicyFactoryAndLinksWithAGlobalHrefGrantThatAllowedNoProtocol(t *testing.T) {
	hrefAnywhere := pfToFactory(t, NewHTMLPolicyBuilder().
		AllowAttributes("href").Globally())
	links := strings.Join([]string{
		"<a href='http://example.com/'>http</a>",
		"<a href='javascript:alert(1)'>js</a>",
	}, "\n")
	expected := strings.Join([]string{
		"<a href=\"http://example.com/\" rel=\"nofollow\">http</a>",
		"js",
	}, "\n")

	pfAssertSanitize(t, expected, Links.And(hrefAnywhere), links, "Links.And(hrefAnywhere)")
	pfAssertSanitize(t, expected, hrefAnywhere.And(Links), links, "hrefAnywhere.And(Links)")
}

// The default yields only to another builder's allowlist, never to a policy
// the author attached with Matching, so a builder that allowed no protocol
// still rejects every absolute URL on its own, as the documentation of
// AllowURLProtocols promises, even when that policy is the library's own
// protocol filter.  And an allowlist from another factory intersects with
// such a policy, as with any other.
func TestPolicyFactoryDefaultURLProtocolGuardDoesNotYieldToAMatchingPolicy(t *testing.T) {
	httpsByMatching := pfToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a").
		AllowAttributes("href").
		Matching(NewFilterURLByProtocolAttributePolicy([]string{"https"})).
		OnElements("a"))
	links := strings.Join([]string{
		"<a href='https://example.com/'>https</a>",
		"<a href='/local'>relative</a>",
	}, "\n")
	relativeOnly := strings.Join([]string{
		"https",
		"<a href=\"/local\">relative</a>",
	}, "\n")

	pfAssertSanitize(t, relativeOnly, httpsByMatching, links, "httpsByMatching")
	pfAssertSanitize(t, relativeOnly, httpsByMatching.And(pfLinks(t)), links, "httpsByMatching.And(links())")
	pfAssertSanitize(t, relativeOnly, pfLinks(t).And(httpsByMatching), links, "links().And(httpsByMatching)")
	pfAssertSanitize(t, relativeOnly, httpsByMatching.And(pfLinks(t, "http")), links, "httpsByMatching.And(links(http))")
	pfAssertSanitize(t,
		strings.Join([]string{
			"<a href=\"https://example.com/\">https</a>",
			"<a href=\"/local\">relative</a>",
		}, "\n"),
		httpsByMatching.And(pfLinks(t, "https")), links, "httpsByMatching.And(links(https))")
}

// The same for srcset, whose guard wraps the protocol guard.
func TestPolicyFactoryAndDefaultURLProtocolGuardYieldsInSrcset(t *testing.T) {
	noProtocols := pfImages(t)
	http := pfImages(t, "http")
	relativeOnly := pfRelativeOnlyImages(t)
	img := "<img src='http://example.com/a.png'" +
		" srcset='http://example.com/a.png 1x, javascript:alert(1) 2x," +
		" /b.png 3x, //example.com/c.png 4x," +
		" /\\example.com/d.png 5x, \\/example.com/e.png 6x," +
		" \\\\example.com/f.png 7x'>"
	httpKept := "<img src=\"http://example.com/a.png\"" +
		" srcset=\"http://example.com/a.png 1x , /b.png 3x\" />"
	relativeKept := "<img srcset=\"/b.png 3x\" />"

	tests := []struct {
		name string
		f    *PolicyFactory
		want string
	}{
		{"noProtocols", noProtocols, relativeKept},
		{"http", http, httpKept},
		{"noProtocols.And(http)", noProtocols.And(http), httpKept},
		{"http.And(noProtocols)", http.And(noProtocols), httpKept},
		{"relativeOnly", relativeOnly, relativeKept},
		{"relativeOnly.And(http)", relativeOnly.And(http), relativeKept},
		{"http.And(relativeOnly)", http.And(relativeOnly), relativeKept},
	}
	for _, tc := range tests {
		pfAssertSanitize(t, tc.want, tc.f, img, tc.name)
	}
}

// The explicit empty allowlist also survives joining inside CSS url().
func TestPolicyFactoryAndExplicitRelativeOnlyURLGuardIntersectsInStyles(t *testing.T) {
	images := pfSchema(t, "background-image")
	noProtocols := pfStyled(t, images)
	relativeOnly := pfRelativeOnlyStyled(t, images)
	web := pfStyled(t, images, "http", "https")
	divs := "<div style=\"background-image: url(https://example.com/i.png)\">" +
		"https</div>" +
		"<div style=\"background-image: url(//example.com/i.png)\">" +
		"scheme-relative</div>" +
		"<div style=\"background-image: url(/local.png)\">relative</div>" +
		"<div style=\"background-image: url(javascript:alert%281%29)\">" +
		"js</div>"
	expected := "<div>https</div>" +
		"<div>scheme-relative</div>" +
		"<div style=\"background-image:url(&#39;/local.png&#39;)\">" +
		"relative</div>" +
		"<div>js</div>"

	tests := []struct {
		name string
		f    *PolicyFactory
	}{
		{"relativeOnly", relativeOnly},
		{"relativeOnly.And(web)", relativeOnly.And(web)},
		{"web.And(relativeOnly)", web.And(relativeOnly)},
		{"noProtocols.And(relativeOnly).And(web)", noProtocols.And(relativeOnly).And(web)},
		{"noProtocols.And(relativeOnly.And(web))", noProtocols.And(relativeOnly.And(web))},
	}
	for _, tc := range tests {
		pfAssertSanitize(t, expected, tc.f, divs, tc.name)
	}

	rewritesToAuthority := pfToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("div").
		AllowAttributes("style").OnElements("div").
		AllowStylingWithSchema(images).
		AllowURLsInStyles(AttributePolicyFunc(func(elementName, attributeName, url string) (string, bool) {
			return "\\\\evil.example/i.png", true
		})).
		AllowOnlyRelativeURLs())
	pfAssertSanitize(t,
		"<div>x</div>",
		rewritesToAuthority,
		"<div style=\"background-image:url(/local.png)\">x</div>",
		"rewritesToAuthority")
}

// And for url() in style, whose rewriter wraps the protocol guard, between
// factories that both allowed URLs in styles.  A rewriter from
// CSSSchema.ToAttributePolicy is a policy of the author's, and takes part
// however the factories are grouped, as does the policy given to
// AllowURLsInStyles, which the default does not yield to.
func TestPolicyFactoryAndDefaultURLProtocolGuardYieldsInStyles(t *testing.T) {
	images := pfSchema(t, "background-image")
	noProtocols := pfStyled(t, images)
	https := pfStyled(t, images, "https")
	divs := "<div style=\"background-image: url(https://example.com/i.png)\">" +
		"x</div>" +
		"<div style=\"background-image: url(javascript:alert%281%29)\">" +
		"y</div>"
	httpsKept := "<div style=\"background-image:url(" +
		"&#39;https://example.com/i.png&#39;)\">" +
		"x</div><div>y</div>"

	pfAssertSanitize(t, "<div>x</div><div>y</div>", noProtocols, divs, "noProtocols")
	pfAssertSanitize(t, httpsKept, https, divs, "https")
	pfAssertSanitize(t, httpsKept, noProtocols.And(https), divs, "noProtocols.And(https)")
	pfAssertSanitize(t, httpsKept, https.And(noProtocols), divs, "https.And(noProtocols)")

	vetted := pfToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("div").
		AllowAttributes("style").
		Matching(images.ToAttributePolicy(func(url string) string {
			return url + "?vetted"
		})).
		OnElements("div"))
	vettedKept := "<div style=\"background-image:url(" +
		"&#39;https://example.com/i.png?vetted&#39;)\">" +
		"x</div><div>y</div>"
	pfAssertSanitize(t, "<div>x</div><div>y</div>", noProtocols.And(vetted), divs, "noProtocols.And(vetted)")
	pfAssertSanitize(t, vettedKept, noProtocols.And(vetted).And(https), divs, "noProtocols.And(vetted).And(https)")
	pfAssertSanitize(t, vettedKept, noProtocols.And(vetted.And(https)), divs, "noProtocols.And(vetted.And(https))")
	pfAssertSanitize(t, vettedKept, vetted.And(https).And(noProtocols), divs, "vetted.And(https).And(noProtocols)")
	pfAssertSanitize(t, vettedKept, https.And(noProtocols.And(vetted)), divs, "https.And(noProtocols.And(vetted))")

	httpsInStylesOnly := pfToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("div").
		AllowAttributes("style").OnElements("div").
		AllowStylingWithSchema(images).
		AllowURLsInStyles(NewFilterURLByProtocolAttributePolicy([]string{"https"})))
	pfAssertSanitize(t, "<div>x</div><div>y</div>", httpsInStylesOnly, divs, "httpsInStylesOnly")
	pfAssertSanitize(t, "<div>x</div><div>y</div>", httpsInStylesOnly.And(noProtocols), divs, "httpsInStylesOnly.And(noProtocols)")
	pfAssertSanitize(t, httpsKept, httpsInStylesOnly.And(https), divs, "httpsInStylesOnly.And(https)")
}

// pfSubstringFilter keeps the comma-separated parts of a value that contain
// a substring.
type pfSubstringFilter struct {
	substr string
}

// Apply joins the trimmed parts that contain the substring with " , ".
func (f *pfSubstringFilter) Apply(elementName, attributeName, value string) (string, bool) {
	var outParts []string
	for _, part := range strings.Split(value, ",") {
		// Trim characters at or below U+0020.
		part = strings.TrimFunc(part, func(r rune) bool { return r <= ' ' })
		if strings.Contains(part, f.substr) {
			outParts = append(outParts, part)
		}
	}
	return strings.Join(outParts, " , "), true
}

// pfLoggingListener is a noisy listener that logs, checking that the context
// is threaded through joined policies.
type pfLoggingListener struct {
	NopHTMLChangeListener
	t       *testing.T
	context any
	log     *strings.Builder
}

// DiscardedTag logs the tag.
func (l *pfLoggingListener) DiscardedTag(ctx any, elementName string) {
	if ctx != l.context {
		l.t.Errorf("DiscardedTag: context %v, want %v", ctx, l.context)
	}
	l.log.WriteString("discardedTag " + elementName + "\n")
}

// DiscardedAttributes logs the tag and the attribute names, formatted as a
// bracketed, comma-separated list.
func (l *pfLoggingListener) DiscardedAttributes(ctx any, tagName string, attributeNames ...string) {
	if ctx != l.context {
		l.t.Errorf("DiscardedAttributes: context %v, want %v", ctx, l.context)
	}
	l.log.WriteString(
		"discardedAttributes " + tagName +
			", [" + strings.Join(attributeNames, ", ") + "]\n")
}

// pfThrowingWriter writes to out, but fails on any write that contains a '!'
// without writing any of it, to test the I/O error handler.
type pfThrowingWriter struct {
	out *strings.Builder
}

// Write appends p to the output unless it contains a '!'.
func (w *pfThrowingWriter) Write(p []byte) (int, error) {
	if strings.IndexByte(string(p), '!') >= 0 {
		return 0, errors.New("BANG")
	}
	return w.out.Write(p)
}

func TestPolicyFactoryAnd(t *testing.T) {
	// Filters srcset to only contain URLs with the substring "foo"
	f := pfToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("img").
		AllowAttributes("srcset").
		Matching(&pfSubstringFilter{"foo"}).
		Globally().
		AllowStandardURLProtocols())
	// Filters srcset to only contain URLs with the substring "bar"
	g := pfToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("img").
		AllowAttributes("srcset").
		Matching(&pfSubstringFilter{"bar"}).
		Globally().
		AllowStandardURLProtocols())

	// The javascript URL will be allowed if the extra policies are not
	// preserved.
	html := "<img" +
		" srcset=\"/foo.png , /bar.png , javascript:alert('foobar') , /foobar.png\"" +
		// title is not allowed.
		" title=Hi>!"

	tests := []struct {
		name           string
		factory        *PolicyFactory
		expectedOutput string
		expectedLog    string
	}{
		{
			"f", f,
			"<img srcset=\"/foo.png , /foobar.png\" />",
			"discardedAttributes img, [title]\n" +
				"Handled IOException BANG\n",
		},
		{
			"g", g,
			"<img srcset=\"/bar.png , /foobar.png\" />",
			"discardedAttributes img, [title]\n" +
				"Handled IOException BANG\n",
		},
		// Test that And intersects regardless of order.
		{
			"f and g", f.And(g),
			"<img srcset=\"/foobar.png\" />",
			"discardedAttributes img, [title]\n" +
				"Handled IOException BANG\n",
		},
		{
			"g and f", g.And(f),
			"<img srcset=\"/foobar.png\" />",
			"discardedAttributes img, [title]\n" +
				"Handled IOException BANG\n",
		},
	}

	for _, tc := range tests {
		// A dummy value that lets us check that context is properly threaded
		// through joined policies.
		context := new(int)
		// Collect events from callbacks.
		var log strings.Builder
		// Collects output HTML.
		var out strings.Builder

		listener := &pfLoggingListener{t: t, context: context, log: &log}

		ioHandler := func(err error) {
			log.WriteString("Handled IOException " + err.Error() + "\n")
		}

		// Should not be called.
		badHTMLHandler := func(x string) {
			t.Errorf("%s: unexpected bad HTML: %s", tc.name, x)
		}

		// Wraps out to fail when a '!' is written to test the ioHandler.
		// There is a '!' at the end of the output.
		receiver := NewHTMLStreamRenderer(&pfThrowingWriter{&out}, ioHandler, badHTMLHandler)
		policy := tc.factory.ApplyWithListener(receiver, listener, context)
		Sanitize(html, policy, IdentityProcessor)

		want := "Out:\n" + tc.expectedOutput + "\n\nLog:\n" + tc.expectedLog
		got := "Out:\n" + out.String() + "\n\nLog:\n" + log.String()
		if got != want {
			t.Errorf("%s:\n got: %q\nwant: %q", tc.name, got, want)
		}
	}
}

// pfSkipMode says how a builder configures skipping an element when it has
// no attributes.
type pfSkipMode int

const (
	// pfSkipDefault leaves the default.
	pfSkipDefault pfSkipMode = iota
	// pfSkipAllow calls AllowWithoutAttributes.
	pfSkipAllow
	// pfSkipDisallow calls DisallowWithoutAttributes.
	pfSkipDisallow
)

// pfSkipFactory allows elementName with the given skip mode.
func pfSkipFactory(t *testing.T, elementName string, mode pfSkipMode) *PolicyFactory {
	t.Helper()
	b := NewHTMLPolicyBuilder().AllowElements(elementName)
	switch mode {
	case pfSkipAllow:
		b.AllowWithoutAttributes(elementName)
	case pfSkipDisallow:
		b.DisallowWithoutAttributes(elementName)
	}
	return pfToFactory(t, b)
}

// TestPolicyFactoryHTMLTagSkipPolicy covers each combination of the skip
// modes of two factories for a tag that is skipped by default (span) and one
// that is not (p).
func TestPolicyFactoryHTMLTagSkipPolicy(t *testing.T) {
	const (
		span = "<span>Hi</span>"
		p    = "<p>Hi</p>"
	)
	tests := []struct {
		name       string
		element    string
		input      string
		before     pfSkipMode
		wantBefore string
		after      pfSkipMode
		wantAfter  string
	}{
		// Default Skip Tag
		{"1", "span", span, pfSkipDefault, "Hi", pfSkipDefault, "Hi"},
		{"2", "span", span, pfSkipDefault, "Hi", pfSkipAllow, span},
		{"3", "span", span, pfSkipDefault, "Hi", pfSkipDisallow, "Hi"},
		{"4", "span", span, pfSkipAllow, span, pfSkipDefault, span},
		{"5", "span", span, pfSkipAllow, span, pfSkipAllow, span},
		{"6", "span", span, pfSkipAllow, span, pfSkipDisallow, "Hi"},
		{"7", "span", span, pfSkipDisallow, "Hi", pfSkipDefault, "Hi"},
		{"8", "span", span, pfSkipDisallow, "Hi", pfSkipAllow, span},
		{"9", "span", span, pfSkipDisallow, "Hi", pfSkipDisallow, "Hi"},
		// Not Default Skip Tag
		{"10", "p", p, pfSkipDefault, p, pfSkipDefault, p},
		{"11", "p", p, pfSkipDefault, p, pfSkipAllow, p},
		{"12", "p", p, pfSkipDefault, p, pfSkipDisallow, "Hi"},
		{"13", "p", p, pfSkipAllow, p, pfSkipDefault, p},
		{"14", "p", p, pfSkipAllow, p, pfSkipAllow, p},
		{"15", "p", p, pfSkipAllow, p, pfSkipDisallow, "Hi"},
		{"16", "p", p, pfSkipDisallow, "Hi", pfSkipDefault, "Hi"},
		{"17", "p", p, pfSkipDisallow, "Hi", pfSkipAllow, p},
		{"18", "p", p, pfSkipDisallow, "Hi", pfSkipDisallow, "Hi"},
	}
	for _, tc := range tests {
		beforePolicy := pfSkipFactory(t, tc.element, tc.before)
		pfAssertSanitize(t, tc.wantBefore, beforePolicy, tc.input, "HTMLTagSkipPolicy"+tc.name+" before")

		afterPolicy := beforePolicy.And(pfSkipFactory(t, tc.element, tc.after))
		pfAssertSanitize(t, tc.wantAfter, afterPolicy, tc.input, "HTMLTagSkipPolicy"+tc.name+" after")
	}
}
