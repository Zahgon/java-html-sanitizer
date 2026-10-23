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

// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/HtmlPolicyBuilderTest.java.

package sanitizer

import (
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// hpbExample is the document most of the builder tests sanitize.
var hpbExample = strings.Join([]string{
	"<h1 id='foo'>Header</h1>",
	"<p onclick='alert(42)'>Paragraph 1<script>evil()</script></p>",
	("<p><a href='java\x00script:bad()'>Click</a> <a href='foo.html'>me</a>" +
		" <a href='http://outside.org/'>out</a></p>"),
	("<p><img src=canary.png alt=local-canary>" +
		"<img src='http://canaries.org/canary.png'></p>"),
	"<p><b style=font-size:bigger>Fancy</b> with <i><b>soupy</i> tags</b>.",
	"<p style='color: expression(foo()); text-align: center;",
	"          /* direction: ltr */; font-weight: bold'>Stylish Para 1</p>",
	"<p style='color: red; font-weight; expression(foo());",
	"          direction: rtl; font-weight: bold'>Stylish Para 2</p>",
	"",
}, "\n")

// hpbLines joins lines with newlines.
func hpbLines(lines ...string) string {
	return strings.Join(lines, "\n")
}

// hpbFactory returns b's factory, failing the test on a configuration error.
func hpbFactory(t *testing.T, b *HTMLPolicyBuilder) *PolicyFactory {
	t.Helper()
	f, err := b.ToFactory()
	if err != nil {
		t.Fatalf("ToFactory: %v", err)
	}
	return f
}

// hpbSchema returns the schema with the named properties, failing the test on
// an error.
func hpbSchema(t *testing.T, propertyNames ...string) *CSSSchema {
	t.Helper()
	s, err := CSSSchemaWithProperties(propertyNames)
	if err != nil {
		t.Fatalf("CSSSchemaWithProperties(%q): %v", propertyNames, err)
	}
	return s
}

// hpbApplyExample sanitizes hpbExample with b's policy.
func hpbApplyExample(t *testing.T, b *HTMLPolicyBuilder) string {
	t.Helper()
	return hpbApply(t, b, hpbExample)
}

// hpbApply sanitizes src with b's policy; any renderer error fails the test.
func hpbApply(t *testing.T, b *HTMLPolicyBuilder, src string) string {
	t.Helper()
	factory := hpbFactory(t, b)
	var sb strings.Builder
	renderer := NewHTMLStreamRenderer(
		&sb,
		func(err error) { t.Errorf("renderer I/O error: %v", err) },
		func(errorMessage string) { t.Errorf("renderer error: %s", errorMessage) })
	Sanitize(src, factory.Apply(renderer), factory.preprocessor)
	return sb.String()
}

// hpbCheck reports a mismatch between want and got.
func hpbCheck(t *testing.T, want, got string, context ...any) {
	t.Helper()
	if got != want {
		if len(context) != 0 {
			t.Errorf("%s:\nwant %q\ngot  %q", fmt.Sprint(context...), want, got)
		} else {
			t.Errorf("\nwant %q\ngot  %q", want, got)
		}
	}
}

// hpbRename returns an element policy that renames every element to name.
func hpbRename(name string) ElementPolicy {
	return ElementPolicyFunc(func(string, *[]string) (string, bool) {
		return name, true
	})
}

// hpbRecorder returns an attribute policy that passes values through and
// appends each to *seen.
func hpbRecorder(seen *[]string) AttributePolicy {
	return AttributePolicyFunc(func(_, _, value string) (string, bool) {
		*seen = append(*seen, value)
		return value, true
	})
}

// hpbProcessorFunc adapts a function to HTMLStreamEventProcessor.
type hpbProcessorFunc func(sink HTMLStreamEventReceiver) HTMLStreamEventReceiver

// Wrap calls f(sink).
func (f hpbProcessorFunc) Wrap(sink HTMLStreamEventReceiver) HTMLStreamEventReceiver {
	return f(sink)
}

// hpbIncrHeader turns h1 into h2, h2 into h3, and so on.
func hpbIncrHeader(en string) string {
	if len(en) == 2 {
		c0, c1 := en[0], en[1]
		if (c0 == 'h' || c0 == 'H') && '0' <= c1 && c1 <= '6' {
			// h1 -> h2, h2 -> h3, etc.
			return "h" + strconv.Itoa(int(c1-'0')+1)
		}
	}
	return en
}

// hpbIncrHeaders increments header element names.
type hpbIncrHeaders struct {
	HTMLStreamEventReceiverWrapper
}

func (w *hpbIncrHeaders) OpenTag(elementName string, attrs []string) {
	w.Underlying.OpenTag(hpbIncrHeader(elementName), attrs)
}

func (w *hpbIncrHeaders) CloseTag(elementName string) {
	w.Underlying.CloseTag(hpbIncrHeader(elementName))
}

func (w *hpbIncrHeaders) String() string { return "incr-headers" }

// hpbShoutyText upper-cases text.
type hpbShoutyText struct {
	HTMLStreamEventReceiverWrapper
}

func (w *hpbShoutyText) Text(s string) {
	w.Underlying.Text(strings.ToUpper(s))
}

func (w *hpbShoutyText) String() string { return "shouty-text" }

// hpbCapitalizedText upper-cases the first code point of each non-empty text.
type hpbCapitalizedText struct {
	HTMLStreamEventReceiverWrapper
}

func (w *hpbCapitalizedText) Text(s string) {
	if s != "" {
		cp0, width := utf8.DecodeRuneInString(s)
		w.Underlying.Text(string(unicode.ToUpper(cp0)) + s[width:])
	}
}

func (w *hpbCapitalizedText) String() string { return "shouty-text" }

// AllowAttributes("style").Globally() installs a default schema so that
// styling is sanitized at all, but it must not overrule a schema the caller
// named -- in either order.  Unioning silently handed back DefaultCSSSchema
// to a caller who asked for something narrower.
func TestHTMLPolicyBuilderGloballyDoesNotWidenAnExplicitStylingSchema(t *testing.T) {
	colorOnly := hpbSchema(t, "color")
	css := "color:red;font-weight:bold;width:10px"

	globallyFirst := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("div").
		AllowAttributes("style").Globally().
		AllowStylingWithSchema(colorOnly))
	hpbCheck(t,
		"<div style=\"color:red\">x</div>",
		globallyFirst.Sanitize("<div style=\""+css+"\">x</div>"))

	stylingFirst := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("div").
		AllowStylingWithSchema(colorOnly).
		AllowAttributes("style").Globally())
	hpbCheck(t,
		"<div style=\"color:red\">x</div>",
		stylingFirst.Sanitize("<div style=\""+css+"\">x</div>"))
}

// With no explicit schema, allowing style globally still sanitizes it.
func TestHTMLPolicyBuilderGloballyStillInstallsADefaultStylingSchema(t *testing.T) {
	p := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("div").
		AllowAttributes("style").Globally())
	hpbCheck(t,
		"<div style=\"color:red\">x</div>",
		p.Sanitize("<div style=\"color:red;position:fixed\">x</div>"))
}

// Two explicit schemas still combine, which is the documented behaviour.
func TestHTMLPolicyBuilderTwoExplicitStylingSchemasStillUnion(t *testing.T) {
	p := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("div").
		AllowAttributes("style").OnElements("div").
		AllowStylingWithSchema(hpbSchema(t, "color")).
		AllowStylingWithSchema(hpbSchema(t, "font-weight")))
	hpbCheck(t,
		"<div style=\"color:red;font-weight:bold\">x</div>",
		p.Sanitize("<div style=\"color:red;font-weight:bold;width:10px\">x</div>"))
}

func TestHTMLPolicyBuilderExamplePolicies(t *testing.T) {
	tests := []struct {
		name    string
		builder func(t *testing.T) *HTMLPolicyBuilder
		want    string
	}{
		{
			name:    "TextFilter",
			builder: func(*testing.T) *HTMLPolicyBuilder { return NewHTMLPolicyBuilder() },
			want: hpbLines(
				"Header",
				"Paragraph 1",
				"Click me out",
				"",
				"Fancy with soupy tags.",
				"Stylish Para 1",
				"Stylish Para 2",
				""),
		},
		{
			name: "CannedFormattingTagFilter",
			builder: func(*testing.T) *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowCommonInlineFormattingElements()
			},
			want: hpbLines(
				"Header",
				"Paragraph 1",
				"Click me out",
				"",
				"<b>Fancy</b> with <i><b>soupy</b></i><b> tags</b>.",
				"Stylish Para 1",
				"Stylish Para 2",
				""),
		},
		{
			name: "CannedFormattingTagFilterNoItalics",
			builder: func(*testing.T) *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowCommonInlineFormattingElements().
					DisallowElements("I")
			},
			want: hpbLines(
				"Header",
				"Paragraph 1",
				"Click me out",
				"",
				"<b>Fancy</b> with <b>soupy</b><b> tags</b>.",
				"Stylish Para 1",
				"Stylish Para 2",
				""),
		},
		{
			name: "SimpleTagFilter",
			builder: func(*testing.T) *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowElements("h1", "i")
			},
			want: hpbLines(
				"<h1>Header</h1>",
				"Paragraph 1",
				"Click me out",
				"",
				"Fancy with <i>soupy</i> tags.",
				"Stylish Para 1",
				"Stylish Para 2",
				""),
		},
		{
			name: "LinksAllowed",
			builder: func(*testing.T) *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowElements("a").
					AllowAttributes("href").OnElements("a")
			},
			want: hpbLines(
				"Header",
				"Paragraph 1",
				// We haven't allowed any protocols so only relative URLs are OK.
				"Click <a href=\"foo.html\">me</a> out",
				"",
				"Fancy with soupy tags.",
				"Stylish Para 1",
				"Stylish Para 2",
				""),
		},
		{
			name: "ExternalLinksAllowed",
			builder: func(*testing.T) *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowElements("a").
					// Allows http.
					AllowStandardURLProtocols().
					AllowAttributes("href").OnElements("a")
			},
			want: hpbLines(
				"Header",
				"Paragraph 1",
				"Click <a href=\"foo.html\">me</a>"+
					" <a href=\"http://outside.org/\">out</a>",
				"",
				"Fancy with soupy tags.",
				"Stylish Para 1",
				"Stylish Para 2",
				""),
		},
		{
			name: "LinksWithNofollow",
			builder: func(*testing.T) *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowElements("a").
					// Allows http.
					AllowAttributes("href").OnElements("a").
					RequireRelNofollowOnLinks()
			},
			want: hpbLines(
				"Header",
				"Paragraph 1",
				"Click <a href=\"foo.html\" rel=\"nofollow\">me</a> out",
				"",
				"Fancy with soupy tags.",
				"Stylish Para 1",
				"Stylish Para 2",
				""),
		},
		{
			name: "ImagesAllowed",
			builder: func(*testing.T) *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowElements("img").
					AllowAttributes("src", "alt").OnElements("img").
					AllowURLProtocols("https")
			},
			want: hpbLines(
				"Header",
				"Paragraph 1",
				"Click me out",
				"<img src=\"canary.png\" alt=\"local-canary\" />",
				// HTTP img not output because only HTTPS allowed.
				"Fancy with soupy tags.",
				"Stylish Para 1",
				"Stylish Para 2",
				""),
		},
		{
			name: "StyleFiltering",
			builder: func(*testing.T) *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowCommonInlineFormattingElements().
					AllowCommonBlockElements().
					AllowStyling().
					AllowStandardURLProtocols()
			},
			want: hpbLines(
				"<h1>Header</h1>",
				"<p>Paragraph 1</p>",
				"<p>Click me out</p>",
				"<p></p>",
				"<p><b>Fancy</b> with <i><b>soupy</b></i><b> tags</b>.",
				("</p><p style=\"text-align:center;font-weight:bold\">" +
					"Stylish Para 1</p>"),
				("<p style=\"color:red;direction:rtl;font-weight:bold\">" +
					"Stylish Para 2</p>"),
				""),
		},
		{
			name: "SpecificStyleFilterung",
			builder: func(t *testing.T) *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowCommonInlineFormattingElements().
					AllowCommonBlockElements().
					AllowStylingWithSchema(hpbSchema(t, "color", "text-align", "font-size")).
					AllowStandardURLProtocols()
			},
			want: hpbLines(
				"<h1>Header</h1>",
				"<p>Paragraph 1</p>",
				"<p>Click me out</p>",
				"<p></p>",
				"<p><b>Fancy</b> with <i><b>soupy</b></i><b> tags</b>.",
				"</p><p style=\"text-align:center\">Stylish Para 1</p>",
				"<p style=\"color:red\">Stylish Para 2</p>",
				""),
		},
		{
			name: "CustomPropertyStyleFiltering",
			builder: func(t *testing.T) *HTMLPolicyBuilder {
				schema, err := CSSSchemaWithPropertyMap([]CSSSchemaNamedProperty{
					{Name: "text-align", Property: NewCSSSchemaProperty(0,
						map[string]struct{}{"center": {}},
						map[string]string{})},
				})
				if err != nil {
					t.Fatalf("CSSSchemaWithPropertyMap: %v", err)
				}
				return NewHTMLPolicyBuilder().
					AllowCommonInlineFormattingElements().
					AllowCommonBlockElements().
					AllowStylingWithSchema(schema).
					AllowStandardURLProtocols()
			},
			want: hpbLines(
				"<h1>Header</h1>",
				"<p>Paragraph 1</p>",
				"<p>Click me out</p>",
				"<p></p>",
				"<p><b>Fancy</b> with <i><b>soupy</b></i><b> tags</b>.",
				"</p><p style=\"text-align:center\">Stylish Para 1</p>",
				"<p>Stylish Para 2</p>",
				""),
		},
		{
			name: "UnionStyleFiltering",
			builder: func(t *testing.T) *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowCommonInlineFormattingElements().
					AllowCommonBlockElements().
					AllowStylingWithSchema(hpbSchema(t, "color", "text-align")).
					// union allowed style properties
					AllowStylingWithSchema(hpbSchema(t, "font-size")).
					AllowStandardURLProtocols()
			},
			want: hpbLines(
				"<h1>Header</h1>",
				"<p>Paragraph 1</p>",
				"<p>Click me out</p>",
				"<p></p>",
				"<p><b>Fancy</b> with <i><b>soupy</b></i><b> tags</b>.",
				"</p><p style=\"text-align:center\">Stylish Para 1</p>",
				"<p style=\"color:red\">Stylish Para 2</p>",
				""),
		},
		{
			name: "CustomPropertyStyleFilteringDisallowed",
			builder: func(t *testing.T) *HTMLPolicyBuilder {
				schema, err := CSSSchemaWithPropertyMap([]CSSSchemaNamedProperty{
					{Name: "text-align", Property: NewCSSSchemaProperty(0,
						map[string]struct{}{"left": {}, "right": {}},
						map[string]string{})},
				})
				if err != nil {
					t.Fatalf("CSSSchemaWithPropertyMap: %v", err)
				}
				return NewHTMLPolicyBuilder().
					AllowCommonInlineFormattingElements().
					AllowCommonBlockElements().
					AllowStylingWithSchema(schema).
					AllowStandardURLProtocols()
			},
			want: hpbLines(
				"<h1>Header</h1>",
				"<p>Paragraph 1</p>",
				"<p>Click me out</p>",
				"<p></p>",
				"<p><b>Fancy</b> with <i><b>soupy</b></i><b> tags</b>.",
				"</p><p>Stylish Para 1</p>",
				"<p>Stylish Para 2</p>",
				""),
		},
		{
			name: "ElementTransforming",
			builder: func(*testing.T) *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowElements("h1", "p", "div").
					AllowElementsWithPolicy(
						ElementPolicyFunc(func(elementName string, attrs *[]string) (string, bool) {
							*attrs = append(*attrs, "class", "header-"+elementName)
							return "div", true
						}),
						"h1")
			},
			want: hpbLines(
				"<div class=\"header-h1\">Header</div>",
				"<p>Paragraph 1</p>",
				"<p>Click me out</p>",
				"<p></p>",
				"<p>Fancy with soupy tags.",
				"</p><p>Stylish Para 1</p>",
				"<p>Stylish Para 2</p>",
				""),
		},
		{
			name: "AllowUrlProtocols",
			builder: func(*testing.T) *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowElements("img").
					AllowAttributes("src", "alt").OnElements("img").
					AllowURLProtocols("http")
			},
			want: hpbLines(
				"Header",
				"Paragraph 1",
				"Click me out",
				"<img src=\"canary.png\" alt=\"local-canary\" />"+
					"<img src=\"http://canaries.org/canary.png\" />",
				"Fancy with soupy tags.",
				"Stylish Para 1",
				"Stylish Para 2",
				""),
		},
		{
			name: "DisallowUrlProtocols",
			builder: func(*testing.T) *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowElements("img").
					AllowAttributes("src", "alt").OnElements("img").
					AllowURLProtocols("http", "https").
					DisallowURLProtocols("http")
			},
			want: hpbLines(
				"Header",
				"Paragraph 1",
				"Click me out",
				"<img src=\"canary.png\" alt=\"local-canary\" />",
				"Fancy with soupy tags.",
				"Stylish Para 1",
				"Stylish Para 2",
				""),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hpbCheck(t, test.want, hpbApplyExample(t, test.builder(t)))
		})
	}
}

// TestHTMLPolicyBuilderApply covers the tests that sanitize one input with
// one fixed builder.
func TestHTMLPolicyBuilderApply(t *testing.T) {
	tests := []struct {
		name    string
		builder func() *HTMLPolicyBuilder
		input   string
		want    string
	}{
		{
			name: "LinksWithNofollowAlreadyPresent",
			builder: func() *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowElements("a").
					AllowAttributes("href").OnElements("a").
					RequireRelNofollowOnLinks()
			},
			input: "html <a href='/' rel='nofollow'>link</a>",
			want:  "html <a href=\"/\" rel=\"nofollow\">link</a>",
		},
		{
			name: "BodyTransforming",
			builder: func() *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowElementsWithPolicy(hpbRename("div"), "body").
					AllowElements("div")
			},
			input: "<body>foo</body>",
			want:  "<div>foo</div>",
		},
		{
			name: "PossibleFalloutFromIssue5",
			builder: func() *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowElements("a").
					AllowAttributes("href").OnElements("a").
					AllowURLProtocols("http")
			},
			input: "<a href='javascript:alert(1337)//:http'>Bad</a>",
			want:  "Bad",
		},
		{
			name: "TextInOption",
			builder: func() *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowElements("select", "option")
			},
			input: "<select>\n  <option>1</option>\n  <option>2</option>\n</select>",
			want:  "<select><option>1</option><option>2</option></select>",
		},
		{
			name:    "Entities",
			builder: NewHTMLPolicyBuilder,
			input: "(Foo)&nbsp;(Bar)&diams;&#9830;&#x2666;&#X2666;(Baz)" +
				"\U00014834&#x14834;&#x014834;(Boo)",
			want: "(Foo)\u00a0(Bar)\u2666\u2666\u2666\u2666(Baz)" +
				"&#x14834;&#x14834;&#x14834;(Boo)",
		},
		{
			name: "ImageTag",
			builder: func() *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowElements("img").
					AllowElementsWithPolicy(hpbRename("img"), "image").
					AllowAttributes("src").OnElements("img", "image").
					AllowStandardURLProtocols()
			},
			input: "" +
				"<image src=\"http://example.com/foo.png\" />" +
				"<Image src=\"http://example.com/bar.png\">" +
				"<IMAGE>",
			want: "" +
				"<img src=\"http://example.com/foo.png\" />" +
				"<img src=\"http://example.com/bar.png\" />" +
				"<img />", // OK if this isn't here too.
		},
		{
			name: "ImgSrcsetSyntax",
			builder: func() *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowElements("img").
					AllowAttributes("srcset").OnElements("img").
					AllowStandardURLProtocols()
			},
			input: "" +
				"<img srcset=\"http://example.com/foo.png\" />\n" +
				"<img srcset=\"http://example.com/foo.png 640w\" />\n" +
				"<img srcset=\"http://example.com/foo.png 48x\" />\n" +
				"<img srcset=\"http://example.com/foo.png .123x\" />\n" +
				"<img srcset=\"http://example.com/foo.png .123e2x\" />\n" +
				"<img srcset=\"http://example.com/foo.png 123.456E-1x\" />\n" +
				"<img srcset=\"http://example.com/foo.png -123x\" />\n" +
				"no float: <img srcset=\"http://example.com/foo.png -x\" />\n" +
				"no fraction: <img srcset=\"http://example.com/foo.png -.e1\" />\n" +
				"no exponent: <img srcset=\"http://example.com/foo.png -1e+x\" />\n" +
				"<img srcset=\"/big.png 64w, /little.png\" />\n" +
				"<img srcset=\" /big.png 64w , /little.png\" />\n" +
				"<img srcset=\"\t\t/big.png 64w\r\n,/little.png\t\t\" />\n" +
				"<img srcset=\"foo,bar.png\" />\n" +
				"empty: <img srcset=\"\" />\n" +
				"only space: <img srcset=\"  \" />\n" +
				"only comma: <img srcset=\",\" />\n" +
				"comma at end: <img srcset=\"foo.png ,\" />\n" + // ok
				"comma stuck to url: <img srcset=\"bar.png,\" />\n" + // not ok
				"commas inside: <img srcset=\"foo.png,,bar.png\" />\n" + // escaped
				"double commas 1: <img srcset=\"a ,, b\" />\n" + // not ok
				"double commas 2: <img srcset=\"a , , b\" />\n" + // not ok
				"bad url: <img srcset=\"foo.png 1w, javascript:evil()\" />\n",
			want: "" +
				"<img srcset=\"http://example.com/foo.png\" />\n" +
				"<img srcset=\"http://example.com/foo.png 640w\" />\n" +
				"<img srcset=\"http://example.com/foo.png 48x\" />\n" +
				"<img srcset=\"http://example.com/foo.png .123x\" />\n" +
				"<img srcset=\"http://example.com/foo.png .123e2x\" />\n" +
				"<img srcset=\"http://example.com/foo.png 123.456E-1x\" />\n" +
				"<img srcset=\"http://example.com/foo.png -123x\" />\n" +
				"no float: \n" +
				"no fraction: \n" +
				"no exponent: \n" +
				"<img srcset=\"/big.png 64w , /little.png\" />\n" +
				"<img srcset=\"/big.png 64w , /little.png\" />\n" +
				"<img srcset=\"/big.png 64w , /little.png\" />\n" +
				"<img srcset=\"foo%2cbar.png\" />\n" +
				"empty: \n" +
				"only space: \n" +
				"only comma: \n" +
				"comma at end: <img srcset=\"foo.png\" />\n" +
				"comma stuck to url: \n" +
				"commas inside: <img srcset=\"foo.png%2c%2cbar.png\" />\n" +
				"double commas 1: \n" +
				"double commas 2: \n" +
				"bad url: <img srcset=\"foo.png 1w\" />\n",
		},
		{
			name: "UrlChecksLayer",
			builder: func() *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowElements("img").
					AllowAttributes("src", "srcset").
					MatchingPattern(regexp.MustCompile(".*OK.*")).
					OnElements("img").
					AllowStandardURLProtocols()
			},
			input: "" +
				"<img src=\"http://example.com/OK.png\" />\n" +
				"<img src=\"http://example.com/\" />\n" +
				"<img srcset=\"http://example.com/bar.png#OK 1w, javascript:alert%28%27OK%27%29\">",
			want: "" +
				"<img src=\"http://example.com/OK.png\" />\n" +
				"\n" +
				"<img srcset=\"http://example.com/bar.png#OK 1w\" />",
		},
		{
			// The duplicate-attribute scan walks a flat list of alternating
			// names and values, so it has to compare names against names.  It
			// used to compare against values too, which dropped an attribute
			// whose name matched an earlier attribute's value.
			//
			// Reaching that comparison takes three attributes, not two: the
			// scan only runs once the attribute's first letter has already
			// been seen on the tag, so sizes is here to put s in play and send
			// src down the scan path, where it used to collide with alt's
			// value.  Without an attribute in that role the test passes either
			// way.
			name: "AttributeNameMatchingAnEarlierValueIsNotADuplicate",
			builder: func() *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowElements("img").
					AllowAttributes("sizes", "alt", "src").OnElements("img").
					AllowURLProtocols("http", "https")
			},
			input: "<img sizes=\"100vw\" alt=\"src\"" +
				" src=\"http://example.com/a.png\">",
			want: "<img sizes=\"100vw\" alt=\"src\"" +
				" src=\"http://example.com/a.png\" />",
		},
		{
			// Genuine repeats are still dropped, keeping the first.
			name: "RepeatedAttributeNamesStillCollapseToTheFirst",
			builder: func() *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowElements("img").
					AllowAttributes("alt").OnElements("img")
			},
			input: "<img alt=\"first\" ALT=\"second\" alt=\"third\">",
			want:  "<img alt=\"first\" />",
		},
		{
			name: "DirLi",
			builder: func() *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowElements("dir", "li", "ul").
					AllowAttributes("compact").OnElements("dir")
			},
			input: "<dir compact=\"compact\"><li>something</li></dir>",
			want:  "<dir compact=\"compact\"><li>something</li></dir>",
		},
		{
			// The input from #113: children of a template came out as its
			// siblings.
			name: "TemplateKeepsItsChildren",
			builder: func() *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowElements("template", "b", "a").
					AllowAttributes("id").OnElements("template").
					AllowAttributes("href").OnElements("a").
					AllowStandardURLProtocols()
			},
			input: "<template id=\"something\"><b>" +
				"<a href=https://www.google.com> google </a></b></template>",
			want: "<template id=\"something\"><b>" +
				"<a href=\"https://www.google.com\"> google </a></b></template>",
		},
		{
			// The doc comment of DisallowTextIn names <template> as the element it
			// exists for.  While the tables said a template could hold no
			// text, the balancer moved the text out before the policy could
			// suppress it.
			name: "DisallowTextInTemplate",
			builder: func() *HTMLPolicyBuilder {
				return NewHTMLPolicyBuilder().
					AllowElements("template", "h1").
					DisallowTextIn("template")
			},
			input: "<h1>allowed text</h1><template>excluded-text</template>",
			want:  "<h1>allowed text</h1><template></template>",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hpbCheck(t, test.want, hpbApply(t, test.builder(), test.input))
		})
	}
}

// DisallowAttributes rejects every value, and joining a policy onto one that
// already rejects everything cannot widen it, so a Matching call after
// DisallowAttributes does nothing.  Pinned because it reads as though it
// should reject only the matching values.
func TestHTMLPolicyBuilderMatchingAfterDisallowAttributesHasNoEffect(t *testing.T) {
	withMatching := hpbApply(t,
		NewHTMLPolicyBuilder().
			AllowURLProtocols("http", "https").
			AllowElements("img").
			AllowAttributes("src").OnElements("img").
			DisallowAttributes("src").
			MatchingPattern(regexp.MustCompile(".*example.*")).OnElements("img"),
		"<img src=\"http://other.example/a.png\">")

	hpbCheck(t, "", withMatching, "the non-matching src is dropped too")
}

// The URL protocol guard runs after the policies an author attaches with
// Matching, so it vets what they produce: a rewrite cannot hand the output a
// protocol the builder did not allow, while a rewrite to an allowed one
// survives.
func TestHTMLPolicyBuilderURLProtocolGuardVetsWhatAMatchingPolicyProduces(t *testing.T) {
	hpbCheck(t,
		"x",
		hpbApply(t,
			NewHTMLPolicyBuilder().
				AllowElements("a").
				AllowAttributes("href").
				Matching(AttributePolicyFunc(func(_, _, value string) (string, bool) {
					return "javascript:" + value, true
				})).
				OnElements("a").
				AllowURLProtocols("http"),
			"<a href='/x'>x</a>"))
	hpbCheck(t,
		"<a href=\"http://example.com/x\">x</a>",
		hpbApply(t,
			NewHTMLPolicyBuilder().
				AllowElements("a").
				AllowAttributes("href").
				Matching(AttributePolicyFunc(func(_, _, value string) (string, bool) {
					return "http://example.com" + value, true
				})).
				OnElements("a").
				AllowURLProtocols("http"),
			"<a href='/x'>x</a>"))
}

// Issue #454.  A matching policy on a URL attribute runs before the protocol
// guard, so it sees the value as written, after entity decoding but before
// the guard trims whitespace and percent-encodes parentheses, and before the
// guard has rejected anything.  A pattern that expects the normalized form
// rejects the raw one, which fails closed.
func TestHTMLPolicyBuilderMatchingPoliciesSeeTheURLAsWrittenBeforeTheProtocolGuard(t *testing.T) {
	var seen []string
	record := hpbRecorder(&seen)
	links := "<a href=\" http://example.com/a&#40;b) \">x</a>" +
		"<a href=\"javascript:alert(1)\">y</a>"

	hpbCheck(t,
		"<a href=\"http://example.com/a%28b%29\">x</a>y",
		hpbApply(t,
			NewHTMLPolicyBuilder().
				AllowElements("a").
				AllowAttributes("href").Matching(record).OnElements("a").
				AllowURLProtocols("http"),
			links))
	if want := []string{" http://example.com/a(b) ", "javascript:alert(1)"}; !slices.Equal(want, seen) {
		t.Errorf("seen: want %q, got %q", want, seen)
	}

	normalized := regexp.MustCompile(`http://example\.com/a%28b%29`)
	asWritten := regexp.MustCompile(` http://example\.com/a\(b\) `)
	hpbCheck(t,
		"xy",
		hpbApply(t,
			NewHTMLPolicyBuilder().
				AllowElements("a").
				AllowAttributes("href").MatchingPattern(normalized).OnElements("a").
				AllowURLProtocols("http"),
			links))
	hpbCheck(t,
		"<a href=\"http://example.com/a%28b%29\">x</a>y",
		hpbApply(t,
			NewHTMLPolicyBuilder().
				AllowElements("a").
				AllowAttributes("href").MatchingPattern(asWritten).OnElements("a").
				AllowURLProtocols("http"),
			links))
}

// Issue #454.  A policy that rewrites one URL into another is handed the
// unvetted value, so a redirector that wraps it produces an allowed URL that
// carries a protocol the builder never allowed.  The guard passes that, as it
// should, so the rewriter has to vet the protocol itself, which putting a
// FilterURLByProtocolAttributePolicy ahead of it does.
func TestHTMLPolicyBuilderARewritingPolicyMustVetTheProtocolItself(t *testing.T) {
	redirector := AttributePolicyFunc(func(_, _, url string) (string, bool) {
		return "https://example.com/go?u=" + url, true
	})
	links := "<a href=\"javascript:alert(1)\">x</a>" +
		"<a href=\"https://other.example/p\">y</a>"

	hpbCheck(t,
		"<a href=\"https://example.com/go?u&#61;javascript:alert%281%29\">x</a>"+
			"<a href=\"https://example.com/go?u&#61;https://other.example/p\">"+
			"y</a>",
		hpbApply(t,
			NewHTMLPolicyBuilder().
				AllowElements("a").
				AllowAttributes("href").Matching(redirector).OnElements("a").
				AllowURLProtocols("https"),
			links))

	hpbCheck(t,
		"x"+
			"<a href=\"https://example.com/go?u&#61;https://other.example/p\">"+
			"y</a>",
		hpbApply(t,
			NewHTMLPolicyBuilder().
				AllowElements("a").
				AllowAttributes("href").
				Matching(NewFilterURLByProtocolAttributePolicy([]string{"https"})).
				Matching(redirector).
				OnElements("a").
				AllowURLProtocols("https"),
			links))
}

// Issue #454.  The policy given to AllowURLsInStyles runs before the protocol
// guard too, so it is consulted even when no protocol was allowed, sees a
// javascript: URL the guard goes on to drop, and on its own admits only
// relative URLs.
func TestHTMLPolicyBuilderStyleURLPolicyRunsBeforeTheProtocolGuard(t *testing.T) {
	var seen []string
	record := hpbRecorder(&seen)
	images := hpbSchema(t, "background-image")

	hpbCheck(t,
		"<div>x</div>"+
			"<div style=\"background-image:url(&#39;/i.png&#39;)\">y</div>",
		hpbApply(t,
			NewHTMLPolicyBuilder().
				AllowElements("div").
				AllowAttributes("style").OnElements("div").
				AllowStylingWithSchema(images).
				AllowURLsInStyles(record),
			"<div style=\"background-image: url(javascript:alert%281%29)\">"+
				"x</div>"+
				"<div style=\"background-image: url(/i.png)\">y</div>"))
	if want := []string{"javascript:alert%281%29", "/i.png"}; !slices.Equal(want, seen) {
		t.Errorf("seen: want %q, got %q", want, seen)
	}
}

// Rejecting only some values means allowing the rest.
func TestHTMLPolicyBuilderAnInvertedAllowRejectsOnlyTheMatchingValues(t *testing.T) {
	b := NewHTMLPolicyBuilder().
		AllowURLProtocols("http", "https").
		AllowElements("img").
		AllowAttributes("src").
		Matching(AttributePolicyFunc(func(_, _, value string) (string, bool) {
			if strings.Contains(value, "example") {
				return "", false
			}
			return value, true
		})).
		OnElements("img")

	hpbCheck(t,
		"<img src=\"http://other.test/a.png\" />",
		hpbApply(t, b, "<img src=\"http://other.test/a.png\">"))
	hpbCheck(t,
		"", hpbApply(t, b, "<img src=\"http://other.example/a.png\">"))
}

// The predicate form of Matching keeps the values the predicate accepts and
// drops the rest, just as the pattern one does.
func TestHTMLPolicyBuilderMatchingPredicateKeepsOnlyAcceptedValues(t *testing.T) {
	isNote := func(value string) bool { return strings.HasPrefix(value, "note-") }
	b := NewHTMLPolicyBuilder().
		AllowElements("p").
		AllowAttributes("class").
		MatchingPredicate(isNote).
		OnElements("p")

	hpbCheck(t,
		"<p class=\"note-aside\">Hi</p>",
		hpbApply(t, b, "<p class=\"note-aside\">Hi</p>"))
	hpbCheck(t,
		"<p>Hi</p>", hpbApply(t, b, "<p class=\"warning\">Hi</p>"),
		"the attribute goes, the element stays")
}

// TestHTMLPolicyBuilderMatchingAcceptsAPredicateOverLength checks a value
// predicate that looks only at the value's length.
func TestHTMLPolicyBuilderMatchingAcceptsAPredicateOverLength(t *testing.T) {
	isNotEmpty := func(value string) bool { return len(value) != 0 }
	b := NewHTMLPolicyBuilder().
		AllowElements("p").
		AllowAttributes("title").
		MatchingPredicate(isNotEmpty).
		OnElements("p")

	hpbCheck(t, "<p title=\"t\">Hi</p>", hpbApply(t, b, "<p title=\"t\">Hi</p>"))
	hpbCheck(t, "<p>Hi</p>", hpbApply(t, b, "<p title=\"\">Hi</p>"))
}

// The ignoreCase flag of the value-set forms picks whether the value is
// lower-cased before it is looked up.  Every caller in the suite passed true,
// so the case-sensitive arm -- the one that compares the value as written --
// went unexercised.
func TestHTMLPolicyBuilderMatchingComparesValuesAsWrittenUnlessIgnoringCase(t *testing.T) {
	caseSensitive := NewHTMLPolicyBuilder().
		AllowElements("p").
		AllowAttributes("class").
		MatchingValues(false, "Note").
		OnElements("p")

	hpbCheck(t,
		"<p class=\"Note\">Hi</p>",
		hpbApply(t, caseSensitive, "<p class=\"Note\">Hi</p>"))
	hpbCheck(t,
		"<p>Hi</p>", hpbApply(t, caseSensitive, "<p class=\"note\">Hi</p>"),
		"a value that differs in case is not one of the allowed values")

	ignoringCase := NewHTMLPolicyBuilder().
		AllowElements("p").
		AllowAttributes("class").
		MatchingValues(true, "note").
		OnElements("p")

	hpbCheck(t,
		"<p class=\"note\">Hi</p>",
		hpbApply(t, ignoringCase, "<p class=\"Note\">Hi</p>"),
		"ignoring case keeps the lower-cased value, not the one written")
}

// ignoreCase lower-cases the value it looks up but not the values it looks
// them up in, so an allowed value that is not already lower-case can never
// be matched and the policy rejects everything.  It fails closed, but
// silently: pinned so the asymmetry is visible to anyone changing it.
func TestHTMLPolicyBuilderMatchingIgnoringCaseNeverMatchesAnUpperCaseAllowedValue(t *testing.T) {
	b := NewHTMLPolicyBuilder().
		AllowElements("p").
		AllowAttributes("class").
		MatchingValues(true, "Note").
		OnElements("p")

	for _, written := range []string{"Note", "note", "NOTE"} {
		hpbCheck(t,
			"<p>Hi</p>", hpbApply(t, b, "<p class=\""+written+"\">Hi</p>"),
			"nothing matches the allowed value `Note`")
	}
}

func TestHTMLPolicyBuilderDuplicateAttributesDoNotReachElementPolicy(t *testing.T) {
	idCount := 0
	hpbCheck(t,
		// The id that is emitted is the first that passes the attribute
		// starts-with-b filter.
		// The attribute policy sees 3 id elements, hence id-count=3.
		// The element policy sees 2 attributes, one "id" and one "href",
		// hence attr-count=2.
		"<a href=\"foo\" id=\"bar\" attr-count=\"2\" id-count=\"3\">link</a>",

		hpbApply(t,
			NewHTMLPolicyBuilder().
				AllowElementsWithPolicy(
					ElementPolicyFunc(func(elementName string, attrs *[]string) (string, bool) {
						nAttrs := len(*attrs) / 2
						*attrs = append(*attrs,
							"attr-count", strconv.Itoa(nAttrs),
							"id-count", strconv.Itoa(idCount))
						return elementName, true
					}),
					"a").
				AllowAttributes("id").Matching(
				AttributePolicyFunc(func(_, _, value string) (string, bool) {
					idCount++
					if strings.HasPrefix(value, "b") {
						return value, true
					}
					return "", false
				})).
				OnElements("a").
				AllowAttributes("href").OnElements("a"),
			"<a href=\"foo\" id='far' id=\"bar\" href=baz id=boo>link</a>"))
}

func TestHTMLPolicyBuilderPreprocessors(t *testing.T) {
	input := "<h1 title='foo'>one</h1> <h2>Two!</h2> <h3>three</h3>" +
		" <h4>Four</h4> <h5>5</h5> <h6>seis</h6>"
	// We upper-case all text nodes and increment all header elements.
	// Since h7 is not allowed, the incremented version of <h6> is dropped.
	// The title attribute value is not upper-cased.
	expected := "<h2 title=\"foo\">ONE</h2> <h3>TWO!</h3> <h4>THREE</h4>" +
		" <h5>FOUR</h5> <h6>5</h6> SEIS"
	hpbCheck(t,
		expected,

		hpbApply(t,
			NewHTMLPolicyBuilder().
				AllowElements("h1", "h2", "h3", "h4", "h5", "h6").
				AllowAttributes("title").Globally().
				WithPreprocessor(hpbProcessorFunc(func(r HTMLStreamEventReceiver) HTMLStreamEventReceiver {
					return &hpbShoutyText{HTMLStreamEventReceiverWrapper{Underlying: r}}
				})).
				WithPreprocessor(hpbProcessorFunc(func(r HTMLStreamEventReceiver) HTMLStreamEventReceiver {
					return &hpbIncrHeaders{HTMLStreamEventReceiverWrapper{Underlying: r}}
				})),

			input))
}

func TestHTMLPolicyBuilderPostprocessors(t *testing.T) {
	input := "<h1 title='foo'>one</h1> <h2>TWO!</h2> <h3>three</h3>" +
		" <h4>Four</h4> <h5>5</h5> <h6>seis</h6>"
	// We upper-case the first letter of each text nodes and increment all
	// header elements.
	// Since post-processors run after the policy, they can insert elements
	// like <h7> which are not allowed.
	expected := "<h2 title=\"foo\">One</h2> <h3>TWO!</h3> <h4>Three</h4>" +
		" <h5>Four</h5> <h6>5</h6> <h7>Seis</h7>"
	hpbCheck(t,
		expected,

		hpbApply(t,
			NewHTMLPolicyBuilder().
				AllowElements("h1", "h2", "h3", "h4", "h5", "h6").
				AllowAttributes("title").Globally().
				WithPostprocessor(hpbProcessorFunc(func(r HTMLStreamEventReceiver) HTMLStreamEventReceiver {
					return &hpbCapitalizedText{HTMLStreamEventReceiverWrapper{Underlying: r}}
				})).
				WithPostprocessor(hpbProcessorFunc(func(r HTMLStreamEventReceiver) HTMLStreamEventReceiver {
					return &hpbIncrHeaders{HTMLStreamEventReceiverWrapper{Underlying: r}}
				})),

			input))
}

func TestHTMLPolicyBuilderBackgroundImageWithURL(t *testing.T) {
	policy := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowStandardURLProtocols().
		AllowStyling().
		AllowURLsInStyles(IdentityAttributePolicy).
		AllowElements("div"))
	unsafeHTML := policy.Sanitize(
		"<html><head><title>test</title></head><body>" +
			"<div style='" +
			"color: red; background-image: " +
			"url(http://example.com/foo.png)" +
			"'>div content" +
			"</div></body></html>")
	safeHTML := policy.Sanitize(unsafeHTML)
	expected := "<div style=\"" +
		"color:red;background-image:" +
		"url(&#39;http://example.com/foo.png&#39;)" +
		"\">div content</div>"
	hpbCheck(t, expected, safeHTML)
}

func TestHTMLPolicyBuilderCalcInStyleAttribute(t *testing.T) {
	policy := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowStyling().
		AllowElements("div"))
	hpbCheck(t,
		"<div style=\"width:calc( 100% - 20px );"+
			"max-height:calc( ( 50% - 2em ) / 2 )\">x</div>",
		policy.Sanitize(
			"<div style=\"width: calc(100% - 20px);"+
				" max-height: calc((50% - 2em) / 2)\">x</div>"))
	// Nothing executable or URL-bearing survives inside calc().
	hpbCheck(t,
		"<div style=\"width:calc( )\">x</div>",
		policy.Sanitize(
			"<div style=\"width: calc(expression(alert(1)))\">x</div>"))
	hpbCheck(t,
		"<div style=\"width:calc( 100% - )\">x</div>",
		policy.Sanitize(
			"<div style=\"width: calc(100% - url(//evil.org/x))\">x</div>"))
}

func TestHTMLPolicyBuilderBackgroundImageWithImageFunction(t *testing.T) {
	policy := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowStandardURLProtocols().
		AllowStyling().
		AllowURLsInStyles(IdentityAttributePolicy).
		AllowElements("div"))
	unsafeHTML := policy.Sanitize(
		"<html><head><title>test</title></head><body>" +
			"<div style='" +
			"color: red; background-image: " +
			"image(\"blue sky.png\", blue)'>" +
			"div content" +
			"</div></body></html>")
	safeHTML := policy.Sanitize(unsafeHTML)
	expected := "<div style=\"" +
		"color:red;background-image:" +
		"image( url(&#39;blue%20sky.png&#39;) , blue )" +
		"\">div content</div>"
	hpbCheck(t, expected, safeHTML)
}

func TestHTMLPolicyBuilderBackgroundWithURLs(t *testing.T) {
	builder := NewHTMLPolicyBuilder().
		AllowStandardURLProtocols().
		AllowStyling().
		AllowElements("div")

	noURLsPolicy := hpbFactory(t, builder)
	urlsPolicy := hpbFactory(t, builder.
		AllowURLsInStyles(IdentityAttributePolicy))

	unsafeHTML := "<div style=\"background:&quot;//evil.org/foo.png&quot;\"></div>"

	safeWithURLs := "<div style=\"background:url(&#39;//evil.org/foo.png&#39;)\"></div>"
	safeWithoutURLs := "<div></div>"

	hpbCheck(t, safeWithoutURLs, noURLsPolicy.Sanitize(unsafeHTML))
	hpbCheck(t, safeWithURLs, urlsPolicy.Sanitize(unsafeHTML))
}

func TestHTMLPolicyBuilderBackgroundsThatViolateGlobalURLPolicy(t *testing.T) {
	policy := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowStandardURLProtocols().
		AllowStyling().
		AllowElements("div").
		AllowURLsInStyles(IdentityAttributePolicy))

	unsafeHTML := "<div style=\"background:'javascript:alert(1337)'\"></div>"
	safeHTML := "<div></div>"

	hpbCheck(t, safeHTML, policy.Sanitize(unsafeHTML))
}

func TestHTMLPolicyBuilderSpanTagFilter(t *testing.T) {
	policy := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("span").
		AllowWithoutAttributes("span"))
	unsafeHTML := policy.Sanitize("<span>test1</span>")
	safeHTML := policy.Sanitize(unsafeHTML)
	expected := "<span>test1</span>"
	hpbCheck(t, expected, safeHTML)
}

func TestHTMLPolicyBuilderLinkRels(t *testing.T) {
	b := NewHTMLPolicyBuilder().
		AllowElements("a").
		AllowAttributes("href").OnElements("a").
		AllowAttributes("rel").OnElements("a").
		AllowAttributes("target").OnElements("a").
		AllowStandardURLProtocols()

	defaultLinkPolicy := hpbFactory(t, b)
	externalLinkPolicy := hpbFactory(t, b.
		RequireRelsOnLinks("external"))
	noNoFollowPolicy := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a").
		AllowAttributes("href").OnElements("a").
		AllowStandardURLProtocols().
		AllowAttributes("target").OnElements("a").
		SkipRelsOnLinks("noreferrer"))

	and0 := externalLinkPolicy.And(noNoFollowPolicy)
	and1 := noNoFollowPolicy.And(externalLinkPolicy)

	link := "<a target=T href=http://example.com/>eg</a>"

	hpbCheck(t,
		"<a target=\"T\" href=\"http://example.com/\""+
			" rel=\"noopener noreferrer\">eg</a>",
		defaultLinkPolicy.Sanitize(link), "default")
	hpbCheck(t,
		"<a target=\"T\" href=\"http://example.com/\""+
			" rel=\"external noopener noreferrer\">eg</a>",
		externalLinkPolicy.Sanitize(link), "external")
	hpbCheck(t,
		"<a target=\"T\" href=\"http://example.com/\""+
			" rel=\"noopener\">eg</a>",
		noNoFollowPolicy.Sanitize(link), "noNoFollow")
	hpbCheck(t,
		"<a target=\"T\" href=\"http://example.com/\""+
			" rel=\"external noopener\">eg</a>",
		and0.Sanitize(link), "and0")
	hpbCheck(t,
		"<a target=\"T\" href=\"http://example.com/\""+
			" rel=\"external noopener\">eg</a>",
		and1.Sanitize(link), "and1")
}

func TestHTMLPolicyBuilderLinkRelsWhenRelPresent(t *testing.T) {
	pf := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a").
		AllowAttributes("href").OnElements("a").
		AllowAttributes("rel").OnElements("a").
		AllowAttributes("target").OnElements("a").
		AllowStandardURLProtocols().
		RequireRelNofollowOnLinks())

	hpbCheck(t,
		""+
			"<a rel=\"external nofollow noopener noreferrer\""+
			" target=\"_blank\" href=\"http://example.com/\">eg</a>",

		pf.Sanitize(
			"<a rel=external target=_blank href=http://example.com/>eg</a>"))

	hpbCheck(t,
		""+
			"<a rel=\"external nofollow noopener noreferrer\""+
			" target=\"windowname\" href=\"//example.com/\">eg</a>",

		pf.Sanitize(
			"<A REL=external TARGET=windowname HREF=//example.com/ >eg</A>"))
}

// hpbLinkBuilder allows links with href, rel and target and the standard
// protocols.
func hpbLinkBuilder() *HTMLPolicyBuilder {
	return NewHTMLPolicyBuilder().
		AllowElements("a").
		AllowAttributes("href").OnElements("a").
		AllowAttributes("rel").OnElements("a").
		AllowAttributes("target").OnElements("a").
		AllowStandardURLProtocols()
}

func TestHTMLPolicyBuilderRelLinksWhenRelIsPartOfData(t *testing.T) {
	pf := hpbFactory(t, hpbLinkBuilder())
	toSanitize := "<a target=\"_blank\" rel=\"noopener noreferrer\" href=\"https://google.com\">test</a>"
	hpbCheck(t, toSanitize, pf.Sanitize(toSanitize))
}

func TestHTMLPolicyBuilderRelLinksWithDuplicateRels(t *testing.T) {
	pf := hpbFactory(t, hpbLinkBuilder())
	hpbCheck(t,
		"<a target=\"_blank\" rel=\"noopener noreferrer\" href=\"https://google.com\">test</a>",
		pf.Sanitize("<a target=\"_blank\" rel=\"noopener noreferrer noreferrer\" href=\"https://google.com\">test</a>"))
}

func TestHTMLPolicyBuilderRelLinksWithDuplicateRelsRequired(t *testing.T) {
	pf := hpbFactory(t, hpbLinkBuilder().
		RequireRelsOnLinks("noreferrer"))
	hpbCheck(t,
		"<a target=\"_blank\" rel=\"noopener noreferrer\" href=\"https://google.com\">test</a>",
		pf.Sanitize("<a target=\"_blank\" rel=\"noopener noreferrer noreferrer\" href=\"https://google.com\">test</a>"))
}

func TestHTMLPolicyBuilderFailFastOnSpaceSeparatedStrings(t *testing.T) {
	// Should be ("nofollow", "noreferrer")
	const want = "spaces in input.  use f(\"foo\", \"bar\") not f(\"foo bar\")"
	for name, b := range map[string]*HTMLPolicyBuilder{
		"RequireRelsOnLinks": NewHTMLPolicyBuilder().RequireRelsOnLinks("nofollow noreferrer"),
		"SkipRelsOnLinks":    NewHTMLPolicyBuilder().SkipRelsOnLinks("nofollow noreferrer"),
	} {
		f, err := b.ToFactory()
		if err == nil {
			t.Errorf("%s: want an error, got factory %v", name, f)
		} else if err.Error() != want {
			t.Errorf("%s: want error %q, got %q", name, want, err.Error())
		}
	}
}

func TestHTMLPolicyBuilderEmptyDefaultLinkRelsSet(t *testing.T) {
	pf := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a").
		AllowAttributes("href", "target").OnElements("a").
		AllowStandardURLProtocols().
		SkipRelsOnLinks("noopener", "noreferrer"))

	hpbCheck(t,
		"<a href=\"http://example.com\" target=\"_blank\">eg</a>",
		pf.Sanitize("<a href=\"http://example.com\" target=\"_blank\">eg</a>"))
}

func TestHTMLPolicyBuilderRequireAndSkipRels(t *testing.T) {
	pf := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a").
		AllowAttributes("href", "target").OnElements("a").
		AllowStandardURLProtocols().
		RequireRelsOnLinks("noreferrer").
		SkipRelsOnLinks("noopener", "noreferrer"))

	hpbCheck(t,
		"<a href=\"http://example.com\" target=\"_blank\">eg</a>",
		pf.Sanitize("<a href=\"http://example.com\" target=\"_blank\">eg</a>"))

	hpbCheck(t,
		"<a href=\"http://example.com\" target=\"_blank\">eg</a>",
		pf.Sanitize("<a href=\"http://example.com\" rel=noreferrer target=\"_blank\">eg</a>"))

	hpbCheck(t,
		"<a href=\"http://example.com\" target=\"_blank\">eg</a>",
		pf.Sanitize("<a href=\"http://example.com\" rel=noopener target=\"_blank\">eg</a>"))
}

func TestHTMLPolicyBuilderSkipAndRequireRels(t *testing.T) {
	pf := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a").
		AllowAttributes("href", "target").OnElements("a").
		AllowStandardURLProtocols().
		SkipRelsOnLinks("noopener", "noreferrer").
		RequireRelsOnLinks("noreferrer"))

	hpbCheck(t,
		"<a href=\"http://example.com\" target=\"_blank\" rel=\"noreferrer\">eg</a>",
		pf.Sanitize("<a href=\"http://example.com\" target=\"_blank\">eg</a>"))

	hpbCheck(t,
		"<a href=\"http://example.com\" target=\"_blank\" rel=\"noreferrer\">eg</a>",
		pf.Sanitize("<a href=\"http://example.com\" rel=noreferrer target=\"_blank\">eg</a>"))

	hpbCheck(t,
		"<a href=\"http://example.com\" target=\"_blank\" rel=\"noreferrer\">eg</a>",
		pf.Sanitize("<a href=\"http://example.com\" rel=noopener target=\"_blank\">eg</a>"))
}

func TestHTMLPolicyBuilderOverflowWrap(t *testing.T) {
	union, err := CSSSchemaUnion(DefaultCSSSchema, hpbSchema(t, "overflow-wrap"))
	if err != nil {
		t.Fatalf("CSSSchemaUnion: %v", err)
	}
	pf := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("span").
		AllowStylingWithSchema(union))

	hpbCheck(t,
		"<span style=\"overflow-wrap:anywhere\">Something</span>",
		pf.Sanitize("<span style=\"overflow-wrap: anywhere\">Something</span>"))

	hpbCheck(t,
		"<span style=\"overflow-wrap:inherit\">Something</span>",
		pf.Sanitize("<span style=\"overflow-wrap: inherit\">Something</span>"))

	hpbCheck(t,
		"Something",
		pf.Sanitize("<span style=\"overflow-wrap: something\">Something</span>"))
}

func TestHTMLPolicyBuilderOverflowWrapNotAllowed(t *testing.T) {
	pf := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("span").
		AllowStyling())

	hpbCheck(t,
		"Something",
		pf.Sanitize("<span style=\"overflow-wrap: anywhere\">Something</span>"))
}

func TestHTMLPolicyBuilderExplicitRelsSkip(t *testing.T) {
	pf := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a").
		AllowAttributes("href", "target", "rel").OnElements("a").
		AllowStandardURLProtocols().
		SkipRelsOnLinks("noopener", "noreferrer"))

	hpbCheck(t,
		"<a href=\"http://example.com\" target=\"_blank\">text</a>",
		pf.Sanitize(
			"<a href=\"http://example.com\" target=\"_blank\""+
				" rel=\"noopener\">text</a>"))
	hpbCheck(t,
		"<a href=\"http://example.com\" target=\"_blank\">text</a>",
		pf.Sanitize(
			"<a href=\"http://example.com\" target=\"_blank\""+
				" rel=\"noreferrer noopener\">text</a>"))
	hpbCheck(t,
		"<a href=\"http://example.com\" target=\"_blank\" rel=\"nofoo nobar nobaz\">text</a>",
		pf.Sanitize(
			"<a href=\"http://example.com\" target=\"_blank\""+
				" rel=\"nofoo noopener nobar  NOREFERRER nobaz \">text</a>"))
}

func TestHTMLPolicyBuilderScopingExitInNoContent(t *testing.T) {
	pf := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tr", "td", "noscript"))

	hpbCheck(t,
		"<table><tr><td>foo<noscript></noscript></td><td>bar</td></tr></table>",
		pf.Sanitize("<table><tr><td>foo<noscript></table></noscript><td>bar"))
}

func TestHTMLPolicyBuilderIssue80(t *testing.T) {
	pf := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tr", "td", "tbody"))

	hpbCheck(t,
		"<table><tbody>"+
			"<tr><td>td1</td><td>td2</td></tr>"+
			"<tr><td>new line</td></tr>"+
			"</tbody></table>",
		pf.Sanitize(
			"<table><tbody>"+
				"<tr><td>td1</td><td>td2</tr>"+
				"<td>new line</tbody></table>"))
}

func TestHTMLPolicyBuilderDisallowTextIn(t *testing.T) {
	sharedPolicyBuilder := NewHTMLPolicyBuilder().
		AllowElements("div").
		AllowAttributes("style").OnElements("div")

	allowPolicy := hpbFactory(t, sharedPolicyBuilder)
	hpbCheck(t, "<div style=\"display:node\">Some Text</div>",
		allowPolicy.Sanitize("<div style=\"display:node\">Some Text</div>"))

	disallowTextPolicy := hpbFactory(t, sharedPolicyBuilder.DisallowTextIn("div"))
	hpbCheck(t, "<div style=\"display:node\"></div>",
		disallowTextPolicy.Sanitize(
			"<div style=\"display:node\">Some Text</div>"))
}

func TestHTMLPolicyBuilderDisallowAttribute(t *testing.T) {
	sharedPolicyBuilder := NewHTMLPolicyBuilder().
		AllowElements("div", "p").
		AllowAttributes("style").OnElements("div", "p")

	allowPolicy := hpbFactory(t, sharedPolicyBuilder)
	hpbCheck(t,
		"<p style=\"display:node\">Some</p><div style=\"display:node\">Text</div>",
		allowPolicy.Sanitize(
			"<p style=\"display:node\">Some</p><div style=\"display:node\">Text</div>"))

	disallowTextPolicy := hpbFactory(t,
		sharedPolicyBuilder.DisallowAttributes("style").OnElements("p"))
	hpbCheck(t, "<p>Some</p><div style=\"display:node\">Text</div>",
		disallowTextPolicy.Sanitize(
			"<p style=\"display:node\">Some</p><div style=\"display:node\">Text</div>"))
}

func TestHTMLPolicyBuilderCreativeCSSStyling(t *testing.T) {
	policy := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("p").
		AllowAttributes("style").OnElements("p").AllowStyling())

	tests := []struct{ input, want string }{
		{"<p style=\"{display:none\">Some</p>", "<p>Some</p>"},
		{"<p style=\"{display:none;};color:red\">Some</p>", "<p style=\"color:red\">Some</p>"},
		{"<p style=\"{display:none;}color:red\">Some</p>", "<p style=\"color:red\">Some</p>"},
		{"<p style=\"display:none }; color:red\">Some</p>", "<p style=\"color:red\">Some</p>"},
		{"<p style=\"{display:none;}}color:red\">Some</p>", "<p style=\"color:red\">Some</p>"},
	}
	for _, test := range tests {
		hpbCheck(t, test.want, policy.Sanitize(test.input), test.input)
	}
}

func TestHTMLPolicyBuilderScriptTagWithCommentBlockContainingHTMLCommentEnd(t *testing.T) {
	scriptSanitizer := hpbFactory(t, NewHTMLPolicyBuilder().
		// allow scripts of type application/json
		AllowElementsWithPolicy(
			ElementPolicyFunc(func(elementName string, attrs *[]string) (string, bool) {
				typeIndex := slices.Index(*attrs, "type")
				if typeIndex < 0 || len(*attrs) < typeIndex+1 ||
					(*attrs)[typeIndex+1] != "application/json" {
					return "", false
				}
				return elementName, true
			}),
			"script").
		// allow contents in this script tag
		AllowTextIn("script").
		// keep type attribute in application/json script tag
		AllowAttributes("type").
		MatchingValueSet(true, map[string]struct{}{"application/json": {}}).
		OnElements("script"))

	mismatchedHTMLComments := "<script type=\"application/json\">\n" +
		"<!--\n" +
		"{\"field\":\"-->\"}\n" +
		"// -->\n" +
		"</script>"
	hpbCheck(t,
		"<script type=\"application/json\"></script>",
		scriptSanitizer.Sanitize(mismatchedHTMLComments))

	htmlMetaCharsEscaped := "<script type=\"application/json\">\n" +
		"<!--\n" +
		"{\"field\":\"--\\u003c\"}\n" +
		"// -->\n" +
		"</script>"
	hpbCheck(t,
		htmlMetaCharsEscaped,
		scriptSanitizer.Sanitize(htmlMetaCharsEscaped))
}

func TestHTMLPolicyBuilderNoscriptInAttribute(t *testing.T) {
	pf := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("img", "p", "noscript").
		AllowAttributes("title").Globally().
		AllowAttributes("img").OnElements("img"))

	hpbCheck(t,
		"<noscript>"+
			"<p title=\"&lt;/noscript&gt;&lt;img src&#61;x onerror&#61;alert(1)&gt;\">"+
			"</p>"+
			"</noscript>",
		pf.Sanitize(
			"<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">"))
}

func TestHTMLPolicyBuilderTableStructure(t *testing.T) {
	input := "<TABLE>" +
		"<TR><TD>Foo<TD>Bar" +
		"<TR><TH>Baz<TH>Boo<TH>Far<TH>Faz" +
		"<TR><TD>Oink<TD>Doink<TD>Poink<TD>Toink"
	sanitized := Tables.Sanitize(input)
	hpbCheck(t,
		"<table><tbody>"+
			"<tr><td>Foo</td><td>Bar</td></tr>"+
			"<tr><th>Baz</th><th>Boo</th><th>Far</th><th>Faz</th></tr>"+
			"<tr><td>Oink</td><td>Doink</td><td>Poink</td><td>Toink</td></tr>"+
			"</tbody></table>",
		sanitized)
}

func TestHTMLPolicyBuilderSvgNames(t *testing.T) {
	policyFactory := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("svg", "animateColor").
		AllowAttributes("viewBox").OnElements("svg"))
	svg := "<svg viewBox=\"0 0 0 0\"><animateColor></animateColor></svg>"
	hpbCheck(t, svg, policyFactory.Sanitize(svg))
}

func TestHTMLPolicyBuilderRawTextElementsInsideForeignContent(t *testing.T) {
	policyFactory := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("svg", "math", "style").
		AllowTextIn("style"))
	// Outside svg/math, style content is raw text and is emitted verbatim.
	hpbCheck(t,
		"<style>a &amp; b</style>",
		policyFactory.Sanitize("<style>a &amp; b</style>"))
	// Inside svg/math, browsers decode character references in style
	// content, so it is escaped once, not twice.
	hpbCheck(t,
		"<svg><style>a &amp; b &lt;c&gt;</style></svg>",
		policyFactory.Sanitize("<svg><style>a &amp; b &lt;c&gt;</style></svg>"))
	hpbCheck(t,
		"<math><style>a &amp; b</style></math>",
		policyFactory.Sanitize("<math><style>a &amp; b</style></math>"))
	hpbCheck(t,
		"<svg><style>a &amp; b</style></svg><style>c &amp; d</style>",
		policyFactory.Sanitize(
			"<svg><style>a &amp; b</style></svg><style>c &amp; d</style>"))
}

func TestHTMLPolicyBuilderTextareaIsNotTextArea(t *testing.T) {
	input := "<textarea>x</textarea><textArea>y</textArea>"
	textareaPolicy := hpbFactory(t, NewHTMLPolicyBuilder().AllowElements("textarea"))
	textAreaPolicy := hpbFactory(t, NewHTMLPolicyBuilder().AllowElements("textArea"))
	hpbCheck(t, "<textarea>x</textarea>y", textareaPolicy.Sanitize(input))
	hpbCheck(t, "x<textArea>y</textArea>", textAreaPolicy.Sanitize(input))
}

func TestHTMLPolicyBuilderDefinitionWithNoAttributesDefinedGlobally(t *testing.T) {
	// Does not fail or panic.
	if _, err := NewHTMLPolicyBuilder().AllowElements().AllowAttributes().Globally().ToFactory(); err != nil {
		t.Errorf("ToFactory: %v", err)
	}
}

// hpbStylingFactory allows span with a sanitized style attribute.
func hpbStylingFactory(t *testing.T) *PolicyFactory {
	t.Helper()
	return hpbFactory(t, NewHTMLPolicyBuilder().AllowElements("span").
		AllowAttributes("style").OnElements("span").AllowStyling())
}

func TestHTMLPolicyBuilderCSSTextAlign(t *testing.T) {
	factory := hpbStylingFactory(t)

	// Every value text-align accepts: the keywords from the CSS Text spec
	// followed by the CSS-wide keywords, which are valid on any property.
	for _, value := range []string{
		"center", "end", "inherit", "justify", "justify-all",
		"match-parent", "start", "left", "right", "initial", "revert",
		"revert-layer", "unset",
	} {
		toSanitize := "<span style=\"text-align:" + value + "\">x</span>"
		hpbCheck(t, toSanitize, factory.Sanitize(toSanitize), value)
	}

	toSanitizeTextAlignFoo := "<span style=\"text-align:foo\">foo</span>"
	hpbCheck(t, "foo", factory.Sanitize(toSanitizeTextAlignFoo))
}

func TestHTMLPolicyBuilderCSSWideKeywords(t *testing.T) {
	factory := hpbStylingFactory(t)

	// Not just text-align: the CSS-wide keywords reset any property.
	for _, property := range []string{"color", "font-size", "text-decoration"} {
		for _, keyword := range []string{
			"inherit", "initial", "revert", "revert-layer", "unset",
		} {
			toSanitize := "<span style=\"" + property + ":" + keyword + "\">x</span>"
			hpbCheck(t, toSanitize, factory.Sanitize(toSanitize), property+":"+keyword)
		}
	}

	// They are whole values, not arguments to a function, so inside
	// rgb(...) "initial" is dropped like any other word the function does
	// not take.
	hpbCheck(t,
		factory.Sanitize("<span style=\"color:rgb(foo,0,0)\">x</span>"),
		factory.Sanitize("<span style=\"color:rgb(initial,0,0)\">x</span>"))
}

func TestHTMLPolicyBuilderCSSFontSize(t *testing.T) {
	factory := hpbStylingFactory(t)
	toSanitizeXXXLarge := "the <span style=\"font-size:xxx-large\">large</span> formatting issue with chrome"
	hpbCheck(t, toSanitizeXXXLarge, factory.Sanitize(toSanitizeXXXLarge))

	toSanitizeMedium := "the <span style=\"font-size:medium\">medium</span> formatting issue with chrome"
	hpbCheck(t, toSanitizeMedium, factory.Sanitize(toSanitizeMedium))
}

func TestHTMLPolicyBuilderCSSChildCombinator(t *testing.T) {
	factory := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("span", "style", "h1").AllowTextIn("style", "h1").
		AllowAttributes("type").OnElements("style").AllowStyling())

	toSanitize := "<style type=\"text/css\">\n" +
		"<!--\n" +
		".hdg-1 {\n" +
		"width:100%;\n" +
		"}\n" +
		"\n" +
		".hdg-1>._inner {\n" +
		"background-color: #999;\n" +
		"}\n" +
		"-->\n" +
		"</style>\n" +
		"<h1>Test</h1>\n" +
		"\n" +
		"<style>\n" +
		"<!--\n" +
		".hdg-1 {\n" +
		"width:100%;\n" +
		"}\n" +
		"\n" +
		".hdg-1>._inner {\n" +
		"background-color: #666;\n" +
		"}\n" +
		"-->\n" +
		"</style>"
	hpbCheck(t, toSanitize, factory.Sanitize(toSanitize))
}

// The text gate was set from the last tag alone, so a dropped tag inside an
// element whose content is never shown reset it and let the content through.
// Text now belongs to the nearest enclosing element the policy kept, and a
// dropped element in between suppresses it only if its content is never
// shown.  Regression test for #444.
func TestHTMLPolicyBuilderDroppedTagInsideSuppressedContentDoesNotResetTheTextGate(t *testing.T) {
	b := NewHTMLPolicyBuilder().AllowElements("h1", "div")
	hpbCheck(t, "", hpbApply(t, b, "<noscript>text</noscript>"))
	hpbCheck(t, "", hpbApply(t, b, "<noscript><b>text</b></noscript>"))
	hpbCheck(t, "", hpbApply(t, b, "<noscript><b>a</b>b</noscript>"))
	// A dropped void element never goes on the stack, so it must not reset
	// the gate either.
	hpbCheck(t, "", hpbApply(t, b, "<noscript><img>text</noscript>"))
	hpbCheck(t,
		"<div>z</div>",
		hpbApply(t, b, "<div><object><b>x</b>y</object>z</div>"))
	// A kept element inside is a text container in its own right.
	hpbCheck(t,
		"<div>shown</div>",
		hpbApply(t, b, "<noscript><div>shown</div></noscript>"))
}

// The same slip seen through DisallowTextIn: a dropped <p> between the text
// and the kept template reset the gate.  Part of #444.
func TestHTMLPolicyBuilderDisallowTextInReachesPastADroppedChild(t *testing.T) {
	b := NewHTMLPolicyBuilder().
		AllowElements("template", "h1").
		DisallowTextIn("template")
	hpbCheck(t,
		"<template></template>",
		hpbApply(t, b, "<template><p>excluded-text</p></template>"))
	hpbCheck(t,
		"<template><h1>shown</h1></template>",
		hpbApply(t, b, "<template><h1>shown</h1></template>"))
}

// DisallowTextIn(x) applies when the policy drops x too.  The builder used to
// discard the disallowed names when it compiled, so a policy that disallowed
// both the template element and text in it still emitted the template's text
// as bare text.  The policy and input are the ones reported in #194.
func TestHTMLPolicyBuilderDisallowTextInAppliesToADroppedElement(t *testing.T) {
	b := NewHTMLPolicyBuilder().
		DisallowElements("template").
		DisallowTextIn("template").
		AllowElements("h1")
	hpbCheck(t,
		"<h1>allowed text</h1>",
		hpbApply(t,
			b,
			"<html><h1>allowed text</h1><template><p>excluded-text</p>"+
				"</template><script>script-text</script><html>"))
	// Text after the dropped element resumes.
	hpbCheck(t, "after", hpbApply(t, b, "<template>hidden</template>after"))
	// Text inside an allowed element nested in the dropped one belongs to
	// that element, and is not affected.
	hpbCheck(t,
		"<h1>shown</h1>",
		hpbApply(t, b, "<template><h1>shown</h1></template>"))

	// An allowed element that is dropped for having no attributes is dropped
	// all the same, so the text in it goes too.
	noBareSpans := NewHTMLPolicyBuilder().
		AllowElements("span").
		AllowAttributes("title").OnElements("span").
		DisallowTextIn("span")
	hpbCheck(t,
		"<span title=\"t\"></span>",
		hpbApply(t, noBareSpans, "<span title=t>x</span>"))
	hpbCheck(t, "", hpbApply(t, noBareSpans, "<span>x</span>"))
}

// And carries a DisallowTextIn over from either factory, unless the other
// allows text in that element: grants union under And, as they do for
// elements and attributes.
func TestHTMLPolicyBuilderAndCombinesDisallowedTextContainers(t *testing.T) {
	headings := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("h1"))
	noTemplateText := hpbFactory(t, NewHTMLPolicyBuilder().
		DisallowTextIn("template"))
	html := "<h1>a</h1><template>hidden</template>"
	hpbCheck(t, "<h1>a</h1>hidden", headings.Sanitize(html))
	hpbCheck(t, "<h1>a</h1>", headings.And(noTemplateText).Sanitize(html))
	hpbCheck(t, "<h1>a</h1>", noTemplateText.And(headings).Sanitize(html))

	templates := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("template"))
	hpbCheck(t,
		"<h1>a</h1><template>hidden</template>",
		headings.And(noTemplateText).And(templates).Sanitize(html))

	// Disallowing the element in one factory grants nothing, so it does not
	// cancel the other factory's DisallowTextIn.
	noDivs := hpbFactory(t, NewHTMLPolicyBuilder().
		DisallowElements("div"))
	noDivText := hpbFactory(t, NewHTMLPolicyBuilder().
		DisallowTextIn("div"))
	hpbCheck(t, "", noDivText.And(noDivs).Sanitize("<div>hidden</div>"))
	hpbCheck(t, "", noDivs.And(noDivText).Sanitize("<div>hidden</div>"))
}

// A kept element is judged by the name it was kept under, so a policy that
// renames span to div would otherwise honour DisallowTextIn("span") only when
// the span happened to be dropped.  The rule follows the name the author
// wrote.
func TestHTMLPolicyBuilderDisallowTextInFollowsARenamedElement(t *testing.T) {
	b := NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(hpbRename("div"), "span").
		AllowElements("div").
		AllowAttributes("title").OnElements("span").
		DisallowTextIn("span")
	hpbCheck(t,
		"<div title=\"t\"></div>", hpbApply(t, b, "<span title=t>hi</span>"))
	hpbCheck(t, "", hpbApply(t, b, "<span>hi</span>"))
	hpbCheck(t, "<div>hi</div>", hpbApply(t, b, "<div>hi</div>"))
}

// Once a kept child closes, the text that follows it is still inside the
// dropped element, and stays suppressed.  The old gate reset to the nearest
// kept ancestor at every close tag, so that text leaked.
func TestHTMLPolicyBuilderSuppressionResumesAfterAKeptChildCloses(t *testing.T) {
	b := NewHTMLPolicyBuilder().AllowElements("p")
	hpbCheck(t, "<p>b</p>", hpbApply(t, b, "<noscript>a<p>b</p>c</noscript>"))
	// Text after the dropped element itself is unaffected.
	hpbCheck(t, "<p>b</p>d", hpbApply(t, b, "<noscript>a<p>b</p>c</noscript>d"))
	hpbCheck(t,
		"<p>b</p>",
		hpbApply(t,
			b.DisallowTextIn("template"), "<template>a<p>b</p>c</template>"))
}

// The other side of the gate following the nearest kept element: text inside
// a dropped child of a kept element that cannot hold text itself is not
// written straight into that element.  A browser would not keep text directly
// inside a <tr> either: it foster-parents the text out of the table.  The
// balancer closes the table's output ahead of such text, so it is written
// beside the table rather than dropped, and the output is a fixed point.
// Policies that allow the cells are unaffected.
func TestHTMLPolicyBuilderTextInADroppedCellOfAKeptRowIsKeptBesideTheTable(t *testing.T) {
	table := "<table><tr><td>cell</td></tr></table>"
	out := hpbApply(t,
		NewHTMLPolicyBuilder().AllowElements("table", "tbody", "tr"), table)
	hpbCheck(t, "<table><tbody><tr></tr></tbody></table>cell", out)
	hpbCheck(t,
		out,
		hpbApply(t, NewHTMLPolicyBuilder().AllowElements("table", "tbody", "tr"),
			out))
	hpbCheck(t,
		"<table><tbody><tr><td>cell</td></tr></tbody></table>",
		hpbApply(t,
			NewHTMLPolicyBuilder().AllowElements("table", "tbody", "tr", "td"),
			table))
}

// Whether an element may hold text is said of the name the author wrote,
// which is the name AllowElementsWithPolicy takes, so a rename to a name the
// policy does not allow in its own right keeps the text (#445).  The gate
// used to follow the emitted name, so the span survived as an empty div.
func TestHTMLPolicyBuilderTextSurvivesARenameToAnUnallowedName(t *testing.T) {
	hpbCheck(t,
		"<div>hi</div>",
		hpbApply(t,
			NewHTMLPolicyBuilder().
				AllowElementsWithPolicy(hpbRename("div"), "span").
				AllowWithoutAttributes("span"),
			"<span>hi</span>"))
	hpbCheck(t,
		"<div>hi</div> <div>x<i>y</i>z</div>",
		hpbApply(t,
			NewHTMLPolicyBuilder().
				AllowElementsWithPolicy(hpbRename("div"), "b").
				AllowElements("i"),
			"<b>hi</b> <b>x<i>y</i>z</b>"))
}

// AllowTextIn takes the name the author wrote too, so it reaches a renamed
// element, and without it the text of a raw-text element written under that
// name stays out, whatever the policy renames it to.
func TestHTMLPolicyBuilderAllowTextInFollowsTheInputNameOfARenamedElement(t *testing.T) {
	styleToDiv := NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(hpbRename("div"), "style")
	hpbCheck(t,
		"<div></div>", hpbApply(t, styleToDiv, "<style>a<b</style>"))
	hpbCheck(t,
		"<div>a&lt;b</div>",
		hpbApply(t, styleToDiv.AllowTextIn("style"), "<style>a<b</style>"))
}

// A rename into an element whose content a browser reads literally is held to
// the bar the builder sets for that name: text in a style needs
// AllowTextIn("style") whether the author wrote <style> or a <div> the policy
// turned into one.  Otherwise a rename would be a way to write raw stylesheet
// or script text without saying so.
func TestHTMLPolicyBuilderRenameIntoALiteralContentElementStillNeedsAllowTextInOnTheTarget(t *testing.T) {
	divToStyle := NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(hpbRename("style"), "div")
	hpbCheck(t,
		"<style></style>", hpbApply(t, divToStyle, "<div>a{b:c}</div>"))
	hpbCheck(t,
		"<style>a{b:c}</style>",
		hpbApply(t, divToStyle.AllowTextIn("style"), "<div>a{b:c}</div>"))
}

// A nested kept element does not override a literal element's text gate.
func TestHTMLPolicyBuilderNestedElementInsideRenamedLiteralContentUsesOuterTextGate(t *testing.T) {
	divToStyle := NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(hpbRename("style"), "div").
		AllowElements("b", "style")
	html := "<div>a<b>bold</b>c</div><b>after</b>"

	hpbCheck(t, "<style></style><b>after</b>", hpbApply(t, divToStyle, html))
	hpbCheck(t,
		"<style>aboldc</style><b>after</b>",
		hpbApply(t, divToStyle.AllowTextIn("style"), html))
}

// A void element renamed to one that is not void is closed at once (#450).
// The lexer never produces a close tag for br, and the balancer, which also
// goes by the input name, never synthesizes one, so the renamed element used
// to stay open until its parent closed and swallowed every sibling after it.
// Same result whether or not the target may hold text: the text after the
// void element belongs to the paragraph.
func TestHTMLPolicyBuilderVoidElementRenamedToANonVoidOneIsClosedAtOnce(t *testing.T) {
	html := "<p>a<br>b<i>c</i>d</p><p>e</p>"
	hpbCheck(t,
		"<p>a<span></span>bcd</p><p>e</p>",
		hpbApply(t,
			NewHTMLPolicyBuilder().
				AllowElementsWithPolicy(hpbRename("span"), "br").
				AllowElements("p", "span"),
			html))
	hpbCheck(t,
		"<p>a<span></span>bcd</p><p>e</p>",
		hpbApply(t,
			NewHTMLPolicyBuilder().
				AllowElementsWithPolicy(hpbRename("span"), "br").
				AllowElements("p"),
			html))
}

// The balancer caps how deep the output nests, but it never counts a void
// input element, so the phantom entries of #450 nested past the cap: three
// hundred <br> renamed to span came out as three hundred spans inside one
// another.
func TestHTMLPolicyBuilderVoidElementRenamedToANonVoidOneDoesNotNest(t *testing.T) {
	var html, expected strings.Builder
	for i := 0; i < 300; i++ {
		html.WriteString("<br>")
		expected.WriteString("<span></span>")
	}
	hpbCheck(t,
		expected.String(),
		hpbApply(t,
			NewHTMLPolicyBuilder().
				AllowElementsWithPolicy(hpbRename("span"), "br").
				AllowElements("span"),
			html.String()))
}

// The reverse rename, to a void element, has nothing to close in the output,
// and the text after the void element belongs to the enclosing container, as
// it does after a dropped element.  Text was disallowed in the element by the
// name the author wrote, so that still holds.
func TestHTMLPolicyBuilderNonVoidElementRenamedToAVoidOne(t *testing.T) {
	spanToBr := NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(hpbRename("br"), "span").
		AllowWithoutAttributes("span").
		AllowElements("p")
	hpbCheck(t,
		"<p>x<br />yz</p>", hpbApply(t, spanToBr, "<p>x<span>y</span>z</p>"))
	hpbCheck(t,
		"<p>x<br />z</p>",
		hpbApply(t, spanToBr.DisallowTextIn("span"), "<p>x<span>y</span>z</p>"))
}

// The close tag of an element renamed to a void one pops that element and
// nothing else.  Before #450 the policy pushed nothing for it, so the close
// tag found the nearest open element of the same input name instead and ended
// the outer span early, leaving c outside it.
func TestHTMLPolicyBuilderCloseTagOfAnElementRenamedToAVoidOnePopsOnlyThatElement(t *testing.T) {
	classedSpanToBr := NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(
			ElementPolicyFunc(func(_ string, attrs *[]string) (string, bool) {
				if len(*attrs) == 0 {
					return "span", true
				}
				return "br", true
			}),
			"span").
		AllowWithoutAttributes("span").
		AllowAttributes("class").OnElements("span")
	hpbCheck(t,
		"<span>a<br class=\"x\" />bc</span>",
		hpbApply(t, classedSpanToBr, "<span>a<span class=x>b</span>c</span>"))
}

// A factory is typically kept in a package-level variable for the life of
// the program, so nothing it holds may point back at the throwaway builder.
// The value policies behind the Matching… methods must not capture the
// attribute builder, and through it the whole builder and its intermediate
// maps.
func TestHTMLPolicyBuilderFactoryDoesNotRetainBuilder(t *testing.T) {
	other := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowAttributes("id").MatchingPattern(regexp.MustCompile("[a-z]+")).
		OnElements("p"))
	factory := hpbFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a", "p", "span", "img").
		AllowAttributes("href").OnElements("a").
		AllowAttributes("lang").MatchingPattern(regexp.MustCompile("[a-z]{2}")).
		Globally().
		AllowAttributes("title").MatchingPredicate(func(v string) bool { return v != "" }).Globally().
		AllowAttributes("align").MatchingValues(true, "left", "right").
		OnElements("p").
		AllowAttributes("dir").MatchingValueSet(false, map[string]struct{}{"ltr": {}, "rtl": {}}).
		Globally().
		AllowAttributes("style").Globally().
		AllowURLProtocols("https").
		AllowTextIn("span").
		RequireRelNofollowOnLinks().
		WithPreprocessor(hpbProcessorFunc(func(r HTMLStreamEventReceiver) HTMLStreamEventReceiver {
			return r
		}))).
		And(other)

	if found := hpbBuildersReachableFrom(factory); len(found) != 0 {
		t.Errorf("builders reachable from factory: %q", found)
	}
	if found := hpbBuildersReachableFrom(
		Formatting.And(Blocks).And(Styles).
			And(Links).And(Tables).
			And(Images)); len(found) != 0 {
		t.Errorf("builders reachable from canned sanitizers: %q", found)
	}
}

// hpbSeenKey identifies a pointer, map or slice already walked.
type hpbSeenKey struct {
	t reflect.Type
	p uintptr
}

// hpbBuildersReachableFrom walks the object graph under root and returns a
// field path for every builder found, so a regression names the field that
// leaked it.  It descends through pointers, interfaces, arrays, slices, maps,
// and the fields of this package's structs; other packages' types such as
// regexps are leaves, and so are functions, whose captures reflection cannot
// see.
func hpbBuildersReachableFrom(root any) []string {
	var found []string
	v := reflect.ValueOf(root)
	hpbWalk(v, reflect.Indirect(v).Type().Name(), map[hpbSeenKey]bool{}, &found)
	return found
}

// hpbPkgPath is the import path of this package.
var hpbPkgPath = reflect.TypeOf(HTMLPolicyBuilder{}).PkgPath()

// hpbWalk is the recursive step of hpbBuildersReachableFrom.
func hpbWalk(v reflect.Value, path string, seen map[hpbSeenKey]bool, found *[]string) {
	if !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.Interface:
		if !v.IsNil() {
			hpbWalk(v.Elem(), path, seen, found)
		}
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		key := hpbSeenKey{v.Type(), v.Pointer()}
		if seen[key] {
			return
		}
		seen[key] = true
		switch v.Type() {
		case reflect.TypeOf((*HTMLPolicyBuilder)(nil)),
			reflect.TypeOf((*HTMLPolicyBuilderAttributeBuilder)(nil)):
			*found = append(*found, path)
			return
		}
		hpbWalk(v.Elem(), path, seen, found)
	case reflect.Struct:
		switch v.Type() {
		case reflect.TypeOf(HTMLPolicyBuilder{}),
			reflect.TypeOf(HTMLPolicyBuilderAttributeBuilder{}):
			*found = append(*found, path)
			return
		}
		if v.Type().PkgPath() != hpbPkgPath && v.Type().Name() != "" {
			return
		}
		for i := 0; i < v.NumField(); i++ {
			hpbWalk(v.Field(i), path+"."+v.Type().Field(i).Name, seen, found)
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			hpbWalk(v.Index(i), path+"["+strconv.Itoa(i)+"]", seen, found)
		}
	case reflect.Slice:
		if v.IsNil() {
			return
		}
		key := hpbSeenKey{v.Type(), v.Pointer()}
		if seen[key] && v.Len() != 0 {
			return
		}
		seen[key] = true
		for i := 0; i < v.Len(); i++ {
			hpbWalk(v.Index(i), path+"["+strconv.Itoa(i)+"]", seen, found)
		}
	case reflect.Map:
		if v.IsNil() {
			return
		}
		key := hpbSeenKey{v.Type(), v.Pointer()}
		if seen[key] {
			return
		}
		seen[key] = true
		iter := v.MapRange()
		for iter.Next() {
			hpbWalk(iter.Key(), path+".key", seen, found)
			hpbWalk(iter.Value(), path+"["+fmt.Sprint(iter.Key())+"]", seen, found)
		}
	}
}
