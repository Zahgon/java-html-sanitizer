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

// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/SanitizersTest.java.

package sanitizer

import (
	"fmt"
	"strings"
	"testing"
)

// sanToFactory builds b's factory, failing the test on a configuration error.
func sanToFactory(t *testing.T, b *HTMLPolicyBuilder) *PolicyFactory {
	t.Helper()
	f, err := b.ToFactory()
	if err != nil {
		t.Fatalf("ToFactory: %v", err)
	}
	return f
}

// sanCase is one input and the output a policy should produce for it.
type sanCase struct {
	input string
	want  string
}

// sanCheck sanitizes each case's input with f and compares the result.
func sanCheck(t *testing.T, name string, f *PolicyFactory, cases []sanCase) {
	t.Helper()
	for _, c := range cases {
		if got := f.Sanitize(c.input); got != c.want {
			t.Errorf("%s: Sanitize(%q)\n got: %q\nwant: %q", name, c.input, got, c.want)
		}
	}
}

func TestSanitizersFormatting(t *testing.T) {
	// Sanitizing "" returns "".
	sanCheck(t, "FORMATTING", Formatting, []sanCase{
		{"", ""},
		{"", ""},
		{"Hello, World!", "Hello, World!"},
		{"Hello, <b>World</b>!", "Hello, <b>World</b>!"},
		{"<p>Hello, <b onclick=alert(1337)>World</b>!</p>", "Hello, <b>World</b>!"},
	})
}

func TestSanitizersBlockElements(t *testing.T) {
	sanCheck(t, "BLOCKS", Blocks, []sanCase{
		{"", ""},
		{"Hello, World!", "Hello, World!"},
		{"Hello, <b>World</b>!", "Hello, World!"},
		{"<p onclick=alert(1337)>Hello, <b>World</b>!</p>", "<p>Hello, World!</p>"},
	})
}

func TestSanitizersBlockAndFormattingElements(t *testing.T) {
	s := Blocks.And(Formatting)
	r1 := Blocks.And(Formatting).And(Blocks)
	r2 := Blocks.And(Formatting).And(Formatting)
	for i, f := range []*PolicyFactory{s, r1, r2} {
		sanCheck(t, fmt.Sprintf("factory %d", i), f, []sanCase{
			{"", ""},
			{"Hello, World!", "Hello, World!"},
			{"Hello, <b>World</b>!", "Hello, <b>World</b>!"},
			{"<p onclick=alert(1337)>Hello, <b>World</b>!</p>", "<p>Hello, <b>World</b>!</p>"},
		})
	}
}

func TestSanitizersStylesAndFormatting(t *testing.T) {
	sanitizer := Formatting.
		And(Blocks).And(Styles).And(Links)
	input := "<span style=\"font-weight:bold;" +
		"text-decoration:underline;background-color:yellow\"" +
		">aaaaaaaaaaaaaaaaaaaaaaa</span>"
	sanCheck(t, "styles and formatting", sanitizer, []sanCase{{input, input}})
}

func TestSanitizersAndIntersects(t *testing.T) {
	restrictedLink := sanToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a").
		AllowURLProtocols("https").
		AllowAttributes("href", "title").OnElements("a"))
	inline := Formatting.And(Links)
	inputHTML := "<a href='http://foo.com/'>Hello, <b>World</b></a>" +
		"<a title='!' href='https://foo.com/#!'>!</a>"
	and1 := restrictedLink.And(inline)
	and2 := inline.And(restrictedLink)
	sanCheck(t, "https-only links", restrictedLink, []sanCase{{
		inputHTML,
		"Hello, World<a title=\"!\" href=\"https://foo.com/#!\">!</a>",
	}})
	sanCheck(t, "inline els", inline, []sanCase{{
		inputHTML,
		"<a href=\"http://foo.com/\" rel=\"nofollow\">Hello, <b>World</b></a>" +
			"<a href=\"https://foo.com/#!\" rel=\"nofollow\">!</a>",
	}})
	sanCheck(t, "https-only links and inline els", and1, []sanCase{{
		inputHTML,
		"Hello, <b>World</b>" +
			"<a title=\"!\" href=\"https://foo.com/#!\" rel=\"nofollow\">!</a>",
	}})
	sanCheck(t, "inline els and https-only links", and2, []sanCase{{
		inputHTML,
		"Hello, <b>World</b>" +
			"<a title=\"!\" href=\"https://foo.com/#!\" rel=\"nofollow\">!</a>",
	}})
}

func TestSanitizersImages(t *testing.T) {
	sanCheck(t, "IMAGES", Images, []sanCase{
		{"<a href=\"javascript:alert(1337)\">foo</a>", "foo"},
		{"<img src=\"foo.gif\">", "<img src=\"foo.gif\" />"},
		{"<img src=\"javascript://alert(1337)\">", ""},
		{
			"<img src=\"x.gif\" alt=\"y\" width=96 height=64 border=0>",
			"<img src=\"x.gif\" alt=\"y\"" +
				" width=\"96\" height=\"64\" border=\"0\" />",
		},
		{
			"<img src=\"x.png\" alt=\"y\" width=\"widgy\" height=64 border=0>",
			"<img src=\"x.png\" alt=\"y\" height=\"64\" border=\"0\" />",
		},
		{"<img src=\"test.jpg\" loading=\"lazy\">", "<img src=\"test.jpg\" loading=\"lazy\" />"},
		{"<img src=\"test.jpg\" loading=\"eager\">", "<img src=\"test.jpg\" loading=\"eager\" />"},
		{"<img src=\"test.jpg\" loading=\"auto\">", "<img src=\"test.jpg\" />"},
		{"<img src=\"test.jpg\" loading=\"javascript:alert(1337)\">", "<img src=\"test.jpg\" />"},
	})
}

func TestSanitizersIntegerAttributePolicy(t *testing.T) {
	sanCheck(t, "IMAGES", Images, []sanCase{
		{
			"<img src=\"x.png\" alt=\"y\" width=\"widgy\" height=0 border=0>",
			"<img src=\"x.png\" alt=\"y\" height=\"0\" border=\"0\" />",
		},
		{
			"<img src=\"x.png\" alt=\"y\" width=\"widgy\" height=069 border=0>",
			"<img src=\"x.png\" alt=\"y\" height=\"069\" border=\"0\" />",
		},
		{
			"<img src=\"x.png\" alt=\"y\" width=\"widgy\" height=64.43 border=0>",
			"<img src=\"x.png\" alt=\"y\" height=\"64\" border=\"0\" />",
		},
		{
			"<img src=\"x.png\" alt=\"y\" width=\"widgy\" height=-64 border=0>",
			"<img src=\"x.png\" alt=\"y\" border=\"0\" />",
		},
		{
			"<img src=\"x.png\" alt=\"y\" width=\"widgy\" height=\"\" border=0>",
			"<img src=\"x.png\" alt=\"y\" border=\"0\" />",
		},
		{
			"<img src=\"x.png\" alt=\"y\" width=\"widgy\" height=.43 border=0>",
			"<img src=\"x.png\" alt=\"y\" border=\"0\" />",
		},
		{
			"<img src=\"x.png\" alt=\"y\" width=\"widgy\" height=something border=0>",
			"<img src=\"x.png\" alt=\"y\" border=\"0\" />",
		},
		{
			"<img src=\"x.png\" alt=\"y\" width=\"widgy\" height=596thin border=0>",
			"<img src=\"x.png\" alt=\"y\" border=\"0\" />",
		},
	})
}

func TestSanitizersTableColspanRowspan(t *testing.T) {
	sanCheck(t, "TABLES", Tables, []sanCase{
		{
			"<table><tr><td colspan=\"3\">cell</td></tr></table>",
			"<table><tbody><tr><td colspan=\"3\">cell</td></tr></tbody></table>",
		},
		{
			"<table><tr><td rowspan=\"4\">cell</td></tr></table>",
			"<table><tbody><tr><td rowspan=\"4\">cell</td></tr></tbody></table>",
		},
		{
			"<table><tr><td colspan=\"three\">cell</td></tr></table>",
			"<table><tbody><tr><td>cell</td></tr></tbody></table>",
		},
		{
			"<table><tr><td colspan=\"3.5\">cell</td></tr></table>",
			"<table><tbody><tr><td colspan=\"3\">cell</td></tr></tbody></table>",
		},
	})
}

func TestSanitizersTableHeadersAndScope(t *testing.T) {
	sanCheck(t, "TABLES", Tables, []sanCase{
		// scope is limited to the four spec values and canonicalized to lower
		// case.
		{
			"<table><tr><th scope=\"col\">h</th></tr></table>",
			"<table><tbody><tr><th scope=\"col\">h</th></tr></tbody></table>",
		},
		{
			"<table><tr><th scope=\"RowGroup\">h</th></tr></table>",
			"<table><tbody><tr><th scope=\"rowgroup\">h</th></tr></tbody></table>",
		},
		{
			"<table><tr><th scope=\"random\">h</th></tr></table>",
			"<table><tbody><tr><th>h</th></tr></tbody></table>",
		},
		{
			"<table><tr><th scope=\"col row\">h</th></tr></table>",
			"<table><tbody><tr><th>h</th></tr></tbody></table>",
		},
		// scope is only meaningful on th.
		{
			"<table><tr><td scope=\"col\">c</td></tr></table>",
			"<table><tbody><tr><td>c</td></tr></tbody></table>",
		},
		// headers is a space-separated list of ids, on both td and th.
		{
			"<table><tr><th headers=\"h1\">h</th>" +
				"<td headers=\"h1 h2\">c</td></tr></table>",
			"<table><tbody><tr><th headers=\"h1\">h</th>" +
				"<td headers=\"h1 h2\">c</td></tr></tbody></table>",
		},
		{
			"<table><tr><td headers=\"  h-1 \t h.2:x  \">c</td></tr></table>",
			"<table><tbody><tr><td headers=\"h-1 h.2:x\">c</td></tr></tbody></table>",
		},
		{
			"<table><tr><td headers=\"\">c</td></tr></table>",
			"<table><tbody><tr><td>c</td></tr></tbody></table>",
		},
		{
			"<table><tr><td headers=\"   \">c</td></tr></table>",
			"<table><tbody><tr><td>c</td></tr></tbody></table>",
		},
		{
			"<table><tr><td headers=\"h1,h2\">c</td></tr></table>",
			"<table><tbody><tr><td>c</td></tr></tbody></table>",
		},
		{
			"<table><tr><td headers=\"javascript:alert(1)\">c</td></tr></table>",
			"<table><tbody><tr><td>c</td></tr></tbody></table>",
		},
		{
			"<table><tr><td headers=\"h1&quot; onmouseover=&quot;alert(1)\">" +
				"c</td></tr></table>",
			"<table><tbody><tr><td>c</td></tr></tbody></table>",
		},
		{
			"<table><tr><td headers=\"hé\">c</td></tr></table>",
			"<table><tbody><tr><td>c</td></tr></tbody></table>",
		},
	})
}

func TestSanitizersLinks(t *testing.T) {
	sanCheck(t, "LINKS", Links, []sanCase{
		{
			"<a href=\"foo.html\">Link text</a>",
			"<a href=\"foo.html\" rel=\"nofollow\">Link text</a>",
		},
		{
			"<a href=\"foo.html\" onclick=\"alert(1337)\">Link text</a>",
			"<a href=\"foo.html\" rel=\"nofollow\">Link text</a>",
		},
		{
			"<a href=\"http://example.com/x.html\"" +
				" onclick=\"alert(1337)\">Link text</a>",
			"<a href=\"http://example.com/x.html\" rel=\"nofollow\">Link text</a>",
		},
		{
			"<a href=\"https://example.com/x.html\"" +
				" onclick=\"alert(1337)\">Link text</a>",
			"<a href=\"https://example.com/x.html\" rel=\"nofollow\">Link text</a>",
		},
		{
			"<a href=\"HTTPS://example.com/x.html\"" +
				" onclick=\"alert(1337)\">Link text</a>",
			"<a href=\"HTTPS://example.com/x.html\" rel=\"nofollow\">Link text</a>",
		},
		{
			"<a href=\"//example.com/x.html\"" +
				" onclick=\"alert(1337)\">Link text</a>",
			"<a href=\"//example.com/x.html\" rel=\"nofollow\">Link text</a>",
		},
		{
			"<a href=\"javascript:alert(1337).html\"" +
				" onclick=\"alert(1337)\">Link text</a>",
			"Link text",
		},
		// Not a link.  Instead, an attempt to intercept URL references that
		// has not been explicitly allowed.
		{"<a name=\"header\" id=\"header\">Header text</a>", "Header text"},
	})
}

func TestSanitizersLinksRelAttributeAdditionsOrder(t *testing.T) {
	// Issue 336.
	pf := Links.And(sanToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a").
		RequireRelsOnLinks("noopener", "noreferrer")))
	sanCheck(t, "noopener noreferrer", pf, []sanCase{{
		"<a href=\"foo.html\">Link text</a>",
		"<a href=\"foo.html\" rel=\"nofollow noopener noreferrer\">Link text</a>",
	}})

	pf = Links.And(sanToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a").
		RequireRelsOnLinks("noreferrer", "noopener")))
	sanCheck(t, "noreferrer noopener", pf, []sanCase{{
		"<a href=\"foo.html\">Link text</a>",
		"<a href=\"foo.html\" rel=\"nofollow noreferrer noopener\">Link text</a>",
	}})
}

func TestSanitizersExplicitlyAllowedProtocolsAreCaseInsensitive(t *testing.T) {
	// Issue 24.
	s := sanToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a").
		AllowAttributes("href").OnElements("a").
		AllowStandardURLProtocols().
		AllowURLProtocols("file")) // Don't try this at home
	input := "<a href='file:///etc/passwd'>Copy and paste this into email</a>" +
		"<a href='FILE:///etc/passwd'>Or this one</a>" +
		"<a href='F\u0130LE:///etc/passwd'>not with Turkish dotted I's</a>" +
		"<a href='fail:///etc/passed'>The fail protocol needs to happen</a>"
	want := "<a href=\"file:///etc/passwd\">Copy and paste this into email</a>" +
		"<a href=\"FILE:///etc/passwd\">Or this one</a>" +
		"not with Turkish dotted I&#39;s" +
		"The fail protocol needs to happen"
	sanCheck(t, "file protocol", s, []sanCase{{input, want}})
}

func TestSanitizersIssue9StylesInTables(t *testing.T) {
	input := "" +
		"<table style=\"color: rgb(0, 0, 0);" +
		" font-family: Arial, Geneva, sans-serif;\">" +
		"<tbody>" +
		"<tr>" +
		"<th>Column One</th><th>Column Two</th>" +
		"</tr>" +
		"<tr>" +
		"<td align=\"center\"" +
		" style=\"background-color: rgb(255, 255, 254);\">" +
		"<font size=\"2\">Size 2</font></td>" +
		"<td align=\"center\"" +
		" style=\"background-color: rgb(255, 255, 254);\">" +
		"<font size=\"7\">Size 7</font></td>" +
		"</tr>" +
		"</tbody>" +
		"</table>"
	s := sanToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tbody", "thead", "tr", "td", "th").
		AllowCommonBlockElements().
		AllowCommonInlineFormattingElements().
		AllowStyling().
		AllowAttributes("align").MatchingValues(true, "left", "center", "right").
		OnElements("table", "tr", "td", "th").
		AllowAttributes("size").OnElements("font", "img"))
	sanitized := "" +
		"<table style=\"color:rgb( 0 , 0 , 0 );" +
		"font-family:&#39;Arial&#39; , &#39;Geneva&#39; , sans-serif\">" +
		"<tbody>" +
		"<tr>" +
		"<th>Column One</th><th>Column Two</th>" +
		"</tr>" +
		"<tr>" +
		"<td align=\"center\"" +
		" style=\"background-color:rgb( 255 , 255 , 254 )\">" +
		"<font size=\"2\">Size 2</font></td>" +
		"<td align=\"center\"" +
		" style=\"background-color:rgb( 255 , 255 , 254 )\">" +
		"<font size=\"7\">Size 7</font></td>" +
		"</tr>" +
		"</tbody>" +
		"</table>"
	sanCheck(t, "styles in tables", s, []sanCase{{input, sanitized}})
}

func TestSanitizersSkipIfEmptyUnionsProperly(t *testing.T) {
	// Issue 23
	extras := sanToFactory(t, NewHTMLPolicyBuilder().
		AllowWithoutAttributes("span", "div").
		AllowElements("span", "div", "textarea").
		// This is not the proper way to require the attribute disabled on
		// textareas.  This is a test.  This is only a test.
		AllowAttributes("disabled").OnElements("textarea").
		DisallowWithoutAttributes("textarea"))
	policy := Formatting.
		And(Blocks).
		And(Images).
		And(Styles).
		And(extras)
	input := "<textarea>text</textarea><textarea disabled></textarea>" +
		"<div onclick='redirect()'><span>Styled by span</span></div>"
	want := "text<textarea disabled=\"disabled\"></textarea>" +
		"<div><span>Styled by span</span></div>"
	sanCheck(t, "skip if empty", policy, []sanCase{{input, want}})
}

// TestSanitizersDeeplyNestedCSSFunctionsDoNotOverflowTheStack checks that
// deeply nested CSS functions in a style attribute, which used to overflow
// the stack in the CSS grammar, now drop the declaration and keep the rest of
// the attribute.
func TestSanitizersDeeplyNestedCSSFunctionsDoNotOverflowTheStack(t *testing.T) {
	policy := Styles.And(Blocks)
	const depth = 200000
	opens := strings.Repeat("rgb(", depth)
	closes := strings.Repeat(")", depth)
	sanCheck(t, "nested CSS functions", policy, []sanCase{
		{
			"<div style=\"color:" + opens + "1" + closes + "\">x</div>",
			"<div>x</div>",
		},
		{
			"<div style=\"color: red; width: " + opens + "1" + closes +
				"; background: blue\">x</div>",
			"<div style=\"color:red;background:blue\">x</div>",
		},
		// Unclosed, the lexer closes the functions at the end of the
		// attribute.
		{
			"<div style=\"color: red; width: " + opens + "1\">x</div>",
			"<div style=\"color:red\">x</div>",
		},
	})
}

func TestSanitizersIssue30(t *testing.T) {
	policy := Formatting.And(Blocks).And(Styles)
	sanCheck(t, "issue 30", policy, []sanCase{{"&nbsp;&gt;", "\u00a0&gt;"}})
}

func TestSanitizersScriptInTable(t *testing.T) {
	input := "<table>Hallo\r\n<script>SCRIPT</script>\nEnde\n\r"
	pf := Blocks.And(Formatting).
		And(Links).
		And(Styles).
		And(Images).
		And(Tables)
	// The CRLF after "Hallo" becomes LF
	// The LF before "Ende" becomes LF
	// The LF CR after "Ende" becomes LF LF
	sanCheck(t, "script in table", pf, []sanCase{{input, "<table></table>Hallo\n\nEnde\n\n"}})
}

func TestSanitizersAndOrdering(t *testing.T) {
	input := "" +
		"xss<a href=\"http://www.google.de\" style=\"color:red\"" +
		" onmouseover=alert(1) onmousemove=\"alert(2)\" onclick=alert(3)>" +
		"g" +
		"<img src=\"http://example.org\"/>oogle</a>"
	want := "" +
		"xss<a href=\"http://www.google.de\" style=\"color:red\"" +
		" rel=\"nofollow\">" +
		"g" +
		"<img src=\"http://example.org\" />oogle</a>"

	names := []string{"BLOCKS", "IMAGES", "STYLES", "LINKS"}
	factories := map[string]*PolicyFactory{
		"BLOCKS": Blocks,
		"IMAGES": Images,
		"STYLES": Styles,
		"LINKS":  Links,
	}
	permutations := sanPermutations(names, len(names))
	if len(permutations) != 24 {
		t.Fatalf("got %d permutations, want 24", len(permutations))
	}
	for _, permutation := range permutations {
		policyFactory := factories[permutation[0]]
		for _, name := range permutation[1:] {
			policyFactory = policyFactory.And(factories[name])
		}
		if got := policyFactory.Sanitize(input); got != want {
			t.Errorf("%v:\n got: %q\nwant: %q", permutation, got, want)
		}
	}
}

func TestSanitizersAngularBindingsInSanitizedCode(t *testing.T) {
	s := sanToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a", "b", "title").
		AllowAttributes("href").OnElements("a").
		AllowAttributes("title").Globally().
		AllowStandardURLProtocols())

	unsafe := "" +
		"<title>\n" +
		"Prevent Side Effects Due to {{expressions}} in angle brackets\n" +
		"</title>\n" +
		"<b>Also in {{regularTextNodes}}</b>\n" +
		"<b>Text nodes can be {<!-- split -->{Sneaky}}</b>\n" +
		"<b>Elided {<tags>{CanSplitToo}<span></span>}</b>\n" +
		"<a href='/{{path}}'>link</a>\n" +
		"<b title='{{title}}'>tag with title</b>\n"

	safe := "" +
		"<title>\n" +
		"Prevent Side Effects Due to" +
		" {\u200B{expressions}} in angle brackets\n" +
		"</title>\n" +
		"<b>Also in {<!-- -->{regularTextNodes}}</b>\n" +
		"<b>Text nodes can be {<!-- -->{Sneaky}}</b>\n" +
		"<b>Elided {<!-- -->{CanSplitToo}}</b>\n" +
		"<a href=\"/%7b%7bpath%7d%7d\">link</a>\n" +
		"<b title=\"{\u200B{title}}\">tag with title</b>\n"

	sanCheck(t, "angular bindings", s, []sanCase{{unsafe, safe}})
}

func TestSanitizersIssue46(t *testing.T) {
	s := sanToFactory(t, NewHTMLPolicyBuilder().
		AllowWithoutAttributes("span").
		AllowElements("span"))
	sanCheck(t, "issue 46", s, []sanCase{{
		"<span onclick=alert(1337)>Foo</span>",
		"<span>Foo</span>",
	}})
}

func TestSanitizersSpacesAroundURLAttributeValues(t *testing.T) {
	s := sanToFactory(t, NewHTMLPolicyBuilder().
		AllowStandardURLProtocols().
		AllowElements("a").
		AllowAttributes("href").OnElements("a"))
	sanCheck(t, "spaces around URL", s, []sanCase{{
		"<a href=\" http://example.com/ foo \t \">text</a>",
		"<a href=\"http://example.com/%20foo\">text</a>",
	}})
}

func TestSanitizersStyleTagInTable(t *testing.T) {
	input := "" +
		"<table>" +
		"<style></style>" +
		"<tr><td>Foo</td></tr>" +
		"<tr><td>Bar</td></tr>" +
		"</table>"
	pf := Blocks.
		And(Formatting).
		And(Tables)
	sanCheck(t, "style tag in table", pf, []sanCase{{
		input,
		"<table><tbody>" +
			"<tr><td>Foo</td></tr>" +
			"<tr><td>Bar</td></tr>" +
			"</tbody></table>",
	}})
}

func TestSanitizersStyleTagsInAllTheWrongPlaces(t *testing.T) {
	input := "" +
		"<select><option><style><script>alert(1)</script></style></option></select>" +
		"<svg><style>.r { color: red }</style></svg>" +
		"<style>.b { color: blue }</style>"
	pf := sanToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("option", "select", "style", "svg").
		AllowTextIn("style"))
	sanCheck(t, "style tags in the wrong places", pf, []sanCase{{
		input,
		"" +
			"<select><option>" +
			"<style></style>&lt;script&gt;alert(1)&lt;/script&gt;" +
			"</option></select>" +
			"<svg>" +
			"<style>.r { color: red }</style>" +
			"</svg>" +
			"<style>.b { color: blue }</style>",
	}})
}

func TestSanitizersSelectIsOdd(t *testing.T) {
	// Special text modes interact badly with select and option
	input := "<select><option><xmp><script>alert(1)</script></xmp></option></select>"
	pf := sanToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("option", "select", "xmp").
		AllowTextIn("xmp", "option"))
	sanCheck(t, "select is odd", pf, []sanCase{{
		input,
		"" +
			"<select><option><pre></pre>" +
			"&lt;script&gt;alert(1)&lt;/script&gt;" +
			"</option></select>",
	}})
}

func TestSanitizersOptionAllowsText(t *testing.T) {
	input := "<select><option><pre>code goes here</pre></option></select>"
	pf := sanToFactory(t, NewHTMLPolicyBuilder().
		AllowElements("option", "select", "pre").
		AllowTextIn("pre", "option"))
	sanCheck(t, "option allows text", pf, []sanCase{{
		input,
		"" +
			"<select><option>" +
			"<pre>code goes here</pre>" +
			"</option></select>",
	}})
}

func TestSanitizersStyleGlobally(t *testing.T) {
	policyBuilder := sanToFactory(t, NewHTMLPolicyBuilder().
		AllowAttributes("style").Globally().
		AllowElements("a", "label", "h1", "h2", "h3", "h4", "h5", "h6"))
	sanCheck(t, "style globally", policyBuilder, []sanCase{{
		"<h1 style=\"color:green ;name:user ;\">This is some green text</h1>",
		"<h1 style=\"color:green\">This is some green text</h1>",
	}})
}

// TestSanitizersStyleWithOtherAttributesGlobally is a regression test for
// https://github.com/OWASP/java-html-sanitizer/issues/237: other attributes
// allowed globally alongside style must survive, and style must still be
// filtered through the CSS schema.
func TestSanitizersStyleWithOtherAttributesGlobally(t *testing.T) {
	policyBuilder := sanToFactory(t, NewHTMLPolicyBuilder().
		AllowAttributes("style", "align").Globally().
		AllowElements("a", "label", "h1", "h2", "h3", "h4", "h5", "h6"))
	sanCheck(t, "style with other attributes globally", policyBuilder, []sanCase{{
		"<h1 style=\"color:green ;name:user ;\" align=\"center\">" +
			"This is some green centered text</h1>",
		"<h1 style=\"color:green\" align=\"center\">" +
			"This is some green centered text</h1>",
	}})
}

// sanFac returns n factorial.
func sanFac(n int) int {
	ifac := 1
	for i := 1; i <= n; i++ {
		ifac *= i
	}
	return ifac
}

// sanPermutations returns the length k partial permutations of elements,
// where all elements are assumed distinct.  Permutation i takes, at step j,
// the unused element whose rank among the unused ones is the next digit of i
// in the mixed radix k, k-1, ...; the expected results rely on that order.
func sanPermutations[T any](elements []T, k int) [][]T {
	limit := sanFac(len(elements)) / sanFac(len(elements)-k)
	var out [][]T
	for i := 0; i < limit; i++ {
		permutation := make([]T, 0, k)
		used := make([]bool, len(elements))
		for j, p := 0, i; j < k; j++ {
			m := k - j // Number of remaining elements.
			x := p % m
			p /= m

			// x is now an index into elements but without any elements
			// already used, so find the x-th unused spot.
			unfilled := -1
			for {
				unfilled++
				for used[unfilled] {
					unfilled++
				}
				if x == 0 {
					break
				}
				x--
			}
			used[unfilled] = true

			permutation = append(permutation, elements[unfilled])
		}
		out = append(out, permutation)
	}
	return out
}
