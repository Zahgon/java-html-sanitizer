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

// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/HtmlStreamRendererTest.java.

package sanitizer

import (
	"slices"
	"strings"
	"testing"
)

// rendererFixture holds a renderer writing to rendered and reporting bad
// HTML to errors.
type rendererFixture struct {
	t        *testing.T
	errors   []string
	rendered strings.Builder
	renderer *HTMLStreamRenderer
}

// newRendererFixture returns a fixture that, when the test ends, catches any
// test that does not check the errors it caused.
func newRendererFixture(t *testing.T) *rendererFixture {
	f := &rendererFixture{t: t}
	f.renderer = NewHTMLStreamRendererToBuilder(&f.rendered, func(e string) {
		f.errors = append(f.errors, e)
	})
	t.Cleanup(func() {
		if len(f.errors) != 0 {
			t.Errorf("unchecked errors: %q", f.errors)
		}
	})
	return f
}

// assertErrors checks the errors reported so far and clears them.
func (f *rendererFixture) assertErrors(want ...string) {
	f.t.Helper()
	if !slices.Equal(f.errors, want) {
		f.t.Errorf("errors: got %q, want %q", f.errors, want)
	}
	f.errors = nil
}

// assertRendered checks the output.
func (f *rendererFixture) assertRendered(want string) {
	f.t.Helper()
	if got := f.rendered.String(); got != want {
		f.t.Errorf("rendered: got %q, want %q", got, want)
	}
}

func TestEmptyDocument(t *testing.T) {
	f := newRendererFixture(t)
	f.assertNormalized("", "")
}

func TestElementNamesNormalized(t *testing.T) {
	f := newRendererFixture(t)
	f.assertNormalized("<br />", "<br>")
	f.assertNormalized("<br />", "<BR>")
	f.assertNormalized("<br />", "<Br />")
	f.assertNormalized("<br />", "<br\n>")
}

func TestAttributeNamesNormalized(t *testing.T) {
	f := newRendererFixture(t)
	f.assertNormalized("<input id=\"foo\" />", "<input  id=foo>")
	f.assertNormalized("<input id=\"foo\" />", "<input id=\"foo\">")
	f.assertNormalized("<input id=\"foo\" />", "<input  ID='foo'>")
	f.assertNormalized("<input id=\"foo\" />", "<input\nid='foo'>")
	f.assertNormalized("<input id=\"foo\" />", "<input\nid=foo'>")
}

func TestAttributeValuesEscaped(t *testing.T) {
	f := newRendererFixture(t)
	f.assertNormalized("<div title=\"a&lt;b\"></div>", "<div title=a<b></div>")
}

func TestRcdataEscaped(t *testing.T) {
	f := newRendererFixture(t)
	f.assertNormalized(
		"<title>I &lt;3 PONIES, OMG!!!</title>",
		"<TITLE>I <3 PONIES, OMG!!!</TITLE>")
}

func TestCdataNotEscaped(t *testing.T) {
	f := newRendererFixture(t)
	f.assertNormalized(
		"<script>I <3\n!!!PONIES, OMG</script>",
		"<script>I <3\n!!!PONIES, OMG</script>")
}

func TestIllegalElementName(t *testing.T) {
	f := newRendererFixture(t)
	r := f.renderer
	r.OpenDocument()
	r.OpenTag(":svg", nil)
	r.OpenTag("svg:", nil)
	r.OpenTag("-1", nil)
	r.OpenTag("svg::svg", nil)
	r.OpenTag("a@b", nil)
	r.CloseDocument()

	if output := f.rendered.String(); strings.Contains(output, "<") {
		t.Error(output)
	}

	f.assertErrors(
		"Invalid element name : :svg",
		"Invalid element name : svg:",
		"Invalid element name : -1",
		"Invalid element name : svg::svg",
		"Invalid element name : a@b")
}

func TestIllegalAttributeName(t *testing.T) {
	f := newRendererFixture(t)
	r := f.renderer
	r.OpenDocument()
	r.OpenTag("div", []string{":svg", "x"})
	r.OpenTag("div", []string{"svg:", "x"})
	r.OpenTag("div", []string{"-1", "x"})
	r.OpenTag("div", []string{"svg::svg", "x"})
	r.OpenTag("div", []string{"a@b", "x"})
	r.CloseDocument()

	if output := f.rendered.String(); strings.Contains(output, "=") {
		t.Error(output)
	}

	f.assertErrors(
		"Invalid attr name : :svg",
		"Invalid attr name : svg:",
		"Invalid attr name : -1",
		"Invalid attr name : svg::svg",
		"Invalid attr name : a@b")
}

// recordingDropListener records the drops a renderer reports.
type recordingDropListener struct {
	drops []string
}

func (l *recordingDropListener) droppedText(elementName, text string) {
	l.drops = append(l.drops, elementName+"{"+text+"}")
}

func (l *recordingDropListener) droppedTag(elementName string) {
	l.drops = append(l.drops, "<"+elementName+">")
}

func (l *recordingDropListener) droppedAttribute(elementName, name, value string) {
	l.drops = append(l.drops, elementName+"."+name+"="+value)
}

// TestDropsReachTheDropListener checks that what the renderer drops reaches
// its drop listener as well as the bad-HTML handler, so that an
// HTMLChangeReporter can report it (#469): a tag it cannot write, an
// attribute it cannot write, and a tag inside literal content.  An end tag
// refused for the same reason as its start tag is the same loss and is not
// reported again.
func TestDropsReachTheDropListener(t *testing.T) {
	f := newRendererFixture(t)
	r := f.renderer
	listener := &recordingDropListener{}
	r.OpenDocument()
	r.reportDropsTo(listener)
	r.OpenTag("a@b", []string{"id", "x"})
	r.Text("t")
	r.CloseTag("a@b")
	r.OpenTag("div", []string{"x@y", "1", "id", "z"})
	r.OpenTag("style", nil)
	r.Text("a")
	r.OpenTag("b", nil)
	r.Text("bold")
	r.CloseTag("b")
	r.CloseTag("style")
	r.CloseTag("div")
	r.CloseDocument()

	f.assertRendered("t<div id=\"z\"><style>abold</style></div>")
	if want := []string{"<a@b>", "div.x@y=1", "<b>"}; !slices.Equal(listener.drops, want) {
		t.Errorf("drops: got %q, want %q", listener.drops, want)
	}
	f.assertErrors(
		"Invalid element name : a@b",
		"Invalid element name : a@b",
		"Invalid attr name : x@y",
		"Tag content cannot appear inside CDATA element : b",
		"Tag content cannot appear inside CDATA element : b")
}

func TestCdataContainsEndTag1(t *testing.T) {
	f := newRendererFixture(t)
	r := f.renderer
	r.OpenDocument()
	r.OpenTag("script", []string{"type", "text/javascript"})
	r.Text("document.write('<SCRIPT>alert(42)</SCRIPT>')")
	r.CloseTag("script")
	r.CloseDocument()

	f.assertRendered("<script type=\"text/javascript\"></script>")
	f.assertErrors("Invalid CDATA text content : </SCRIPT>'")
}

func TestCdataContainsEndTag2(t *testing.T) {
	f := newRendererFixture(t)
	r := f.renderer
	r.OpenDocument()
	r.OpenTag("style", []string{"type", "text/css"})
	r.Text("/* </St")
	// Split into two text chunks, and insert NULs.
	r.Text("\x00yle> */")
	r.CloseTag("style")
	r.CloseDocument()

	f.assertRendered("<style type=\"text/css\"></style>")
	f.assertErrors("Invalid CDATA text content : </Style> *")
}

func TestRcdataContainsEndTag(t *testing.T) {
	f := newRendererFixture(t)
	r := f.renderer
	r.OpenDocument()
	r.OpenTag("textarea", nil)
	r.Text("<textarea></textarea>")
	r.CloseTag("textarea")
	r.CloseDocument()

	f.assertRendered("<textarea>&lt;textarea&gt;&lt;/textarea&gt;</textarea>")
}

func TestEndTagInsideScriptBodyInner(t *testing.T) {
	f := newRendererFixture(t)
	f.assertNormalized(
		"<script></script>&#39;)--&gt;",
		"<script><!--document.write('<SCRIPT>alert(42)</SCRIPT>')--></script>")
	f.assertErrors("Invalid CDATA text content : <SCRIPT>al")
}

// Testcases from
// www.w3.org/TR/html51/semantics-scripting.html#restrictions-for-contents-of-script-elements

func TestHTML51SemanticsScriptingExample5Part1(t *testing.T) {
	f := newRendererFixture(t)
	js := "  var example = 'Consider this string: <!-- <script>';\n" +
		"  console.log(example);\n"

	f.renderScript(js)

	f.assertRendered("<script></script>")
	f.assertErrors("Invalid CDATA text content : <script>';")
}

func TestHTML51SemanticsScriptingExample5Part2(t *testing.T) {
	f := newRendererFixture(t)
	js := "if (x<!--y) { ... }\n"

	f.renderScript(js)

	f.assertRendered("<script></script>")
	f.assertErrors("Invalid CDATA text content : <!--y) { .")
}

func TestMoreUnbalancedHTMLCommentsInScripts(t *testing.T) {
	f := newRendererFixture(t)
	js := "if (x-->y) { ... }\n"

	f.renderScript(js)

	// We could actually allow this since --> is not banned per 4.12.1.3
	f.assertRendered("<script></script>")
	f.assertErrors("Invalid CDATA text content : -->y) { ..")
}

func TestShortHTMLCommentInScript(t *testing.T) {
	f := newRendererFixture(t)
	js := "// <!----> <!--->"

	f.renderScript(js)

	// We could actually allow this since --> is not banned per 4.12.1.3
	f.assertRendered("<script></script>")
	f.assertErrors("Invalid CDATA text content : <!--->")
}

func TestHTML51SemanticsScriptingExample5Part3(t *testing.T) {
	f := newRendererFixture(t)
	js := "<!-- if ( player<script ) { ... } -->"

	f.renderScript(js)

	f.assertRendered("<script></script>")
	f.assertErrors("Invalid CDATA text content : <script ) ")
}

func TestHTML51SemanticsScriptingExample5Part4(t *testing.T) {
	f := newRendererFixture(t)
	js := "<!--\n" +
		"if (x < !--y) { ... }\n" +
		"if (!--y > x) { ... }\n" +
		"if (!(--y) > x) { ... }\n" +
		"if (player < script) { ... }\n" +
		"if (script > player) { ... }\n" +
		"-->"

	f.renderScript(js)

	f.assertRendered("<script><!--\n" +
		"if (x < !--y) { ... }\n" +
		"if (!--y > x) { ... }\n" +
		"if (!(--y) > x) { ... }\n" +
		"if (player < script) { ... }\n" +
		"if (script > player) { ... }\n" +
		"--></script>")
}

// renderScript renders a document holding a script element with content
// js.
func (f *rendererFixture) renderScript(js string) {
	r := f.renderer
	r.OpenDocument()
	r.OpenTag("script", nil)
	r.Text(js)
	r.CloseTag("script")
	r.CloseDocument()
}

func TestHTMLCommentInRcdata(t *testing.T) {
	f := newRendererFixture(t)
	r := f.renderer
	str := "// <!----> <!---> <!--"

	r.OpenDocument()
	r.OpenTag("title", nil)
	r.Text(str)
	r.CloseTag("title")
	r.OpenTag("textarea", nil)
	r.Text(str)
	r.CloseTag("textarea")
	r.CloseDocument()

	f.assertRendered(
		"<title>// &lt;!----&gt; &lt;!---&gt; &lt;!--</title>" +
			"<textarea>// &lt;!----&gt; &lt;!---&gt; &lt;!--</textarea>")
}

func TestTagInCdata(t *testing.T) {
	f := newRendererFixture(t)
	r := f.renderer
	r.OpenDocument()
	r.OpenTag("script", nil)
	r.Text("alert('")
	r.OpenTag("b", nil)
	r.Text("foo")
	r.CloseTag("b")
	r.Text("')")
	r.CloseTag("script")
	r.CloseDocument()

	f.assertRendered("<script>alert('foo')</script>")
	f.assertErrors(
		"Tag content cannot appear inside CDATA element : b",
		"Tag content cannot appear inside CDATA element : b")
}

func TestUnclosedEscapingTextSpan(t *testing.T) {
	f := newRendererFixture(t)
	f.renderScript("<!--alert('</script>')")

	f.assertRendered("<script></script>")
	f.assertErrors("Invalid CDATA text content : </script>'")
}

func TestAlmostCompleteEndTag(t *testing.T) {
	f := newRendererFixture(t)
	f.renderScript("//</scrip")

	f.assertRendered("<script>//</scrip</script>")
}

func TestBalancedCommentInNoscript(t *testing.T) {
	f := newRendererFixture(t)
	r := f.renderer
	r.OpenDocument()
	r.OpenTag("noscript", nil)
	r.Text("<!--<script>foo</script>-->")
	r.CloseTag("noscript")
	r.CloseDocument()

	f.assertRendered(
		"<noscript>&lt;!--&lt;script&gt;foo&lt;/script&gt;--&gt;</noscript>")
}

func TestUnbalancedCommentInNoscript(t *testing.T) {
	f := newRendererFixture(t)
	r := f.renderer
	r.OpenDocument()
	r.OpenTag("noscript", nil)
	r.Text("<!--<script>foo</script>--")
	r.CloseTag("noscript")
	r.OpenTag("noscript", nil)
	r.Text("<script>foo</script>-->")
	r.CloseTag("noscript")
	r.CloseDocument()

	f.assertRendered(
		"<noscript>&lt;!--&lt;script&gt;foo&lt;/script&gt;--</noscript>" +
			"<noscript>&lt;script&gt;foo&lt;/script&gt;--&gt;</noscript>")
}

func TestSupplementaryCodepoints(t *testing.T) {
	f := newRendererFixture(t)
	r := f.renderer
	r.OpenDocument()
	r.Text("\U0002f81a") // Supplementary codepoint U+2F81A
	r.CloseDocument()

	f.assertRendered("&#x2f81a;")
}

// Test that policies that naively allow <xmp>, <listing>, or <plaintext>
// on XHTML don't shoot themselves in the foot.

func TestPreSubstitutes1(t *testing.T) {
	f := newRendererFixture(t)
	r := f.renderer
	r.OpenDocument()
	r.OpenTag("Xmp", nil)
	r.Text("<form>Hello, World</form>")
	r.CloseTag("Xmp")
	r.CloseDocument()

	f.assertRendered("<pre>&lt;form&gt;Hello, World&lt;/form&gt;</pre>")
}

func TestPreSubstitutes2(t *testing.T) {
	f := newRendererFixture(t)
	r := f.renderer
	r.OpenDocument()
	r.OpenTag("xmp", nil)
	r.Text("<form>Hello, World</form>")
	r.CloseTag("xmp")
	r.CloseDocument()

	f.assertRendered("<pre>&lt;form&gt;Hello, World&lt;/form&gt;</pre>")
}

func TestPreSubstitutes3(t *testing.T) {
	f := newRendererFixture(t)
	r := f.renderer
	r.OpenDocument()
	r.OpenTag("LISTING", nil)
	r.Text("<form>Hello, World</form>")
	r.CloseTag("LISTING")
	r.CloseDocument()

	f.assertRendered("<pre>&lt;form&gt;Hello, World&lt;/form&gt;</pre>")
}

func TestPreSubstitutes4(t *testing.T) {
	f := newRendererFixture(t)
	r := f.renderer
	r.OpenDocument()
	r.OpenTag("plaintext", nil)
	r.Text("<form>Hello, World</form>")
	r.CloseDocument()

	f.assertRendered("<pre>&lt;form&gt;Hello, World&lt;/form&gt;")
}

func (f *rendererFixture) assertNormalized(golden, htmlInput string) {
	f.t.Helper()
	if got := f.normalize(htmlInput); got != golden {
		f.t.Errorf("normalize(%q) = %q, want %q", htmlInput, got, golden)
	}

	// Check that normalization is idempotent.
	if golden != htmlInput {
		f.assertNormalized(golden, golden)
	}
}

// forwardingPolicy is a permissive sanitizer policy that sends every event
// to a renderer.
type forwardingPolicy struct {
	renderer *HTMLStreamRenderer
}

func (p forwardingPolicy) OpenTag(elementName string, attrs []string) {
	p.renderer.OpenTag(elementName, attrs)
}

func (p forwardingPolicy) CloseTag(elementName string) { p.renderer.CloseTag(elementName) }

func (p forwardingPolicy) Text(textChunk string) { p.renderer.Text(textChunk) }

func (p forwardingPolicy) OpenDocument() { p.renderer.OpenDocument() }

func (p forwardingPolicy) CloseDocument() { p.renderer.CloseDocument() }

func (f *rendererFixture) normalize(htmlInput string) string {
	// Use a permissive sanitizer to generate the events.
	Sanitize(htmlInput, forwardingPolicy{f.renderer},
		IdentityProcessor)

	result := f.rendered.String()
	f.rendered.Reset()
	return result
}

func TestRawTextElementInsideForeignContentIsDecodedBeforeEscaping(t *testing.T) {
	f := newRendererFixture(t)
	r := f.renderer
	r.OpenDocument()
	r.OpenTag("svg", nil)
	r.OpenTag("style", nil)
	// The lexer does not decode character references in raw text elements.
	r.Text("a &amp; b &lt;c&gt; &#x3c;d>")
	r.CloseTag("style")
	// Text outside the raw text element arrives decoded as usual.
	r.Text("x &amp; y")
	r.CloseTag("svg")
	r.CloseDocument()

	f.assertRendered(
		"<svg><style>a &amp; b &lt;c&gt; &lt;d&gt;</style>x &amp;amp; y</svg>")
}

func TestRawTextElementOutsideForeignContentIsNotDecoded(t *testing.T) {
	f := newRendererFixture(t)
	r := f.renderer
	r.OpenDocument()
	r.OpenTag("style", nil)
	r.Text("a &amp; b")
	r.CloseTag("style")
	r.CloseDocument()

	f.assertRendered("<style>a &amp; b</style>")
}
