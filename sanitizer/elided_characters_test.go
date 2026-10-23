// Copyright (c) 2021, Simon Greatrix
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

// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/ElidedCharactersTest.java.

package sanitizer

// Some characters must not appear in HTML documents: the standard treats
// them as parse errors in the input stream and forbids character references
// to them.  Others, such as a raw U+000D, are a log injection risk.  These
// tests check that the sanitizer does not emit such characters, and that
// dropping one never joins the text around it into a tag, attribute or URL
// protocol that a policy would have rejected had it seen the joined form.
//
// See https://html.spec.whatwg.org/multipage/syntax.html#character-references
// (HTML 13.1.4 - Character references).

import (
	"fmt"
	"strings"
	"testing"
)

// elidedDiscouraged lists every code point that must not appear in sanitized
// output.  Lone surrogates are in their WTF-8 form.
var elidedDiscouraged = func() []string {
	var list []string

	// C0 controls, except the whitespace characters that XML allows.
	// U+000C FORM FEED is elided from text too, but it is ASCII whitespace
	// inside a tag, so it separates tag tokens like a space does; see
	// TestFormFeedIsTagWhitespaceButElidedFromText.
	for i := rune(0); i <= 0x1f; i++ {
		if i != '\t' && i != '\n' && i != '\r' && i != '\f' {
			list = append(list, string(i))
		}
	}

	// DEL and the C1 controls, which HTML forbids as character references
	// and XML discourages.  U+0085 NEL is among them: some systems read it
	// as a line break and others as an ellipsis, so it has no safe meaning.
	for i := rune(0x7f); i <= 0x9f; i++ {
		list = append(list, string(i))
	}

	// Isolated surrogates.  TestSurrogatePairsAreKept checks that a valid
	// pair survives.
	for i := rune(0xd800); i <= 0xdfff; i++ {
		list = append(list, string(wtf8AppendRune(nil, i)))
	}

	// The noncharacters in Arabic Presentation Forms-A.
	for i := rune(0xfdd0); i <= 0xfdef; i++ {
		list = append(list, string(i))
	}

	// The last two code points of the BMP and of every supplementary plane.
	list = append(list, string(rune(0xfffe)), string(rune(0xffff)))
	for plane := rune(1); plane <= 16; plane++ {
		list = append(list, string(0x10000*plane+0xfffe), string(0x10000*plane+0xffff))
	}

	return list
}()

// elidedLinksWithTitles lets through the attributes that the token merging
// cases aim at.
var elidedLinksWithTitles = func() *PolicyFactory {
	f, err := NewHTMLPolicyBuilder().
		AllowElements("a", "b").
		AllowAttributes("href", "title").OnElements("a").
		AllowStandardURLProtocols().
		ToFactory()
	if err != nil {
		panic(err)
	}
	return f
}()

func elidedDescribe(d string) string {
	r, _ := wtf8DecodeRune(d)
	return fmt.Sprintf("U+%04X", r)
}

func TestRemoveDiscouragedCharacterFromTagStart(t *testing.T) {
	// "<?h1>" is text, since '<' is not followed by a letter.
	for _, d := range elidedDiscouraged {
		if html := Blocks.Sanitize("<" + d + "h1></h1>"); html != "&lt;h1&gt;" {
			t.Errorf("%s: got %q", elidedDescribe(d), html)
		}
	}
	if got := Blocks.Sanitize("<h1></h1>"); got != "<h1></h1>" {
		t.Errorf("got %q", got)
	}
}

func TestRemoveDiscouragedCharacterFromInsideTag(t *testing.T) {
	// "<h?1>" is an unrecognised element and "</h1>" an unmatched end tag.
	for _, d := range elidedDiscouraged {
		if html := Blocks.Sanitize("<h" + d + "1></h1>"); html != "" {
			t.Errorf("%s: got %q", elidedDescribe(d), html)
		}
	}
	if got := Blocks.Sanitize("<h1></h1>"); got != "<h1></h1>" {
		t.Errorf("got %q", got)
	}
}

func TestRemoveDiscouragedCharacterFromTagEnd(t *testing.T) {
	// "<h1?>" is an unrecognised element: the character is not whitespace,
	// so it does not end the tag name.
	for _, d := range elidedDiscouraged {
		if html := Blocks.Sanitize("<h1" + d + "></h1>"); html != "" {
			t.Errorf("%s: got %q", elidedDescribe(d), html)
		}
	}
	if got := Blocks.Sanitize("<h1></h1>"); got != "<h1></h1>" {
		t.Errorf("got %q", got)
	}
}

func elidedAssertPcdataEncoded(t *testing.T, message, want, plainText string) {
	t.Helper()
	var builder strings.Builder
	if err := encodingEncodePcdataOnto(plainText, &builder); err != nil {
		t.Fatal(err)
	}
	if got := builder.String(); got != want {
		t.Errorf("%s: got %q, want %q", message, got, want)
	}
}

func TestRemoveDiscouragedCharacterFromEndWhenEncoding(t *testing.T) {
	for _, d := range elidedDiscouraged {
		elidedAssertPcdataEncoded(t, elidedDescribe(d), "Hello", "Hello"+d)
	}
}

func TestRemoveDiscouragedCharacterFromMiddleWhenEncoding(t *testing.T) {
	for _, d := range elidedDiscouraged {
		elidedAssertPcdataEncoded(t, elidedDescribe(d), "Hello", "Hel"+d+"lo")
	}
}

func TestRemoveDiscouragedCharacterFromStartWhenEncoding(t *testing.T) {
	for _, d := range elidedDiscouraged {
		elidedAssertPcdataEncoded(t, elidedDescribe(d), "Hello", d+"Hello")
	}
}

func TestDiscouragedCharacterIsStrippedWhenDecoding(t *testing.T) {
	for _, d := range elidedDiscouraged {
		m := elidedDescribe(d)
		if got := DecodeHTML("Hel"+d+"lo", false); got != "Hello" {
			t.Errorf("%s: got %q", m, got)
		}
		if got := DecodeHTML("Hel"+d+"lo", true); got != "Hello" {
			t.Errorf("%s: got %q", m, got)
		}
		// Stripping happens after references are decoded, so a stripped
		// character cannot turn the text around it into a reference.
		if got := DecodeHTML("&l"+d+"t;", false); got != "&lt;" {
			t.Errorf("%s: got %q", m, got)
		}
	}
}

// elidedAssertSanitized checks what elidedLinksWithTitles makes of html.
func elidedAssertSanitized(t *testing.T, message, want, html string) {
	t.Helper()
	if got := elidedLinksWithTitles.Sanitize(html); got != want {
		t.Errorf("%s: %q: got %q, want %q", message, html, got, want)
	}
}

func TestDiscouragedCharacterDoesNotHideAScriptTag(t *testing.T) {
	for _, d := range elidedDiscouraged {
		m := elidedDescribe(d)
		// '<' followed by a non-letter is text.
		elidedAssertSanitized(t, m, "&lt;script&gt;alert(1)",
			"<"+d+"script>alert(1)</script>")
		// "<s?cript>" is an unknown element, so its content is ordinary
		// text and the end tag matches nothing.  It must not become
		// <script>.
		elidedAssertSanitized(t, m, "alert(1)", "<s"+d+"cript>alert(1)</script>")
		elidedAssertSanitized(t, m, "x", "<b"+d+">x</b>")
	}
}

func TestDiscouragedCharacterDoesNotSplitAnAttribute(t *testing.T) {
	for _, d := range elidedDiscouraged {
		m := elidedDescribe(d)
		// Inside a tag the character is not whitespace, so "a?href=..." is
		// one unknown element name rather than an <a> with an href.
		elidedAssertSanitized(t, m, "x", "<a"+d+"href=\"javascript:alert(1)\">x</a>")
		// An unquoted value runs on past the character, so
		// "onclick=alert(1)" stays inside the title value and never becomes
		// an attribute.
		elidedAssertSanitized(t, m,
			"<a href=\"/\" title=\"onclick&#61;alert(1)\">x</a>",
			"<a href=\"/\" title="+d+"onclick=alert(1)>x</a>")
		elidedAssertSanitized(t, m,
			"<a href=\"/\" title=\"onclick&#61;alert(1)\">x</a>",
			"<a href=\"/\" title=\""+d+"onclick=alert(1)\">x</a>")
	}
}

func TestDiscouragedCharacterDoesNotHideAURLProtocol(t *testing.T) {
	for _, d := range elidedDiscouraged {
		m := elidedDescribe(d)
		// The character is stripped before the URL policy runs, so the
		// policy sees "javascript:" and rejects it.  Stripping it only on
		// output would let "java?script:" through as an unknown protocol and
		// then emit "javascript:".
		elidedAssertSanitized(t, m, "x", "<a href=\"java"+d+"script:alert(1)\">x</a>")
		// Nor can it hide a character reference from the decoder: "&?#58;"
		// stays a literal ampersand, which the encoder escapes.
		elidedAssertSanitized(t, m,
			"<a href=\"javascript&amp;#58;alert%281%29\">x</a>",
			"<a href=\"javascript&"+d+"#58;alert(1)\">x</a>")
	}
}

func TestSurrogatePairsAreKept(t *testing.T) {
	elidedAssertPcdataEncoded(t, "U+1F600", "a&#x1f600;b", "a\U0001f600b")
	elidedAssertSanitized(t, "U+1F600", "<b>a&#x1f600;b</b>", "<b>a\U0001f600b</b>")
	// The last assigned code point of a plane is kept; the two
	// noncharacters after it are not.
	elidedAssertPcdataEncoded(t, "plane 1", "a&#x1fffd;b",
		"a\U0001fffdb\U0001fffe\U0001ffff")
}

func TestFormFeedIsTagWhitespaceButElidedFromText(t *testing.T) {
	// U+000C is one of the five ASCII whitespace characters, so inside a tag
	// it separates tokens like a space; it is not an XML character, so it
	// is dropped from text.
	elidedAssertSanitized(t, "form feed", "<b>x</b>", "<b\f>x</b>")
	elidedAssertPcdataEncoded(t, "form feed", "ab", "a\fb")
}

func TestCarriageReturnsAreNormalizedToLineFeeds(t *testing.T) {
	// As the HTML input stream preprocessor does, so rendering is unchanged
	// and the output never contains a raw U+000D.
	// CRLF and a lone CR each become LF; LF CR is two line breaks.
	elidedAssertSanitized(t, "CR", "a\nb\nc\n\n", "a\r\nb\rc\n\r")
	elidedAssertSanitized(t, "CR", "a\nb", "a&#13;b")
	elidedAssertSanitized(t, "CR",
		"<a href=\"/\" title=\"a\nb\">x</a>",
		"<a href=\"/\" title=\"a\r\nb\">x</a>")
}
