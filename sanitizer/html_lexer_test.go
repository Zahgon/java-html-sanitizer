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

// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/HtmlLexerTest.java.

package sanitizer

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestHTMLLexer(t *testing.T) {
	// Do the lexing.
	inputBytes, err := os.ReadFile("testdata/htmllexerinput1.html")
	if err != nil {
		t.Fatal(err)
	}
	// Normalize line endings in input to handle Windows/Unix differences
	input := normalizeLineEndings(string(inputBytes))
	var actual strings.Builder
	lexToGolden(input, &actual)

	// Get the golden.
	goldenBytes, err := os.ReadFile("testdata/htmllexergolden1.txt")
	if err != nil {
		t.Fatal(err)
	}
	// Normalize line endings to handle Windows/Unix differences
	golden := normalizeLineEndings(string(goldenBytes))
	actualStr := normalizeLineEndings(actual.String())

	// Compare.
	if actualStr != golden {
		t.Errorf("got\n%s\nwant\n%s", actualStr, golden)
	}
}

func normalizeLineEndings(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
}

func TestEOFInTag(t *testing.T) {
	assertTokens(t, "<div", "TAGBEGIN: <div")
	assertTokens(t, "</div", "TAGBEGIN: </div")
	assertTokens(t, "<div\n", "TAGBEGIN: <div")
	assertTokens(t, "</div\n", "TAGBEGIN: </div")
	assertTokens(t, "<div", "TAGBEGIN: <div")
	assertTokens(t, "</div", "TAGBEGIN: </div")
	assertTokens(t, "<div\n", "TAGBEGIN: <div")
	assertTokens(t, "</div\n", "TAGBEGIN: </div")
}

// TestEndTagOpenFollowedByANonLetter checks that after "</", only a letter
// starts an end tag.  A browser drops "</>" outright, turns anything else
// into a bogus comment that runs to the next ">", and takes "</" at the end
// of input as text (#410).  Inside literal content none of that applies.
func TestEndTagOpenFollowedByANonLetter(t *testing.T) {
	assertTokens(t, "</>", "COMMENT: </>")
	assertTokens(t, "</ notatag>x", "COMMENT: </ notatag>", "TEXT: x")
	assertTokens(t,
		"</\"<p>y</p>",
		"COMMENT: </\"<p>", "TEXT: y", "TAGBEGIN: </p", "TAGEND: >")
	assertTokens(t, "</<p>y", "COMMENT: </<p>", "TEXT: y")
	// Unterminated, the bogus comment runs to the end of input.
	assertTokens(t, "</\"", "COMMENT: </\"")
	assertTokens(t, "</", "TEXT: </")
	assertTokens(t, "a</", "TEXT: a</")
	// Literal content is text whatever follows "</", up to its end tag.
	assertTokens(t,
		"<script></\"</script>",
		"TAGBEGIN: <script", "TAGEND: >", "UNESCAPED: </\"",
		"TAGBEGIN: </script", "TAGEND: >")
	assertTokens(t,
		"<style>a</ b</style>",
		"TAGBEGIN: <style", "TAGEND: >", "UNESCAPED: a</ b",
		"TAGBEGIN: </style", "TAGEND: >")
}

func TestPartialTagInCData(t *testing.T) {
	assertTokens(t,
		"<script>w('</b')</script>",
		"TAGBEGIN: <script",
		"TAGEND: >",
		"UNESCAPED: w('</b')",
		"TAGBEGIN: </script",
		"TAGEND: >")
}

func TestURLEndingInSlashOutsideQuotes(t *testing.T) {
	assertTokens(t,
		"<a href=http://foo.com/>Clicky</a>",
		"TAGBEGIN: <a",
		"ATTRNAME: href",
		"ATTRVALUE: http://foo.com/",
		"TAGEND: >",
		"TEXT: Clicky",
		"TAGBEGIN: </a",
		"TAGEND: >")
}

func TestSlashStartsAnUnquotedValueAfterEquals(t *testing.T) {
	assertTokens(t,
		"<path d=/>x</path>",
		"TAGBEGIN: <path",
		"ATTRNAME: d",
		"ATTRVALUE: /",
		"TAGEND: >",
		"TEXT: x",
		"TAGBEGIN: </path",
		"TAGEND: >")
	assertTokens(t,
		"<path d = />x</path>",
		"TAGBEGIN: <path",
		"ATTRNAME: d",
		"ATTRVALUE: /",
		"TAGEND: >",
		"TEXT: x",
		"TAGBEGIN: </path",
		"TAGEND: >")
}

func TestShortTags(t *testing.T) {
	// See comments in html-sanitizer-test.js as to why we don't bother with
	// short tags.  In short, they are not in HTML5 and not implemented
	// properly in existing HTML4 clients.
	assertTokens(t,
		"<p<a href=\"/\">first part of the text</> second part",
		"TAGBEGIN: <p",
		"ATTRNAME: <a",
		"ATTRNAME: href",
		"ATTRVALUE: \"/\"",
		"TAGEND: >",
		"TEXT: first part of the text",
		// "</>" is nothing to a browser: an empty comment here.
		"COMMENT: </>",
		"TEXT:  second part")
	assertTokens(t,
		"<p/b/",
		"TAGBEGIN: <p",
		"ATTRNAME: /",
		"ATTRNAME: b/")
	assertTokens(t,
		"<p<b>",
		"TAGBEGIN: <p",
		"ATTRNAME: <b",
		"TAGEND: >")
}

func TestCommentDeclarationWith0CommentsAndXSS(t *testing.T) {
	// check https://datatracker.ietf.org/doc/html/rfc1866#section-3.2.5
	assertTokens(t, "<!><img src=1 onError=alert(\"nice\")>",
		"COMMENT: <!>",
		"TAGBEGIN: <img",
		"ATTRNAME: src",
		"ATTRVALUE: 1",
		"ATTRNAME: onError",
		"ATTRVALUE: alert(\"nice\")",
		"TAGEND: >",
	)
}

func TestTextEndingWithTagOpenAndBang(t *testing.T) {
	// taken from https://html.spec.whatwg.org/#comments
	assertTokens(t, "<!--My favorite operators are > and <!--><a></a>",
		"COMMENT: <!--My favorite operators are > and <!-->",
		"TAGBEGIN: <a",
		"TAGEND: >",
		"TAGBEGIN: </a",
		"TAGEND: >",
	)
}

func TestDashDashBangComment(t *testing.T) {
	assertTokens(t, "<!-- --!-->",
		"COMMENT: <!-- --!-->",
	)
}

func TestAbruptClosingOfEmptyComment(t *testing.T) {
	assertTokens(t, "<!--><img>a<!--->b<!->c",
		"COMMENT: <!-->",
		"TAGBEGIN: <img",
		"TAGEND: >",
		"TEXT: a",
		"COMMENT: <!--->",
		"TEXT: b",
		"COMMENT: <!->",
		"TEXT: c",
	)
}

func TestBangDashIsABogusComment(t *testing.T) {
	// <!- followed by anything but a dash is a bogus comment that ends at
	// the first '>', so <!-> must not swallow the following tag.
	assertTokens(t, "<!->c<b>after</b>",
		"COMMENT: <!->",
		"TEXT: c",
		"TAGBEGIN: <b",
		"TAGEND: >",
		"TEXT: after",
		"TAGBEGIN: </b",
		"TAGEND: >",
	)
	assertTokens(t, "<!-x>c<b>after</b>",
		"DIRECTIVE: <!-x>",
		"TEXT: c",
		"TAGBEGIN: <b",
		"TAGEND: >",
		"TEXT: after",
		"TAGBEGIN: </b",
		"TAGEND: >",
	)
}

func TestDashDashBangClosesCommentAfterLeadingDashes(t *testing.T) {
	// Issue #258: <!-- followed only by dashes and then --!> must terminate
	// rather than swallowing the rest of the document.
	assertTokens(t, "<!----!><b>after</b>",
		"COMMENT: <!----!>",
		"TAGBEGIN: <b",
		"TAGEND: >",
		"TEXT: after",
		"TAGBEGIN: </b",
		"TAGEND: >",
	)
	assertTokens(t, "<!-----!><b>after</b>",
		"COMMENT: <!-----!>",
		"TAGBEGIN: <b",
		"TAGEND: >",
		"TEXT: after",
		"TAGBEGIN: </b",
		"TAGEND: >",
	)
	// Fewer than two dashes after <!-- do not reach the comment end state,
	// so !> is ordinary comment content and the comment runs to the end.
	assertTokens(t, "<!--!><b>after</b>",
		"COMMENT: <!--!><b>after</b>",
	)
	assertTokens(t, "<!---!><b>after</b>",
		"COMMENT: <!---!><b>after</b>",
	)
}

func TestCommentCloseRequiresAdjacentDashes(t *testing.T) {
	// A dash followed by other content is ordinary comment text; only a
	// contiguous "-->" (or "--!>") closes the comment, as in a browser.
	assertTokens(t, "<!-- a -x-><b>after</b>",
		"COMMENT: <!-- a -x-><b>after</b>",
	)
	assertTokens(t, "<!-- a --b-><b>after</b>",
		"COMMENT: <!-- a --b-><b>after</b>",
	)
	assertTokens(t, "<!-- a -x--><b>after</b>",
		"COMMENT: <!-- a -x-->",
		"TAGBEGIN: <b",
		"TAGEND: >",
		"TEXT: after",
		"TAGBEGIN: </b",
		"TAGEND: >",
	)
	assertTokens(t, "<!-- a --b--><b>after</b>",
		"COMMENT: <!-- a --b-->",
		"TAGBEGIN: <b",
		"TAGEND: >",
		"TEXT: after",
		"TAGBEGIN: </b",
		"TAGEND: >",
	)
	// Issue #231: the comment used to end at "->" before "I'M".
	assertTokens(t, "<!-- COMMENT -- ME -> I'M ALONE --> MY CODE",
		"COMMENT: <!-- COMMENT -- ME -> I'M ALONE -->",
		"TEXT:  MY CODE",
	)
}

func TestIncorrectlyClosedComment(t *testing.T) {
	assertTokens(t, "<!-- Comment --!><img>",
		"COMMENT: <!-- Comment --!>",
		"TAGBEGIN: <img",
		"TAGEND: >",
	)
}

func TestQuoteNotAfterEqualsIsPartOfAttributeName(t *testing.T) {
	// Issue #189: the WHATWG tokenizer only starts a quoted value directly
	// after an attribute name and '='.  A quote anywhere else in a tag is an
	// ordinary character of an attribute name, so it must not pair with a
	// later quote and swallow the tag's '>' and the content after it.
	assertTokens(t, "<p class=\"test\" \"=\"\">bar</p> <p>baz</p>",
		"TAGBEGIN: <p",
		"ATTRNAME: class",
		"ATTRVALUE: \"test\"",
		"ATTRNAME: \"",
		"ATTRVALUE: \"\"",
		"TAGEND: >",
		"TEXT: bar",
		"TAGBEGIN: </p",
		"TAGEND: >",
		"TEXT:  ",
		"TAGBEGIN: <p",
		"TAGEND: >",
		"TEXT: baz",
		"TAGBEGIN: </p",
		"TAGEND: >",
	)
	assertTokens(t, "<p class=\"test\" \">bar</p>",
		"TAGBEGIN: <p",
		"ATTRNAME: class",
		"ATTRVALUE: \"test\"",
		"ATTRNAME: \"",
		"TAGEND: >",
		"TEXT: bar",
		"TAGBEGIN: </p",
		"TAGEND: >",
	)
	assertTokens(t, "<p \"a>b\">c</p>",
		"TAGBEGIN: <p",
		"ATTRNAME: \"a",
		"TAGEND: >",
		"TEXT: b\">c",
		"TAGBEGIN: </p",
		"TAGEND: >",
	)
	assertTokens(t, "<p class=\"a\"\"b\">x</p>",
		"TAGBEGIN: <p",
		"ATTRNAME: class",
		"ATTRVALUE: \"a\"",
		"ATTRNAME: \"b\"",
		"TAGEND: >",
		"TEXT: x",
		"TAGBEGIN: </p",
		"TAGEND: >",
	)
	assertTokens(t, "<p 'class'=\"test\">bar</p>",
		"TAGBEGIN: <p",
		"ATTRNAME: 'class'",
		"ATTRVALUE: \"test\"",
		"TAGEND: >",
		"TEXT: bar",
		"TAGBEGIN: </p",
		"TAGEND: >",
	)
}

func TestSlashInTagReturnsToBeforeAttributeName(t *testing.T) {
	// A '/' that does not close the tag puts the tokenizer back before an
	// attribute name, so the '=' after it starts a name rather than
	// introducing a value, and the quote after that is not a delimiter.
	// The lexer still pairs the '/' name with the quote as its value, which
	// is harmless: no policy allows either name and the tag ends at the '>'.
	assertTokens(t, "<p a/=\">y</p>",
		"TAGBEGIN: <p",
		"ATTRNAME: a/",
		"ATTRVALUE: \"",
		"TAGEND: >",
		"TEXT: y",
		"TAGBEGIN: </p",
		"TAGEND: >",
	)
	assertTokens(t, "<p a=\"x\"/=\">y</p>",
		"TAGBEGIN: <p",
		"ATTRNAME: a",
		"ATTRVALUE: \"x\"",
		"ATTRNAME: /",
		"ATTRVALUE: \"",
		"TAGEND: >",
		"TEXT: y",
		"TAGBEGIN: </p",
		"TAGEND: >",
	)
	// A '/' inside a name is just a character of it, so the value follows.
	assertTokens(t, "<p a/b=\"x\">y</p>",
		"TAGBEGIN: <p",
		"ATTRNAME: a/b",
		"ATTRVALUE: \"x\"",
		"TAGEND: >",
		"TEXT: y",
		"TAGBEGIN: </p",
		"TAGEND: >",
	)
}

func TestQuoteInUnquotedValueIsPartOfTheValue(t *testing.T) {
	// Once an unquoted value has started, a quote belongs to that value even
	// when it directly follows an '=', as in the tokenizer's unquoted value
	// state, so it does not start a new quoted value either.
	assertTokens(t, "<p class=x=\"y\">z</p>",
		"TAGBEGIN: <p",
		"ATTRNAME: class",
		"ATTRVALUE: x=\"y\"",
		"TAGEND: >",
		"TEXT: z",
		"TAGBEGIN: </p",
		"TAGEND: >",
	)
	assertTokens(t, "<p class=x=\">y</p>",
		"TAGBEGIN: <p",
		"ATTRNAME: class",
		"ATTRVALUE: x=\"",
		"TAGEND: >",
		"TEXT: y",
		"TAGBEGIN: </p",
		"TAGEND: >",
	)
}

func TestUnterminatedQuotedValueRunsToEndOfInput(t *testing.T) {
	// Conversely, a quote that does begin a value and is never closed takes
	// the rest of the input, which is where a browser hits EOF in the tag.
	assertTokens(t, "<p class=\">y</p>",
		"TAGBEGIN: <p",
		"ATTRNAME: class",
		"ATTRVALUE: \">y</p>",
	)
	assertTokens(t, "<p class = \">y</p>",
		"TAGBEGIN: <p",
		"ATTRNAME: class",
		"ATTRVALUE: \">y</p>",
	)
	// In "=", the first quote names an attribute and the second, which
	// follows the '=', begins its value.
	assertTokens(t, "<p \"=\">y</p>",
		"TAGBEGIN: <p",
		"ATTRNAME: \"",
		"ATTRVALUE: \">y</p>",
	)
}

func TestOnlyASCIIWhitespaceSeparatesTagTokens(t *testing.T) {
	// The five ASCII whitespace characters end a tag name or an unquoted
	// attribute value.  A broader whitespace test would also accept U+000B,
	// U+001C..U+001F and the Unicode space separators, but the WHATWG
	// tokenizer keeps those inside names and values, as validator.nu
	// confirms for each of the characters below.
	for _, ws := range []string{" ", "\t", "\n", "\f", "\r"} {
		assertTokens(t, "<b"+ws+"title=x>y</b>",
			"TAGBEGIN: <b", "ATTRNAME: title", "ATTRVALUE: x", "TAGEND: >",
			"TEXT: y", "TAGBEGIN: </b", "TAGEND: >")
		assertTokens(t, "<style>a</style"+ws+">b",
			"TAGBEGIN: <style", "TAGEND: >", "UNESCAPED: a",
			"TAGBEGIN: </style", "TAGEND: >", "TEXT: b")
	}
	for _, notWs := range []string{
		"\u000b", "\u001c", "\u001f", "\u0085", "\u00a0", "\u1680",
		"\u2000", "\u2028", "\u2029", "\u205f", "\u3000"} {
		r, _ := wtf8DecodeRune(notWs)
		m := fmt.Sprintf("U+%04X", r)
		// Part of the tag name.
		assertTokensFor(t, m, "<b"+notWs+"title=x>y</b>",
			"TAGBEGIN: <b"+notWs+"title=x", "TAGEND: >",
			"TEXT: y", "TAGBEGIN: </b", "TAGEND: >")
		// Part of an unquoted attribute value.
		assertTokensFor(t, m, "<b title=x"+notWs+"id=z>y</b>",
			"TAGBEGIN: <b", "ATTRNAME: title", "ATTRVALUE: x"+notWs+"id=z",
			"TAGEND: >", "TEXT: y", "TAGBEGIN: </b", "TAGEND: >")
		// Part of the next attribute's name after a quoted value.
		assertTokensFor(t, m, "<b title='x'"+notWs+"id=z>y</b>",
			"TAGBEGIN: <b", "ATTRNAME: title", "ATTRVALUE: 'x'",
			"ATTRNAME: "+notWs+"id", "ATTRVALUE: z", "TAGEND: >",
			"TEXT: y", "TAGBEGIN: </b", "TAGEND: >")
		// Does not end the end tag of a raw text element, so the element
		// stays open just as it does in a browser.
		assertTokensFor(t, m, "<style>a</style"+notWs+">b",
			"TAGBEGIN: <style", "TAGEND: >",
			"UNESCAPED: a</style"+notWs+">b")
	}
}

// lexToGolden writes one line per token of input to out, giving the
// token's type, its text with C style escaping so that it fits on one line,
// and its start and end offsets in UTF-16 code units, as the golden file has
// them.
func lexToGolden(input string, out *strings.Builder) {
	lexer := newHTMLLexer(input)
	maxTypeLength := 0
	for _, name := range htmlTokenTypeNames {
		maxTypeLength = max(maxTypeLength, len(name))
	}

	for lexer.hasNext() {
		t := lexer.next()
		// Do C style escaping of the token text so that each token in the
		// golden file can fit on one line.
		escaped := strings.ReplaceAll(
			strings.ReplaceAll(input[t.start:t.end], "\\", "\\\\"), "\n", "\\n")
		typ := t.typ.String()
		out.WriteString(typ)
		out.WriteString(strings.Repeat(" ", maxTypeLength-len(typ)))
		out.WriteString(" [")
		out.WriteString(escaped)
		out.WriteString("]  :  ")
		out.WriteString(strconv.Itoa(utf16Length(input[:t.start])))
		out.WriteByte('-')
		out.WriteString(strconv.Itoa(utf16Length(input[:t.end])))
		out.WriteByte('\n')
	}
}

func assertTokens(t *testing.T, markup string, golden ...string) {
	t.Helper()
	assertTokensFor(t, markup, markup, golden...)
}

func assertTokensFor(t *testing.T, message, markup string, golden ...string) {
	t.Helper()
	lexer := newHTMLLexer(markup)
	var actual []string
	for lexer.hasNext() {
		tok := lexer.next()
		actual = append(actual, tok.typ.String()+": "+markup[tok.start:tok.end])
	}
	if !slices.Equal(actual, golden) {
		t.Errorf("%s:\n got %q\nwant %q", message, actual, golden)
	}
}
