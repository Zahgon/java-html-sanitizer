// Copyright (c) 2012, Mike Samuel
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

// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/EncodingTest.java.

package sanitizer

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"unsafe"
)

// encodingTestLone returns the WTF-8 form of a lone surrogate code unit,
// which Go string literals cannot spell with \u.
func encodingTestLone(unit rune) string {
	return string(wtf8AppendRune(nil, unit))
}

func assertDecodedHTML(t *testing.T, want, inputHTML string) {
	t.Helper()
	assertDecodedHTMLInContexts(t, want, want, inputHTML)
}

func assertDecodedHTMLInContexts(t *testing.T, wantText, wantAttr, inputHTML string) {
	t.Helper()
	if got := DecodeHTML(inputHTML, false); got != wantText {
		t.Errorf("!inAttribute: %q: got %q, want %q", inputHTML, got, wantText)
	}
	if got := DecodeHTML(inputHTML, true); got != wantAttr {
		t.Errorf("inAttribute: %q: got %q, want %q", inputHTML, got, wantAttr)
	}
}

// sameString reports whether a and b share their bytes, that is, whether one
// was returned for the other without a copy.
func sameString(a, b string) bool {
	return len(a) == len(b) && unsafe.StringData(a) == unsafe.StringData(b)
}

func TestDecodeHTML(t *testing.T) {
	html := "The quick&nbsp;brown fox&#xa;jumps over&#xd;&#10;the lazy dog&#x000a;"
	//          1         2         3         4         5         6
	// 123456789012345678901234567890123456789012345678901234567890123456789
	golden := "The quick\u00a0brown fox\njumps over\r\nthe lazy dog\n"
	assertDecodedHTML(t, golden, html)

	// Don't allocate a new string when no entities.
	if !sameString(DecodeHTML(golden, false), golden) {
		t.Error("decoding text without entities allocated a new string")
	}

	// test interrupted escapes and escapes at end of file handled gracefully
	assertDecodedHTML(t, "\\\\u000a", "\\\\u000a")
	assertDecodedHTML(t, "\n", "&#x000a;")
	assertDecodedHTML(t, "\n", "&#x00a;")
	assertDecodedHTML(t, "\n", "&#x0a;")
	assertDecodedHTML(t, "\n", "&#xa;")
	assertDecodedHTML(t, string(rune(0x10000)), "&#x10000;")
	assertDecodedHTML(t, "\n", "&#xa")
	assertDecodedHTML(t, "&#x00ziggy", "&#x00ziggy")
	assertDecodedHTML(t, "&#xa00z;", "&#xa00z;")
	assertDecodedHTML(t, "&#\n", "&#&#x000a;")
	assertDecodedHTML(t, "&#x\n", "&#x&#x000a;")
	assertDecodedHTML(t, "\n\n", "&#xa&#x000a;")
	assertDecodedHTML(t, "&#\n", "&#&#xa;")
	assertDecodedHTML(t, "&#x", "&#x")
	assertDecodedHTML(t, "", "&#x0") // NUL elided.
	assertDecodedHTML(t, "&#", "&#")

	assertDecodedHTML(t, "\\", "\\")
	assertDecodedHTML(t, "&", "&")

	assertDecodedHTML(t, "&#000a;", "&#000a;")
	assertDecodedHTML(t, "\n", "&#10;")
	assertDecodedHTML(t, "\n", "&#010;")
	assertDecodedHTML(t, "\n", "&#0010;")
	assertDecodedHTML(t, "\t", "&#9;")
	assertDecodedHTML(t, "\n", "&#10")
	assertDecodedHTML(t, "&#00ziggy", "&#00ziggy")
	assertDecodedHTML(t, "&#\n", "&#&#010;")
	assertDecodedHTML(t, "\n", "&#0&#010;")
	assertDecodedHTML(t, "\n", "&#01&#10;")
	assertDecodedHTML(t, "&#\n", "&#&#10;")
	assertDecodedHTML(t, "", "&#1") // Invalid XML char elided.
	assertDecodedHTML(t, "\t", "&#9")
	assertDecodedHTML(t, "\n", "&#10")

	// test the named escapes
	assertDecodedHTML(t, "<", "&lt;")
	assertDecodedHTML(t, ">", "&gt;")
	assertDecodedHTML(t, "\"", "&quot;")
	assertDecodedHTML(t, "'", "&apos;")
	assertDecodedHTML(t, "'", "&#39;")
	assertDecodedHTML(t, "'", "&#x27;")
	assertDecodedHTML(t, "&", "&amp;")
	assertDecodedHTML(t, "&lt;", "&amp;lt;")
	assertDecodedHTML(t, "&", "&AMP;")
	assertDecodedHTML(t, "&", "&AMP")
	assertDecodedHTML(t, "&", "&AmP;")
	assertDecodedHTML(t, "\u0391", "&Alpha;")
	assertDecodedHTML(t, "\u03b1", "&alpha;")
	// U+1D49C requires a surrogate pair in UTF-16.
	assertDecodedHTML(t, "\U0001d49c", "&Ascr;")
	// &fjlig; refers to 2 characters.
	assertDecodedHTML(t, "fj", "&fjlig;")
	// HTML entity with the longest name.
	assertDecodedHTML(t, "\u2233", "&CounterClockwiseContourIntegral;")
	// Missing the semicolon.
	assertDecodedHTML(t,
		"&CounterClockwiseContourIntegral",
		"&CounterClockwiseContourIntegral")

	assertDecodedHTML(t, "&;", "&;")
	assertDecodedHTML(t, "&bogus;", "&bogus;")

	// Some strings decode differently depending on whether or not they're in
	// an HTML attribute.
	assertDecodedHTMLInContexts(t,
		"?foo\u00b6m=bar",
		"?foo&param=bar",
		"?foo&param=bar")
	assertDecodedHTMLInContexts(t,
		"?foo\u00b6=bar",
		"?foo&para=bar",
		"?foo&para=bar")

	// Banned code units are stripped after character references are decoded,
	// so a banned code unit cannot split text that would otherwise be a
	// character reference into one.
	assertDecodedHTML(t, "lt<", "lt&lt;")
	assertDecodedHTML(t, "ltlt;", "ltlt;")
	assertDecodedHTML(t, "lt&lt;", "lt&&#108;t;")
	assertDecodedHTML(t, "lt&<", "lt&&lt;")

	assertDecodedHTML(t, "lt&&lt;gt",
		"\ufdddlt&&l\ufffet;"+encodingTestLone(0xdc9c)+encodingTestLone(0xd835)+"gt")
	assertDecodedHTML(t, "lt&<", "lt&&lt;"+encodingTestLone(0xdc9c))
	assertDecodedHTML(t, "lt&<", "lt&&lt;"+encodingTestLone(0xd835))

	// DEL and the C1 controls are stripped, raw or as references, like the
	// C0 controls; encodeHtmlOnto elides them, and policies must see the
	// same text that will be emitted.
	assertDecodedHTML(t, "ab", "a\u007fb")
	assertDecodedHTML(t, "ab", "a&#x7f;b")
	assertDecodedHTML(t, "ab", "a\u0085b")
	assertDecodedHTML(t, "ab", "a\u009fb")
	assertDecodedHTML(t, "a&lt;b", "a\u0085&l\u0085t;b")

	// A numeric reference in the C1 range is read as a Windows-1252 byte, as
	// browsers do, so it is a printable character rather than a control.
	assertDecodedHTML(t, "a\u2026b", "a&#x85;b")
	assertDecodedHTML(t, "a\u2026b", "a&#133;b")
	assertDecodedHTML(t, "a\u2026b", "a&#x0085;b")
	assertDecodedHTML(t, "a\u20acb", "a&#x80;b")
	assertDecodedHTML(t, "a\u0178b", "a&#x9f;b")
	assertDecodedHTML(t, "a\u2122b", "a&#153;b")
	// The bytes that Windows-1252 leaves undefined stay C1 controls, which
	// are stripped.
	assertDecodedHTML(t, "ab", "a&#x81;b")
	assertDecodedHTML(t, "ab", "a&#x8d;b")
	assertDecodedHTML(t, "ab", "a&#x8f;b")
	assertDecodedHTML(t, "ab", "a&#x90;b")
	assertDecodedHTML(t, "ab", "a&#x9d;b")
	// The mapping applies only to references, not to raw characters, and not
	// to the neighbouring ranges.
	assertDecodedHTML(t, "ab", "a\u0080b")
	assertDecodedHTML(t, "a\u00a0b", "a&#xa0;b")
	assertDecodedHTML(t, "ab", "a&#x7f;b")
	assertDecodedHTML(t, "a\u00a0b", "a\u00a0b")

	// Noncharacters, in the BMP and in the supplementary planes.
	assertDecodedHTML(t, "ab", "a\ufdd0b")
	assertDecodedHTML(t, "ab", "a&#xfdd0;b")
	assertDecodedHTML(t, "a\ufdcf\ufdf0b", "a\ufdcf\ufdf0b")
	assertDecodedHTML(t, "ab", "a\U0001fffeb")
	assertDecodedHTML(t, "ab", "a&#x1fffe;b")
	assertDecodedHTML(t, "ab", "a&#x10ffff;b")
	assertDecodedHTML(t, "a\U0001fffdb", "a\U0001fffdb")
}

func TestC1NumericReferencesDecodeAsWindows1252(t *testing.T) {
	// https://html.spec.whatwg.org/multipage/parsing.html#numeric-character-reference-end-state
	table := [][2]rune{
		{0x80, 0x20ac}, {0x82, 0x201a}, {0x83, 0x0192}, {0x84, 0x201e},
		{0x85, 0x2026}, {0x86, 0x2020}, {0x87, 0x2021}, {0x88, 0x02c6},
		{0x89, 0x2030}, {0x8a, 0x0160}, {0x8b, 0x2039}, {0x8c, 0x0152},
		{0x8e, 0x017d}, {0x91, 0x2018}, {0x92, 0x2019}, {0x93, 0x201c},
		{0x94, 0x201d}, {0x95, 0x2022}, {0x96, 0x2013}, {0x97, 0x2014},
		{0x98, 0x02dc}, {0x99, 0x2122}, {0x9a, 0x0161}, {0x9b, 0x203a},
		{0x9c, 0x0153}, {0x9e, 0x017e}, {0x9f, 0x0178},
	}
	var mapped [0x20]bool
	for _, row := range table {
		want := string(row[1])
		assertDecodedHTML(t, want, "&#x"+strconv.FormatInt(int64(row[0]), 16)+";")
		assertDecodedHTML(t, want, "&#"+strconv.Itoa(int(row[0]))+";")
		mapped[row[0]-0x80] = true
	}
	for b := 0x80; b <= 0x9f; b++ {
		if !mapped[b-0x80] {
			assertDecodedHTML(t, "", "&#x"+strconv.FormatInt(int64(b), 16)+";")
		}
	}
}

func TestAppendNumericEntityAndEncodeOnto(t *testing.T) {
	var sb, cps strings.Builder
	// Test with a set of legal code points
	for _, codepoint := range []rune{
		9, '\n', '@', 0xa0, 0xff, 0x100, 0xfff, 0x1000, 0x123a, 0xfffd,
		0x10000, maxCodePoint - 2,
	} {
		if err := encodingAppendNumericEntity(codepoint, &sb); err != nil {
			t.Fatal(err)
		}
		sb.WriteByte(' ')

		cps.WriteRune(codepoint)
		cps.WriteByte(' ')
	}

	if got, want := sb.String(),
		"&#9; &#10; &#64; &#xa0; &#xff; &#x100; &#xfff; &#x1000; "+
			"&#x123a; &#xfffd; &#x10000; &#x10fffd; "; got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	var out strings.Builder
	if err := encodingEncodeHTMLAttribOnto(cps.String(), &out); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(),
		"\t \n &#64; \u00a0 \u00ff \u0100 \u0fff \u1000 "+
			"\u123a &#xfffd; &#x10000; &#x10fffd; "; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestAppendIllegalNumericEntityAndEncodeOnto(t *testing.T) {
	var sb strings.Builder
	var cps wtf8Builder
	// Code points to which HTML forbids a numeric character reference.
	for _, codepoint := range []rune{
		0, 8, '\r', 0x1f, 0x7f, 0x80, 0x85, 0x9f, 0xd800, 0xdfff,
		0xfdd0, 0xfdef, 0xfffe, 0xffff, 0x1fffe, 0x3ffff, 0x10ffff,
		maxCodePoint + 1, -1,
	} {
		err := encodingAppendNumericEntity(codepoint, &sb)
		if err == nil {
			t.Errorf("Illegal code point was accepted: %d", codepoint)
		} else if want := "Cannot write a character reference to U+" +
			strconv.FormatUint(uint64(uint32(codepoint)), 16); err.Error() != want {
			t.Errorf("got error %q, want %q", err, want)
		}
		if 0 <= codepoint && codepoint <= maxCodePoint {
			cps.appendCodePoint(codepoint)
			_ = cps.WriteByte(',')
		}
	}
	if got := sb.String(); got != "" {
		t.Errorf("got %q, want nothing written", got)
	}

	// The encoder elides all of them, except that CR becomes LF.
	var out strings.Builder
	if err := encodingEncodeHTMLAttribOnto(cps.String(), &out); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), ",,\n,,,,,,,,,,,,,,,"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestAngularJSBracesInTextNode(t *testing.T) {
	var sb strings.Builder

	_ = encodingEncodePcdataOnto("{{angularVariable}}", &sb)
	if got, want := sb.String(), "{<!-- -->{angularVariable}}"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	sb.Reset()

	_ = encodingEncodePcdataOnto("{", &sb)
	_ = encodingEncodePcdataOnto("{angularVariable}}", &sb)
	if got, want := sb.String(), "{<!-- -->{angularVariable}}"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func assertStripped(t *testing.T, stripped, orig string) {
	t.Helper()
	actual := encodingStripBannedCodeunits(orig)
	if actual != stripped {
		t.Errorf("%q: got %q, want %q", orig, actual, stripped)
	}
	if stripped == orig && !sameString(actual, orig) {
		t.Errorf("%q: stripping nothing allocated a new string", orig)
	}
}

func TestStripBannedCodeunits(t *testing.T) {
	lone := encodingTestLone
	assertStripped(t, "", "")
	assertStripped(t, "foo", "foo")
	assertStripped(t, "foobar", "foo\u0000bar")
	assertStripped(t, "foobar", "foo\u0000bar\u0000")
	assertStripped(t, "foobar", "foo\ufffebar\u0008")
	assertStripped(t, "foobar", "foo"+lone(0xd800)+"bar"+lone(0xdc00))
	assertStripped(t, "foo\U00010000bar", "foo"+lone(0xd800)+"\U00010000bar")
	assertStripped(t, "foo\U00010000bar", "foo\U00010000"+lone(0xd800)+"bar")
	assertStripped(t, "foo\U00010000bar", "foo\U00010000"+lone(0xdc00)+"bar")
	assertStripped(t, "foo\U00010000bar", "foo"+lone(0xdc00)+"\U00010000bar")
	assertStripped(t, "foo\U0001d11ebar", "foo\U0001d11ebar")
	assertStripped(t, "foo\U0001d11e", "foo\U0001d11e")
	assertStripped(t, "foobar", "foo\u007fbar")
	assertStripped(t, "foobar", "foo\u0080\u0085\u009fbar")
	assertStripped(t, "foo\u00a0bar", "foo\u00a0bar")
	assertStripped(t, "foobar", "foo\ufdd0bar\ufdef")
	assertStripped(t, "foo\ufdcf\ufdf0bar", "foo\ufdcf\ufdf0bar")

	// The last two code points of every plane are noncharacters.
	for plane := rune(0); plane <= 16; plane++ {
		o := 0x10000 * plane
		prefix := fmt.Sprintf("%02x", plane)
		s := prefix + string(o+0xffef) + string(o+0xfffd) +
			string(o+0xfffe) + string(o+0xffff)
		want := prefix + string(o+0xffef) + string(o+0xfffd)
		assertStripped(t, want, s)

		s = "foo" + string(o+0xfffe) + string(o+0xffff) + "bar"
		assertStripped(t, "foobar", s)
	}
}

func TestBadlyDonePostProcessingWillnotAllowInsertingNonceAttributes(t *testing.T) {
	// Some clients do ad-hoc post processing of the output.
	// String replace of {{...}} shouldn't turn
	//   <span title="{{">}} <br class="a nonce=xyz "></span>
	// into
	//   <span title="x <br class="a nonce=xyz "></span>
	// which contains CSP directives.
	// We prevent this by being strict about quotes to prevent ending an
	// attribute with quotes about strict mode, and being strict about equals
	// signs to prevent text nodes or attribute values from introducing an
	// attribute with a value.
	var pcdata strings.Builder
	_ = encodingEncodePcdataOnto("\" nonce=xyz", &pcdata)
	if got, want := pcdata.String(), "&#34; nonce&#61;xyz"; got != want {
		t.Errorf("pcdata: got %q, want %q", got, want)
	}

	var rcdata strings.Builder
	_ = EncodeRcdataOnto("\" nonce=xyz", &rcdata)
	if got, want := rcdata.String(), "&#34; nonce&#61;xyz"; got != want {
		t.Errorf("rcdata: got %q, want %q", got, want)
	}

	var attrib strings.Builder
	_ = encodingEncodeHTMLAttribOnto("a nonce=xyz ", &attrib)
	if got, want := attrib.String(), "a nonce&#61;xyz "; got != want {
		t.Errorf("attrib: got %q, want %q", got, want)
	}
}

// TestRiskyNormalizationSetContents checks the table in encoding.go against
// the characters whose NFKD decomposition contains ASCII punctuation.  Go's
// standard library has no NFKD, so that set is recorded in testdata.
func TestRiskyNormalizationSetContents(t *testing.T) {
	f, err := os.Open("testdata/nfkd_ascii_punctuation.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var risky [0x10000]bool
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		first, last, isRange := strings.Cut(line, "..")
		if !isRange {
			last = first
		}
		lo, err1 := strconv.ParseUint(first, 16, 16)
		hi, err2 := strconv.ParseUint(last, 16, 16)
		if err1 != nil || err2 != nil {
			t.Fatalf("bad line %q", line)
		}
		for c := lo; c <= hi; c++ {
			risky[c] = true
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	for c := rune(0x80); c < 0xfffe; c++ {
		if isRisky := risky[c]; isRisky != encodingIsRiskyNormalization(c) {
			what := "should not be in the table"
			if isRisky {
				what = "missing from the table"
			}
			t.Errorf("U+%04X: %s.  If the Unicode tables are newer than "+
				"encodingRiskyNormalization, update the table.", c, what)
		}
	}
}

func assertRcdataEncoded(t *testing.T, want, plainText string) {
	t.Helper()
	var sb strings.Builder
	if err := EncodeRcdataOnto(plainText, &sb); err != nil {
		t.Fatal(err)
	}
	if got := sb.String(); got != want {
		t.Errorf("%q: got %q, want %q", plainText, got, want)
	}
}

func TestRiskyNormalization(t *testing.T) {
	// Characters whose compatibility decomposition contains ASCII
	// punctuation are written as references so that a later normalization
	// of the output cannot produce an HTML special character.
	assertRcdataEncoded(t, "Small Less-than Sign : &#xfe64;",
		"Small Less-than Sign : \ufe64")
	assertRcdataEncoded(t, "Fullwidth Quotation Mark : &#xff02;",
		"Fullwidth Quotation Mark : \uff02")
	assertRcdataEncoded(t, "Greek Varia : &#x1fef;", "Greek Varia : \u1fef")
	assertRcdataEncoded(t, "Greek Question Mark : &#x37e;",
		"Greek Question Mark : \u037e")
	assertRcdataEncoded(t, "One Dot Leader : &#x2024;", "One Dot Leader : \u2024")
	assertRcdataEncoded(t, "Double Exclamation Mark : &#x203c;",
		"Double Exclamation Mark : \u203c")

	// Everything from U+FE60 up is written as a reference whether or not it
	// normalizes to something risky: the byte order mark, the fullwidth
	// letters and the replacement character among them.
	assertRcdataEncoded(t, "BOM : &#xfeff;", "BOM : \ufeff")
	assertRcdataEncoded(t, "Fullwidth A : &#xff21;", "Fullwidth A : \uff21")
	assertRcdataEncoded(t, "Replacement : &#xfffd;", "Replacement : \ufffd")
	assertRcdataEncoded(t, "Arabic ligature : &#xfefb;", "Arabic ligature : \ufefb")

	// Below U+FE60, characters with a harmless or no decomposition pass.
	assertRcdataEncoded(t, "NBSP : \u00a0", "NBSP : \u00a0")
	assertRcdataEncoded(t, "Ligature : \ufb01", "Ligature : \ufb01")
	assertRcdataEncoded(t, "CJK : \u4e2d\u6587", "CJK : \u4e2d\u6587")
}

func TestNewLineNormalization(t *testing.T) {
	// https://infra.spec.whatwg.org/#normalize-newlines
	assertRcdataEncoded(t, "\none\ntwo\n", "\rone\ntwo\r")
	assertRcdataEncoded(t, "\none\ntwo\n", "\none\rtwo\n")
	assertRcdataEncoded(t, "\none\ntwo\n", "\r\none\r\ntwo\r\n")
	assertRcdataEncoded(t, "\n\none\n\ntwo\n\n", "\n\rone\n\rtwo\n\r")
	assertRcdataEncoded(t, "\n\none\n\ntwo\n\n", "\r\rone\n\ntwo\r\r")
	assertRcdataEncoded(t, "\n", "\r")
	assertRcdataEncoded(t, "", "")

	var attrib strings.Builder
	_ = encodingEncodeHTMLAttribOnto("a\r\nb\rc", &attrib)
	if got, want := attrib.String(), "a\nb\nc"; got != want {
		t.Errorf("attrib: got %q, want %q", got, want)
	}
	var pcdata strings.Builder
	_ = encodingEncodePcdataOnto("a\r\nb\rc", &pcdata)
	if got, want := pcdata.String(), "a\nb\nc"; got != want {
		t.Errorf("pcdata: got %q, want %q", got, want)
	}
}

// TestInvalidUTF8ReadsAsReplacementCharacter checks how invalid UTF-8 is
// handled: each invalid byte is U+FFFD.
func TestInvalidUTF8ReadsAsReplacementCharacter(t *testing.T) {
	assertDecodedHTML(t, "a\ufffdb\ufffd&", "a\xffb\xc3&amp;")
	assertStripped(t, "a\ufffdb", "a\xffb")
	assertRcdataEncoded(t, "a&#xfffd;b", "a\xffb")
}

// TestSurrogatePairSpelledInWTF8 checks that a surrogate pair spelled as two
// WTF-8 surrogates, or decoded from two references, is treated as the pair.
func TestSurrogatePairSpelledInWTF8(t *testing.T) {
	cesu := encodingTestLone(0xd835) + encodingTestLone(0xdc9c)
	assertDecodedHTML(t, "\U0001d49c", "&#xd835;&#xdc9c;")
	assertDecodedHTML(t, "\U0001d49c", encodingTestLone(0xd835)+"&#xdc9c;")
	assertDecodedHTML(t, "\U0001d49c", "&#xd835;"+encodingTestLone(0xdc9c))
	assertStripped(t, "a\U0001d49c", "a"+cesu)
	assertRcdataEncoded(t, "a&#x1d49c;", "a"+cesu)
	if got := encodingStripBannedCodeunits("&#xd835;&#xdc9c;"); got != "&#xd835;&#xdc9c;" {
		t.Errorf("got %q", got)
	}
}
