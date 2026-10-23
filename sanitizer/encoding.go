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

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/Encoding.java.

package sanitizer

// Encoders and decoders for HTML.
//
// Text is handled one UTF-16 code unit at a time: see utf16.go for how
// strings carry lone surrogates.  A byte that is
// not part of a valid UTF-8 sequence counts as U+FFFD REPLACEMENT CHARACTER,
// which the decoder writes out in full and the encoders write as a numeric
// character reference.

import (
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// DecodeHTML decodes HTML entities to produce a string containing
// only valid Unicode scalar values.
//
// s is text/html, and inAttribute tells whether it is in an attribute value.
// The result is text/plain.
func DecodeHTML(s string, inAttribute bool) string {
	firstAmp := strings.IndexByte(s, '&')
	safeLimit := encodingLongestPrefixOfGoodCodeunits(s)
	if firstAmp < 0 && safeLimit < 0 {
		return s
	}

	var sb wtf8Builder
	{
		n := len(s)
		sb.buf = make([]byte, 0, n)
		pos := 0
		amp := firstAmp
		for amp >= 0 {
			_, _ = sb.WriteString(s[pos:amp])
			end := htmlEntitiesAppendDecodedEntity(s, amp, n, inAttribute, &sb)
			pos = end
			amp = strings.IndexByte(s[end:], '&')
			if amp >= 0 {
				amp += end
			}
		}
		_, _ = sb.WriteString(s[pos:n])
	}

	start := firstAmp
	switch {
	case firstAmp < 0:
		start = safeLimit
	case safeLimit >= 0:
		start = min(firstAmp, safeLimit)
	}
	return encodingStripBannedCodeunitsFrom(sb.String(), start)
}

// encodingStripBannedCodeunits returns the portion of its input that consists
// of chars that are safe in both XML and HTML: the XML Character production
// without the noncharacters, DEL and the C1 controls that HTML treats as
// parse errors.  It returns s itself when every char is safe.
//
// See http://www.w3.org/TR/2008/REC-xml-20081126/#charsets (XML Ch. 2.2 -
// Characters) and
// https://html.spec.whatwg.org/multipage/parsing.html#preprocessing-the-input-stream
// (HTML 13.2.3.5 - Preprocessing the input stream).
func encodingStripBannedCodeunits(s string) string {
	safeLimit := encodingLongestPrefixOfGoodCodeunits(s)
	if safeLimit < 0 {
		return s
	}
	return encodingStripBannedCodeunitsFrom(s, safeLimit)
}

// encodingStripBannedCodeunitsFrom keeps s[:start] and, of the rest, only the
// chars that are safe in both XML and HTML.  A surrogate pair spelled as two
// WTF-8 surrogates comes out as four-byte UTF-8, and an invalid byte as the
// UTF-8 encoding of U+FFFD.
func encodingStripBannedCodeunitsFrom(s string, start int) string {
	out := make([]byte, start, len(s))
	copy(out, s[:start])
	for i, n := start, len(s); i < n; {
		ch := s[i]
		if ch < utf8.RuneSelf {
			if (ch >= 0x20 || !encodingIsBannedASCII[ch]) && ch != 0x7f {
				out = append(out, ch)
			}
			i++
			continue
		}
		r, size := wtf8DecodeRune(s[i:])
		switch {
		case r <= 0x9f:
			// DEL and the C1 controls.  encodeHtmlOnto elides them, so they
			// are stripped here too: policies must judge the text that will
			// be emitted, not text that a later elision would join up
			// differently.
		case isSurrogate(r):
			if isHighSurrogate(r) {
				if next, nextSize := wtf8DecodeRune(s[i+size:]); isLowSurrogate(next) {
					// The last two code points of each plane are
					// noncharacters.
					if cp := combineSurrogates(r, next); !encodingIsNoncharacter(cp) {
						out = utf8.AppendRune(out, cp)
					}
					size += nextSize
				}
			}
		case encodingIsNoncharacter(r):
		case r == utf8.RuneError && size == 1:
			out = utf8.AppendRune(out, utf8.RuneError)
		default:
			out = append(out, s[i:i+size]...)
		}
		i += size
	}
	return string(out)
}

// encodingLongestPrefixOfGoodCodeunits returns the number of bytes at the
// front of s that form chars that encodingStripBannedCodeunits keeps as they
// are, or -1 if all of s is kept.
func encodingLongestPrefixOfGoodCodeunits(s string) int {
	for i, n := 0, len(s); i < n; {
		ch := s[i]
		if ch < utf8.RuneSelf {
			if (ch < 0x20 && encodingIsBannedASCII[ch]) || ch == 0x7f {
				return i
			}
			i++
			continue
		}
		r, size := wtf8DecodeRune(s[i:])
		if r <= 0x9f || isSurrogate(r) || encodingIsNoncharacter(r) ||
			(r == utf8.RuneError && size == 1) {
			// A WTF-8 surrogate is either orphaned or half of a pair that
			// must be rewritten as four-byte UTF-8, and an invalid byte must
			// be rewritten as U+FFFD.
			return i
		}
		i += size
	}
	return -1
}

// encodingIsNoncharacter reports whether codepoint is one of the 66 Unicode
// noncharacters: U+FDD0..U+FDEF and the last two code points of every plane.
// HTML treats them as parse errors and forbids numeric character references
// to them.
//
// See https://infra.spec.whatwg.org/#noncharacter
func encodingIsNoncharacter(codepoint rune) bool {
	return codepoint&0xfffe == 0xfffe ||
		(0xfdd0 <= codepoint && codepoint <= 0xfdef)
}

// encodingEncodeHTMLAttribOnto appends an encoded form of plainText to output
// where the encoding is sufficient to prevent an HTML parser from
// interpreting any characters in the appended chunk as part of an attribute
// or tag boundary.
//
// output is a buffer of text/html that has a well-formed HTML prefix that
// ends after the open-quote of an attribute value and does not yet contain a
// corresponding close quote.  The result is the first error output returns.
func encodingEncodeHTMLAttribOnto(plainText string, output io.Writer) error {
	return encodingEncodeHTMLOnto(plainText, output, "{\u200b")
}

// encodingEncodePcdataOnto appends an encoded form of plainText to output
// where the encoding is sufficient to prevent an HTML parser from
// transitioning out of the Data state
// (https://html.spec.whatwg.org/multipage/parsing.html#data-state).
//
// This is suitable for encoding a text node inside any element that does not
// require special handling as a context element (see "context element" in
// step 4 of
// https://html.spec.whatwg.org/multipage/parsing.html#parsing-html-fragments).
//
// output is a buffer of text/html that has a well-formed HTML prefix that
// would leave an HTML parser in the Data state if it were to encounter a
// space character as the next character.  In practice this means that the
// buffer does not contain partial tags or comments, and does not have an
// unclosed element with a special content model.  The result is the first
// error output returns.
func encodingEncodePcdataOnto(plainText string, output io.Writer) error {
	// Avoid problems with client-side template languages like
	// Angular & Polymer which attach special significance to text like
	// {{...}}.
	// We split brackets so that these template languages don't end up
	// executing expressions in sanitized text.
	return encodingEncodeHTMLOnto(plainText, output, "{<!-- -->")
}

// EncodeRcdataOnto appends an encoded form of plainText to output
// where the encoding is sufficient to prevent an HTML parser from
// transitioning out of the RCDATA state
// (https://html.spec.whatwg.org/multipage/parsing.html#rcdata-state).
//
// This is suitable for encoding a text node inside a <textarea> or <title>
// element outside foreign content.
//
// output is a buffer of text/html that has a well-formed HTML prefix that
// would leave an HTML parser in the Data state if it were to encounter a
// space character as the next character.  In practice this means that the
// buffer does not contain partial tags or comments, and the most recently
// opened element is <textarea> or <title> and that element is still open.
// The result is the first error output returns.
func EncodeRcdataOnto(plainText string, output io.Writer) error {
	// Avoid problems with client-side template languages like
	// Angular & Polymer which attach special significance to text like
	// {{...}}.
	// We split brackets so that these template languages don't end up
	// executing expressions in sanitized text.
	return encodingEncodeHTMLOnto(plainText, output, "{\u200b")
}

// encodingEncodeHTMLOnto writes the HTML equivalent of the given plain text
// to output.  For example, encoding "1 < 2" is equivalent to writing
// "1 &lt; 2" but possibly with fewer smaller writes.
//
// It elides code-units that are not valid XML Characters, and the
// noncharacters, DEL and C1 controls that HTML forbids in character
// references and treats as parse errors in the input stream.  It normalizes
// CR and CRLF to LF as the HTML input stream preprocessor does, so the output
// never contains a raw carriage return.  It stops at, and returns, the first
// error output returns.
//
// See http://www.w3.org/TR/2008/REC-xml-20081126/#charsets (XML Ch. 2.2 -
// Characters),
// https://html.spec.whatwg.org/multipage/syntax.html#character-references
// (HTML 13.1.4 - Character references) and
// https://infra.spec.whatwg.org/#normalize-newlines (Infra - normalize
// newlines).
func encodingEncodeHTMLOnto(
	plainText string, output io.Writer, braceReplacement string,
) error {
	n := len(plainText)
	pos := 0
	for i := 0; i < n; {
		ch := plainText[i]
		if ch < utf8.RuneSelf { // Handles all ASCII.
			repl, ok := encodingReplacements[ch], encodingHasReplacement[ch]
			if !ok {
				if ch == '{' {
					if i+1 == n || plainText[i+1] == '{' {
						repl, ok = braceReplacement, true
					}
				} else if ch == '\r' {
					// CRLF becomes LF by dropping the CR; a lone CR becomes
					// LF.
					repl, ok = "\n", true
					if i+1 < n && plainText[i+1] == '\n' {
						repl = ""
					}
				}
			}
			if ok {
				if err := encodingWriteStrings(output, plainText[pos:i], repl); err != nil {
					return err
				}
				pos = i + 1
			}
			i++
			continue
		}
		// An invalid byte decodes as U+FFFD, which is written as a reference
		// below like everything from U+FE60 up.
		r, size := wtf8DecodeRune(plainText[i:])
		switch {
		case r <= 0x9f || encodingIsNoncharacter(r):
			// Elide the C1 controls and the BMP noncharacters.
			if err := encodingWriteStrings(output, plainText[pos:i]); err != nil {
				return err
			}
			pos = i + size
		case isSurrogate(r) || r > 0xffff:
			codepoint := r
			if isHighSurrogate(r) {
				if next, nextSize := wtf8DecodeRune(plainText[i+size:]); isLowSurrogate(next) {
					codepoint = combineSurrogates(r, next)
					size += nextSize
				}
			}
			if err := encodingWriteStrings(output, plainText[pos:i]); err != nil {
				return err
			}
			if !isSurrogate(codepoint) && !encodingIsNoncharacter(codepoint) {
				// Emit supplemental codepoints as entity so that they cannot
				// be mis-encoded as UTF-8 of surrogates instead of UTF-8
				// proper and get involved in UTF-16/UCS-2 confusion.
				if err := encodingAppendNumericEntity(codepoint, output); err != nil {
					return err
				}
			}
			// Otherwise elide the orphaned surrogate.
			pos = i + size
		case 0xfe60 <= r || encodingIsRiskyNormalization(r):
			// Above U+FE60 lie the small form variants, Arabic presentation
			// forms, the halfwidth and fullwidth forms, the byte order mark
			// and the specials block: full-width versions of HTML special
			// characters and code points that an encoding conversion may drop
			// or mangle.  Elsewhere in the BMP, encodingIsRiskyNormalization
			// picks out characters whose compatibility decomposition contains
			// ASCII punctuation, such as U+1FEF GREEK VARIA which normalizes
			// to a backtick.  Either way, a numeric reference survives any
			// later normalization of the output unchanged.
			if err := encodingWriteStrings(output, plainText[pos:i]); err != nil {
				return err
			}
			pos = i + size
			if err := encodingAppendNumericEntity(r, output); err != nil {
				return err
			}
		}
		i += size
	}
	return encodingWriteStrings(output, plainText[pos:n])
}

// encodingWriteStrings writes each of strs to output, skipping empty ones,
// and returns the first error.
func encodingWriteStrings(output io.Writer, strs ...string) error {
	for _, s := range strs {
		if s == "" {
			continue
		}
		if _, err := io.WriteString(output, s); err != nil {
			return err
		}
	}
	return nil
}

// encodingAppendNumericEntity appends a numeric character reference for the
// code point to the output.
//
// It returns an error, and writes nothing, if HTML forbids a numeric
// character reference to the code point: controls other than TAB and LF,
// surrogates, noncharacters and values above U+10FFFF.
//
// See https://html.spec.whatwg.org/multipage/syntax.html#character-references
// (HTML 13.1.4 - Character references).
func encodingAppendNumericEntity(codepoint rune, output io.Writer) error {
	if (codepoint < 0x20 && codepoint != '\t' && codepoint != '\n') ||
		(0x7f <= codepoint && codepoint <= 0x9f) ||
		isSurrogate(codepoint) ||
		codepoint > maxCodePoint ||
		encodingIsNoncharacter(codepoint) {
		return errors.New(
			"Cannot write a character reference to U+" +
				strconv.FormatUint(uint64(uint32(codepoint)), 16))
	}
	var buf [16]byte
	b := append(buf[:0], "&#"...)
	if codepoint < 100 {
		// Below 100 the decimal form is shortest.
		b = strconv.AppendInt(b, int64(codepoint), 10)
	} else {
		b = append(b, 'x')
		b = strconv.AppendInt(b, int64(codepoint), 16)
	}
	b = append(b, ';')
	_, err := output.Write(b)
	return err
}

// encodingReplacements maps ASCII chars that need to be encoded to an
// equivalent HTML entity, where encodingHasReplacement says there is one.
var (
	encodingReplacements   [0x80]string
	encodingHasReplacement [0x80]bool
)

// encodingIsBannedASCII[i], where i is an ASCII control character code point
// (< 0x20), is true for control characters that are not allowed in an XML
// source text.
var encodingIsBannedASCII [0x20]bool

func init() {
	replace := func(ch byte, repl string) {
		encodingReplacements[ch] = repl
		encodingHasReplacement[ch] = true
	}
	for i := byte(0); i < ' '; i++ {
		// We elide control characters so that we can ensure that our output
		// is in the intersection of valid HTML5 and XML.  According to
		// http://www.w3.org/TR/2008/REC-xml-20081126/#charsets
		// Char      ::=          #x9 | #xA | #xD | [#x20-#xD7FF]
		//             |          [#xE000-#xFFFD] | [#x10000-#x10FFFF]
		if i != '\t' && i != '\n' && i != '\r' {
			replace(i, "") // Elide
		}
	}
	// "&#34;" is shorter than "&quot;"
	replace('"', "&#34;") // Attribute delimiter.
	replace('&', "&amp;") // HTML special.
	// We don't use &apos; since that is not in the intersection of HTML&XML.
	replace('\'', "&#39;") // Attribute delimiter.
	replace('+', "&#43;")  // UTF-7 special.
	replace('<', "&lt;")   // HTML special.
	replace('=', "&#61;")  // Special in attributes.
	replace('>', "&gt;")   // HTML special.
	replace('@', "&#64;")  // Conditional compilation.
	replace('`', "&#96;")  // Attribute delimiter.
	replace(0x7f, "")      // DEL is a control; elide.

	for i := range encodingIsBannedASCII {
		encodingIsBannedASCII[i] = !(i == '\t' || i == '\n' || i == '\r')
	}

	for _, ch := range encodingRiskyNormalizationSingles {
		encodingRiskyNormalization[ch>>6] |= 1 << (ch & 63)
	}
	for _, r := range encodingRiskyNormalizationRanges {
		for ch := r[0]; ch <= r[1]; ch++ {
			encodingRiskyNormalization[ch>>6] |= 1 << (ch & 63)
		}
	}
}

// encodingIsPossiblyElidedCodeunit reports whether encodingStripBannedCodeunits
// may elide ch, so that the text on either side of it is joined up in the
// output.  A policy that reads text has to judge the text that will be
// emitted, not text that a later elision would join differently, so this
// answers true for a surrogate, which is elided when it is alone and may be
// when it is paired.
//
// ch is a code point as wtf8DecodeRune returns it.  A supplementary code
// point answers true, as do the surrogates that spell it.
func encodingIsPossiblyElidedCodeunit(ch rune) bool {
	if ch < 0x20 {
		return ch >= 0 && encodingIsBannedASCII[ch]
	}
	return (0x7f <= ch && ch <= 0x9f) ||
		(0xd800 <= ch && ch <= 0xdfff) ||
		ch > 0xffff ||
		encodingIsNoncharacter(ch)
}

// encodingRiskyNormalization has bit c set when the BMP character U+c has a
// compatibility decomposition (NFKD) that contains a printable,
// non-alphanumeric ASCII character, so that a downstream normalization could
// turn it into an HTML special character: U+FE64 SMALL LESS-THAN SIGN
// normalizes to '<'.
//
// The table is spelled out rather than derived from a Unicode database at
// start-up so that output does not vary with the Unicode version; the tests
// check it against recorded decompositions and say which characters to add
// if they drift.
var encodingRiskyNormalization [0x10000 / 64]uint64

// encodingRiskyNormalizationSingles are the single characters in
// encodingRiskyNormalization.
var encodingRiskyNormalizationSingles = [...]rune{
	'\u037e', '\u1fef', '\u203c', '\u207a', '\u208a', '\u2100', '\u2101',
	'\u2105', '\u2106', '\u2260', '\u226e', '\u226f', '\u33c2', '\u33c7',
	'\u33d8', '\ufb29', '\ufe10', '\ufe19', '\ufe30', '\ufe47', '\ufe48',
	'\ufe52',
}

// encodingRiskyNormalizationRanges are the inclusive ranges of characters in
// encodingRiskyNormalization.
var encodingRiskyNormalizationRanges = [...][2]rune{
	{'\u2024', '\u2026'}, {'\u2047', '\u2049'}, {'\u207c', '\u207e'},
	{'\u208c', '\u208e'}, {'\u2474', '\u24b5'}, {'\u2a74', '\u2a76'},
	{'\u3200', '\u321e'}, {'\u3220', '\u3243'}, {'\ufe13', '\ufe16'},
	{'\ufe33', '\ufe38'}, {'\ufe4d', '\ufe50'}, {'\ufe54', '\ufe57'},
	{'\ufe59', '\ufe5c'}, {'\ufe5f', '\ufe66'}, {'\ufe68', '\ufe6b'},
	{'\uff01', '\uff0f'}, {'\uff1a', '\uff20'}, {'\uff3b', '\uff40'},
	{'\uff5b', '\uff5e'},
}

// encodingIsRiskyNormalization reports whether a compatibility normalization
// of the BMP character ch could produce an ASCII punctuation character.
func encodingIsRiskyNormalization(ch rune) bool {
	return 0 <= ch && ch <= 0xffff &&
		encodingRiskyNormalization[ch>>6]&(1<<(ch&63)) != 0
}
