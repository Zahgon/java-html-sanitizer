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

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/Strings.java.

package sanitizer

// Locale independent case-insensitive string operations.
//
// Locale-aware case mapping folds the letters "i" and "I" differently under a
// Turkish locale than under an English one.
//
// These operations ignore all case folding for non-Roman letters, and are
// independent of the current locale.  Lower-casing is exactly equivalent to
// tr/A-Z/a-z/, and case insensitive comparison is equivalent to lower-casing
// both then comparing by code-unit.
//
// Offsets and lengths are in bytes.  Every character outside ASCII is encoded
// as bytes outside ASCII, which never fold, so comparing whole characters
// byte by byte gives the same result as comparing by UTF-16 code unit.

// stringsRegionMatchesIgnoreCase reports whether the n bytes of a starting at
// aoffset equal the n bytes of b starting at boffset, ignoring the case of
// ASCII letters.  It is false if either region runs past the end of its
// string.
func stringsRegionMatchesIgnoreCase(
	a string, aoffset int, b string, boffset int, n int,
) bool {
	if aoffset+n > len(a) || boffset+n > len(b) {
		return false
	}
	for i := n - 1; i >= 0; i-- {
		c, d := a[aoffset+i], b[boffset+i]
		if c != d {
			if c <= 'z' && c >= 'A' {
				if c <= 'Z' {
					c |= 0x20
				}
				if d <= 'Z' && d >= 'A' {
					d |= 0x20
				}
				if c == d {
					continue
				}
			}
			return false
		}
	}
	return true
}

// stringsToLowerCase lower-cases the ASCII letters in s and leaves every
// other character as it is.  It returns s itself when s has no upper-case
// ASCII letter.
func stringsToLowerCase(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c <= 'Z' && c >= 'A' {
			chars := []byte(s)
			chars[i] = c | 0x20
			for i--; i >= 0; i-- {
				if c = chars[i]; c <= 'Z' && c >= 'A' {
					chars[i] = c | 0x20
				}
			}
			return string(chars)
		}
	}
	return s
}

// stringsHTMLSpaceCharBitmask has bit c set for each HTML space character c.
const stringsHTMLSpaceCharBitmask uint64 = 1<<' ' |
	1<<'\t' |
	1<<'\n' |
	1<<'\f' |
	1<<'\r'

// stringsIsHTMLSpace reports whether ch is one of the five ASCII whitespace
// characters that HTML recognises: space, tab, line feed, form feed and
// carriage return.
func stringsIsHTMLSpace(ch rune) bool {
	return ch >= 0 && ch <= 0x20 && stringsHTMLSpaceCharBitmask&(1<<ch) != 0
}

// stringsContainsHTMLSpace reports whether s contains an HTML space
// character.
func stringsContainsHTMLSpace(s string) bool {
	for i := 0; i < len(s); i++ {
		if stringsIsHTMLSpace(rune(s[i])) {
			return true
		}
	}
	return false
}

// stringsStripHTMLSpaces removes HTML space characters from both ends of s.
func stringsStripHTMLSpaces(s string) string {
	i, n := 0, len(s)
	for ; n > i; n-- {
		if !stringsIsHTMLSpace(rune(s[n-1])) {
			break
		}
	}
	for ; i < n; i++ {
		if !stringsIsHTMLSpace(rune(s[i])) {
			break
		}
	}
	return s[i:n]
}

// stringsSkipValidFloatingPointNumber parses a valid floating point number
// per the HTML5 spec, starting at byte offset start of value.
// https://html.spec.whatwg.org/multipage/common-microsyntaxes.html#valid-floating-point-number
//
// It returns the end of the floating point number if valid or -1 if not.
func stringsSkipValidFloatingPointNumber(value string, start int) int {
	// A string is a valid floating-point number if it consists of:
	i := start
	n := len(value)

	if i >= n {
		return -1
	}

	// 1. Optionally, a U+002D HYPHEN-MINUS character (-).
	if value[i] == '-' {
		i++
	}
	// 2. One or both of the following, in the given order:
	hasMantissa := false
	//    1. A series of one or more ASCII digits.
	for i < n && '0' <= value[i] && value[i] <= '9' {
		i++
		hasMantissa = true
	}
	//    2. Both of the following, in the given order:
	//       1. A single U+002E FULL STOP character (.).
	//       2. A series of one or more ASCII digits.
	if i < n && value[i] == '.' {
		i++
		// Even if there's an integer, you need digits after the decimal
		// point.
		hasMantissa = false
		for i < n && '0' <= value[i] && value[i] <= '9' {
			i++
			hasMantissa = true
		}
	}
	if !hasMantissa {
		return -1
	}
	// 3. Optionally:
	//    1. Either a U+0065 LATIN SMALL LETTER E character (e)
	//       or a U+0045 LATIN CAPITAL LETTER E character (E).
	if i < n && value[i]|32 == 'e' {
		i++
		//    2. Optionally, a U+002D HYPHEN-MINUS character (-) or
		//       U+002B PLUS SIGN character (+).
		if i < n && (value[i] == '+' || value[i] == '-') {
			i++
		}
		//    3. A series of one or more ASCII digits.
		hasExponent := false
		for i < n && '0' <= value[i] && value[i] <= '9' {
			i++
			hasExponent = true
		}
		if !hasExponent {
			return -1
		}
	}
	return i
}
