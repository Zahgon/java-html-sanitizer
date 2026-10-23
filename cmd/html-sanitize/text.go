// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

package main

import (
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// The sanitizer carries a lone UTF-16 surrogate, which a decoded numeric
// character reference such as "&#xd800;" can produce, as its three-byte
// generalized UTF-8 form (ED A0 80 to ED BF BF).

// loneSurrogate reports the surrogate encoded at the start of s, if any.
func loneSurrogate(s string) (uint16, bool) {
	if len(s) >= 3 && s[0] == 0xed && s[1] >= 0xa0 && s[1] <= 0xbf && s[2]&0xc0 == 0x80 {
		return 0xd000 | uint16(s[1]&0x3f)<<6 | uint16(s[2]&0x3f), true
	}
	return 0, false
}

// utf16Units returns s as UTF-16 code units; bytes that are not UTF-8 count
// as U+FFFD.
func utf16Units(s string) []uint16 {
	units := make([]uint16, 0, len(s))
	for len(s) > 0 {
		if u, ok := loneSurrogate(s); ok {
			units = append(units, u)
			s = s[3:]
			continue
		}
		r, size := utf8.DecodeRuneInString(s)
		if r > 0xffff {
			hi, lo := utf16.EncodeRune(r)
			units = append(units, uint16(hi), uint16(lo))
		} else {
			units = append(units, uint16(r))
		}
		s = s[size:]
	}
	return units
}

// outputText returns s as it is written out in UTF-8: a lone surrogate
// becomes '?' and bytes that are not UTF-8 become U+FFFD.
func outputText(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for len(s) > 0 {
		if _, ok := loneSurrogate(s); ok {
			b.WriteByte('?')
			s = s[3:]
			continue
		}
		r, size := utf8.DecodeRuneInString(s)
		b.WriteRune(r)
		s = s[size:]
	}
	return b.String()
}
