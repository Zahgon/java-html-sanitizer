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

package sanitizer

import (
	"unicode/utf8"
)

// The sanitizer measures, slices and hashes text in UTF-16 code units,
// because lengths, truncation points and hash-table order observable in its
// output are defined in those units.
//
// Text is held as UTF-8, except that it may contain a lone surrogate code
// unit, for example one decoded from "&#xd800;".  Such a code unit is carried
// as its three-byte generalized UTF-8 (WTF-8) form, ED A0 80 through ED BF BF.
// A surrogate pair is always ordinary four-byte UTF-8.  The helpers below
// also accept a pair spelled as two WTF-8 surrogates and treat it as that
// pair.  A byte that is not part of any valid sequence reads as the single
// code unit U+FFFD.

// wtf8DecodeRune decodes the first character of s like
// utf8.DecodeRuneInString, but also decodes the WTF-8 form of a surrogate
// code unit, returning the surrogate itself.  An invalid byte decodes as
// (utf8.RuneError, 1), and an empty string as (utf8.RuneError, 0).
func wtf8DecodeRune(s string) (rune, int) {
	if len(s) >= 3 && s[0] == 0xed && s[1] >= 0xa0 && s[1] <= 0xbf &&
		s[2]&0xc0 == 0x80 {
		return 0xd000 | rune(s[1]&0x3f)<<6 | rune(s[2]&0x3f), 3
	}
	return utf8.DecodeRuneInString(s)
}

// wtf8AppendRune appends the UTF-8 encoding of r to b, or the WTF-8 encoding
// if r is a surrogate code unit.  It does not join a low surrogate to a high
// surrogate at the end of b; wtf8Builder does that.
func wtf8AppendRune(b []byte, r rune) []byte {
	if isSurrogate(r) {
		return append(b, 0xed, 0xa0|byte(r>>6&0x1f), 0x80|byte(r&0x3f))
	}
	return utf8.AppendRune(b, r)
}

// maxCodePoint is the largest Unicode code point.
const maxCodePoint = 0x10ffff

// isSurrogate reports whether r is a UTF-16 surrogate code unit.
func isSurrogate(r rune) bool { return 0xd800 <= r && r <= 0xdfff }

// isHighSurrogate reports whether r is a leading (high) surrogate.
func isHighSurrogate(r rune) bool { return 0xd800 <= r && r <= 0xdbff }

// isLowSurrogate reports whether r is a trailing (low) surrogate.
func isLowSurrogate(r rune) bool { return 0xdc00 <= r && r <= 0xdfff }

// combineSurrogates returns the supplementary code point that the surrogate
// pair high, low encodes.
func combineSurrogates(high, low rune) rune {
	return (high-0xd800)<<10 + (low - 0xdc00) + 0x10000
}

// forEachUTF16Unit calls f with each UTF-16 code unit of s, in order, and the
// byte offset in s of the character the code unit belongs to.  It stops early
// if f returns false.
func forEachUTF16Unit(s string, f func(unit uint16, byteOffset int) bool) {
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if !f(uint16(c), i) {
				return
			}
			i++
			continue
		}
		r, size := wtf8DecodeRune(s[i:])
		if r >= 0x10000 {
			r -= 0x10000
			if !f(uint16(0xd800+r>>10), i) || !f(uint16(0xdc00+r&0x3ff), i) {
				return
			}
		} else if !f(uint16(r), i) {
			return
		}
		i += size
	}
}

// utf16Units returns the UTF-16 code units of s.
func utf16Units(s string) []uint16 {
	units := make([]uint16, 0, len(s))
	forEachUTF16Unit(s, func(u uint16, _ int) bool {
		units = append(units, u)
		return true
	})
	return units
}

// fromUTF16Units converts UTF-16 code units to a Go string, joining surrogate
// pairs and keeping lone surrogates in their WTF-8 form.
func fromUTF16Units(units []uint16) string {
	b := make([]byte, 0, len(units))
	for i := 0; i < len(units); i++ {
		r := rune(units[i])
		if isHighSurrogate(r) && i+1 < len(units) &&
			isLowSurrogate(rune(units[i+1])) {
			r = combineSurrogates(r, rune(units[i+1]))
			i++
		}
		b = wtf8AppendRune(b, r)
	}
	return string(b)
}

// utf16Length returns the length of s in UTF-16 code units.
func utf16Length(s string) int {
	n := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			n++
			i++
			continue
		}
		r, size := wtf8DecodeRune(s[i:])
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
		i += size
	}
	return n
}

// utf16Substring returns the part of s from code unit begin up to, but not
// including, code unit end, counting in UTF-16 code units.  A surrogate pair cut in
// two leaves a lone surrogate.
func utf16Substring(s string, begin, end int) string {
	return fromUTF16Units(utf16Units(s)[begin:end])
}

// stringHash is the polynomial hash s[0]*31^(n-1) + ... + s[n-1] over the
// UTF-16 code units of s, wrapping at 32 bits.  hashOrderedMap places keys
// by it.
func stringHash(s string) int32 {
	var h int32
	forEachUTF16Unit(s, func(u uint16, _ int) bool {
		h = 31*h + int32(u)
		return true
	})
	return h
}

// wtf8Builder accumulates text in which a low surrogate appended right after
// a lone high surrogate joins it to form a pair, which the builder stores as
// four-byte UTF-8 rather than two WTF-8 sequences.
type wtf8Builder struct {
	buf []byte
}

// WriteString appends s.  It never fails.
func (b *wtf8Builder) WriteString(s string) (int, error) {
	n := len(s)
	if n >= 3 && s[0] == 0xed && b.endsWithHighSurrogate() {
		if low, _ := wtf8DecodeRune(s); isLowSurrogate(low) {
			high, _ := wtf8DecodeRune(string(b.buf[len(b.buf)-3:]))
			b.buf = utf8.AppendRune(
				b.buf[:len(b.buf)-3], combineSurrogates(high, low))
			s = s[3:]
		}
	}
	b.buf = append(b.buf, s...)
	return n, nil
}

// Write appends p.  It never fails.
func (b *wtf8Builder) Write(p []byte) (int, error) {
	return b.WriteString(string(p))
}

// WriteByte appends the single byte c, which should be ASCII.  It never
// fails.
func (b *wtf8Builder) WriteByte(c byte) error {
	b.buf = append(b.buf, c)
	return nil
}

// appendCodePoint appends any code point, including a surrogate code unit,
// which may complete a pair.
func (b *wtf8Builder) appendCodePoint(r rune) {
	if isLowSurrogate(r) {
		_, _ = b.WriteString(string(wtf8AppendRune(nil, r)))
		return
	}
	b.buf = wtf8AppendRune(b.buf, r)
}

// endsWithHighSurrogate reports whether the text ends in a lone high
// surrogate.
func (b *wtf8Builder) endsWithHighSurrogate() bool {
	n := len(b.buf)
	return n >= 3 && b.buf[n-3] == 0xed && b.buf[n-2] >= 0xa0 &&
		b.buf[n-2] <= 0xaf
}

// Len returns the length of the text in bytes.
func (b *wtf8Builder) Len() int { return len(b.buf) }

// String returns the accumulated text.
func (b *wtf8Builder) String() string { return string(b.buf) }
