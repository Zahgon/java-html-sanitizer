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

import "testing"

func TestStringHash(t *testing.T) {
	for _, tc := range []struct {
		s    string
		want int32
	}{
		{"", 0},
		{"a", 97},
		{"Aa", 2112},
		{"BB", 2112},
		{"hello", 99162322},
		{"The quick brown fox jumps over the lazy dog", -609428141},
		{"\u00e9", 0xe9},
		{"\U0001d49c", 31*0xd835 + 0xdc9c},
		{"\xed\xa0\xb5", 0xd835},
		// A pair spelled as two WTF-8 surrogates is still the pair.
		{"\xed\xa0\xb5\xed\xb2\x9c", 31*0xd835 + 0xdc9c},
		// An invalid byte reads as U+FFFD.
		{"\xff", 0xfffd},
	} {
		if got := stringHash(tc.s); got != tc.want {
			t.Errorf("stringHash(%q) = %d, want %d", tc.s, got, tc.want)
		}
	}
}

func TestUTF16LengthAndSubstring(t *testing.T) {
	s := "a\u00e9\U0001d49c\xed\xb0\x80z"
	if got, want := utf16Length(s), 6; got != want {
		t.Errorf("utf16Length = %d, want %d", got, want)
	}
	if got, want := utf16Substring(s, 1, 3), "\u00e9\xed\xa0\xb5"; got != want {
		t.Errorf("utf16Substring(1, 3) = %q, want %q", got, want)
	}
	if got, want := utf16Substring(s, 3, 6), "\xed\xb2\x9c\xed\xb0\x80z"; got != want {
		t.Errorf("utf16Substring(3, 6) = %q, want %q", got, want)
	}
	if got, want := fromUTF16Units(utf16Units(s)), s; got != want {
		t.Errorf("round trip = %q, want %q", got, want)
	}
}

func TestWTF8BuilderJoinsSurrogates(t *testing.T) {
	var sb wtf8Builder
	sb.appendCodePoint(0xd835)
	sb.appendCodePoint(0xdc9c)
	_, _ = sb.WriteString("\xed\xa0\xb5")
	_, _ = sb.WriteString("\xed\xb2\x9cx")
	sb.appendCodePoint(0xdc9c)
	if got, want := sb.String(), "\U0001d49c\U0001d49cx\xed\xb2\x9c"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
