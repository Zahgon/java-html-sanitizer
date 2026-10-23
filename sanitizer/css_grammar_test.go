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
// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/CssGrammarTest.java.

package sanitizer

import (
	"slices"
	"strings"
	"testing"
)

func TestCSSGrammarLex(t *testing.T) {
	tokens := cssTokensLex(strings.Join([]string{
		"/* A comment */",
		"words with-dashes #hashes .dots. -and-leading-dashes",
		"quantities: 3px 4ex -.5pt 12.5%",
		"punctuation: { ( } / , ;",
		"[ url( http://example.com )",
		"rgb(255, 127, 127)",
		"'strings' \"oh \\\"my\" 'foo bar'",
		"color:blue!important",
		"",
	}, "\n"))

	var actualTokens []string
	for it := tokens.iterator(); it.hasNext(); {
		typ := it.tokenType()
		token := it.next()
		if token != " " {
			actualTokens = append(actualTokens, token+":"+typ.String())
		}
	}

	want := []string{
		// "/* A comment */",  // Comments are elided.
		"words:IDENT",
		"with-dashes:IDENT",
		"#hashes:HASH_ID",
		".dots:DOT_IDENT",
		".:DELIM",
		"-and-leading-dashes:IDENT",
		"quantities:IDENT",
		"::COLON",
		"3px:DIMENSION",
		"4ex:DIMENSION",
		"-0.5pt:DIMENSION",
		"12.5%:PERCENTAGE",
		"punctuation:IDENT",
		"::COLON",
		"{:LEFT_CURLY",
		"(:LEFT_PAREN",  // Explicit
		"):RIGHT_PAREN", // Implicit closing bracket to keep balance.
		"}:RIGHT_CURLY",
		"/:DELIM",
		",:COMMA",
		";:SEMICOLON",
		"[:LEFT_SQUARE",
		"url('http://example.com'):URL",
		"rgb(:FUNCTION",
		"255:NUMBER",
		",:COMMA",
		"127:NUMBER",
		",:COMMA",
		"127:NUMBER",
		"):RIGHT_PAREN",
		"'strings':STRING",
		"'oh \\22my':STRING",
		"'foo bar':STRING",
		"color:IDENT",
		"::COLON",
		"blue:IDENT",
		"!:DELIM",
		"important:IDENT",
		"]:RIGHT_SQUARE", // Manufactured due to unmatched '['.
	}
	if !slices.Equal(want, actualTokens) {
		t.Errorf("got  %q\nwant %q", actualTokens, want)
	}
}

func TestCSSGrammarCSSContent(t *testing.T) {
	for _, test := range []struct{ want, token string }{
		{"", ""},
		{"azimuth", "\\61zimuth"},
		{"table-cell", "t\\61\tble-cell"},
		{"foo", "foo"},
		{"foo", "'foo'"},
		{"foo", "\"foo\""},
		{"'", "'"},
		{"\"", "\""},
		{"\"\"", "\"\\22\\22\""},
		{"\"\"", "\"\\22 \\22\""},
		{"\"\"", "\\22\\22"},
		{"\\", "'\\\\'"},
		{"\n", "'\\a'"},
	} {
		if got := cssGrammarCSSContent(test.token); got != test.want {
			t.Errorf("cssGrammarCSSContent(%q) = %q, want %q", test.token, got, test.want)
		}
	}
}
