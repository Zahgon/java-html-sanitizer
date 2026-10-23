// Copyright (c) 2013, Mike Samuel
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
// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/CssTokensTest.java.

package sanitizer

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// cssTokensTestLex lexes s and checks that lexing is idempotent.
func cssTokensTestLex(t *testing.T, s string) *cssTokens {
	t.Helper()
	tokens := cssTokensLex(s)
	if got := cssTokensLex(tokens.normalizedCSS).normalizedCSS; got != tokens.normalizedCSS {
		t.Errorf("`%s` not idempotent: %q != %q", s, tokens.normalizedCSS, got)
	}
	return tokens
}

// cssTokensTestTypeByName maps the upper-case names of token types to the
// types.
func cssTokensTestTypeByName(t *testing.T, name string) cssTokensTokenType {
	t.Helper()
	for i, n := range cssTokensTokenTypeNames {
		if n == name {
			return cssTokensTokenType(i)
		}
	}
	t.Fatalf("no token type %s", name)
	return 0
}

func cssTokensAssertTokens(t *testing.T, css string, goldens ...string) {
	t.Helper()
	var expected []string
	for _, golden := range goldens {
		if golden == " " {
			expected = append(expected, " :"+cssTokensTokenTypeWhitespace.String())
		} else {
			colon := strings.LastIndexByte(golden, ':')
			expected = append(expected,
				golden[:colon]+":"+cssTokensTestTypeByName(t, golden[colon+1:]).String())
		}
	}
	var actual []string
	for it := cssTokensTestLex(t, css).iterator(); it.hasNext(); it.advance() {
		actual = append(actual, it.token()+":"+it.tokenType().String())
	}
	if !slices.Equal(expected, actual) {
		t.Errorf("%s:\nwant %q\ngot  %q", css, expected, actual)
	}
}

func cssTokensAssertLexedCSS(t *testing.T, input string, goldens ...string) {
	t.Helper()
	var actual []string
	for it := cssTokensTestLex(t, input).iterator(); it.hasNext(); {
		actual = append(actual, it.next())
	}
	if !slices.Equal(goldens, actual) {
		t.Errorf("%s:\nwant %q\ngot  %q", input, goldens, actual)
	}
}

func TestCSSTokensBracketIndices(t *testing.T) {
	tokens := cssTokensTestLex(t, "([foo[[||]])")
	if got, want := tokens.normalizedCSS, "([foo[[||]]])"; got != want {
		t.Errorf("normalizedCSS = %q, want %q", got, want)
	}

	var tokenTexts []string
	var types []cssTokensTokenType
	var partners []int
	for it := tokens.iterator(); it.hasNext(); {
		types = append(types, it.tokenType())
		partners = append(partners, tokens.brackets.partner(it.tokenIndex()))
		tokenTexts = append(tokenTexts, it.next())
	}
	if want := []string{"(", "[", "foo", "[", "[", "||", "]", "]", "]", ")"}; !slices.Equal(want, tokenTexts) {
		t.Errorf("tokens = %q, want %q", tokenTexts, want)
	}
	if want := []cssTokensTokenType{
		cssTokensTokenTypeLeftParen, cssTokensTokenTypeLeftSquare,
		cssTokensTokenTypeIdent, cssTokensTokenTypeLeftSquare,
		cssTokensTokenTypeLeftSquare, cssTokensTokenTypeColumn,
		cssTokensTokenTypeRightSquare, cssTokensTokenTypeRightSquare,
		cssTokensTokenTypeRightSquare, cssTokensTokenTypeRightParen,
	}; !slices.Equal(want, types) {
		t.Errorf("types = %v, want %v", types, want)
	}
	// ([foo[[||]]])
	// 012  345 6789
	if want := []int{9, 8, -1, 7, 6, -1, 4, 3, 1, 0}; !slices.Equal(want, partners) {
		t.Errorf("partners = %v, want %v", partners, want)
	}
}

// cssTokensTestNoGolden marks an input that lexes to nothing.
const cssTokensTestNoGolden = "\x00<none>"

func TestCSSTokensStringEscaping(t *testing.T) {
	tests := []struct{ input, golden string }{
		{"''", "''"},
		{"\"\"", "''"},
		{"\"\\a\"", "'\\a'"},
		{"\"\\0d\\0a\"", "'\\d\\a'"},
		{"'\\000000d'", "'\\0 d'"}, // too many hex digits
		{"'\\1fffff'", "'\ufffd'"}, // exceeds max codepoint
		{"\"'\"", "'\\27'"},
		{"\"\\\"\"", "'\\22'"},
		{"'\\\\'", "'\\\\'"},
		{"'-->'", "'--\\3e'"},
		{"'</style>'", "'\\3c/style\\3e'"},
		{"\"<![CDATA[...]]>\"", "'\\3c![CDATA[...]]\\3e'"},
		{"\"&quot;/*\"", "'\\26quot;/*'"},
		{"\"\x00AB\"", "'\\0 AB'"},
		{"\"\x00 AB\"", "'\\0  AB'"},
		{"\"\x00\\000020AB\"", "'\\0  AB'"},
		{"\"\x00\\000009AB\"", "'\\0 \tAB'"},
		{"\"", cssTokensTestNoGolden},
		{"'", cssTokensTestNoGolden},
		{"\"\n", cssTokensTestNoGolden},
		{"\"\r", cssTokensTestNoGolden},
		{"'\f", cssTokensTestNoGolden},
		{"'\\22", cssTokensTestNoGolden},
		{"'foo\\\n", cssTokensTestNoGolden},
		{"'foo\\\r\n", cssTokensTestNoGolden},
		{"//\\a'foo'", cssTokensTestNoGolden},
		{"/*'foo\\2a/'//*/", cssTokensTestNoGolden},
	}
	for _, test := range tests {
		hasGolden := test.golden != cssTokensTestNoGolden
		tokens := cssTokensTestLex(t, test.input)
		want := test.golden
		if !hasGolden {
			want = ""
		}
		if tokens.normalizedCSS != want {
			t.Errorf("%q: normalizedCSS = %q, want %q", test.input, tokens.normalizedCSS, want)
		}
		it := tokens.iterator()
		if it.hasNext() != hasGolden {
			t.Errorf("%q: hasNext = %v", test.input, it.hasNext())
			continue
		}
		if hasGolden {
			if it.tokenType() != cssTokensTokenTypeString {
				t.Errorf("%q: type = %v", test.input, it.tokenType())
			}
			if got := it.next(); got != test.golden {
				t.Errorf("%q: token = %q", test.input, got)
			}
			if it.hasNext() {
				t.Errorf("%q: more tokens", test.input)
			}
		}
	}
}

func TestCSSTokensComments(t *testing.T) {
	if got, want := cssTokensTestLex(t,
		"//\na/*z*/b//z*/z\\az\nc/*z/**/d//*/\f/**/e/***/f/*//*/g/*z**z*/h",
	).normalizedCSS, "a b c d e f g h"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCSSTokensNonCommentSlash(t *testing.T) {
	if got, want := cssTokensTestLex(t, "foo/bar/").normalizedCSS, "foo/ bar/"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCSSTokensCdoCdc(t *testing.T) {
	for _, test := range []struct{ want, input string }{
		{"|| and are ignorable||", "||<!-- and --> are ignorable||"},
		{"< !-- and -- > are not ignorable", "<!-\\- and -\\-> are not ignorable"},
	} {
		if got := cssTokensTestLex(t, test.input).normalizedCSS; got != test.want {
			t.Errorf("%q: got %q, want %q", test.input, got, test.want)
		}
	}
}

func TestCSSTokensIdentReencoding(t *testing.T) {
	tests := []struct{ input, golden string }{
		{"\\", cssTokensTestNoGolden},
		{"a", "a"},
		{"\\61", "a"},
		{"\\061", "a"},
		{"\\0061", "a"},
		{"\\00061", "a"},
		{"\\000061", "a"},
		// First character is not an identifier part.
		{"\\0000061", "61:NUMBER"},
		{"\\61 b", "ab"},
		{"\\61\tb", "ab"},
		{"\\61\nb", "ab"},
		{"\\61\fb", "ab"},
		{"\\61\rb", "ab"},
		{"ab", "ab"},
		{"_ab", "_ab"},
		{"_42", "_42"},
		{"foo-bar", "foo-bar"},
		{"-foo-bar", "-foo-bar"},
		{"\\2d foo-bar", "-foo-bar"},
		{"-\\66oo-bar", "-foo-bar"},
		// \\5c66 is a single escape sequence, not \\5c66 -> \\66 -> f .
		{"\\5c66oo-bar", "\u5c66" + "oo-bar"},
		{"\\22foo-bar", "\u022f" + "oo-bar"},
		// \\5c is not a valid identifier
		{"\\5c", "5c:BAD_DIMENSION"},
		{"\\22oo-bar", "22oo-bar:BAD_DIMENSION"},
		{"\\27oo-bar", "27oo-bar:BAD_DIMENSION"},
		// \\34 encodes a digit so slash is dropped.
		{"\\34mm", "34mm:DIMENSION"},
		// Number ambiguity can arise when - is escaped.
		// We disallow such ambiguity even in the encoded output since it is
		// of little value, and a possible source of confusion.
		// In these cases, the \\ is just dropped.
		{"-42", "-42:NUMBER"},
		{"\\-42", "-42:NUMBER"},
	}
	for _, test := range tests {
		hasGolden := test.golden != cssTokensTestNoGolden
		golden := test.golden
		// Invalid escape sequences can lead to things that are not
		// identifiers once error recovery happens.
		typ := cssTokensTokenTypeIdent
		if hasGolden {
			// Unambiguous since : not allowed in identifier.
			if colon := strings.LastIndexByte(golden, ':'); colon >= 0 {
				typ = cssTokensTestTypeByName(t, golden[colon+1:])
				golden = golden[:colon]
			}
		} else {
			golden = ""
		}
		tokens := cssTokensTestLex(t, test.input)
		if tokens.normalizedCSS != golden {
			t.Errorf("%q: normalizedCSS = %q, want %q", test.input, tokens.normalizedCSS, golden)
		}
		it := tokens.iterator()
		if it.hasNext() != hasGolden {
			t.Errorf("%q: hasNext = %v", test.input, it.hasNext())
			continue
		}
		if hasGolden {
			if it.tokenType() != typ {
				t.Errorf("%q: type = %v, want %v", test.input, it.tokenType(), typ)
			}
			if got := it.next(); got != golden {
				t.Errorf("%q: token = %q", test.input, got)
			}
			if it.hasNext() {
				t.Errorf("%q: more tokens", test.input)
			}
		}
	}
	// More number ambiguity.
	cssTokensAssertTokens(t, "\\2d 42", "2d:BAD_DIMENSION", " ", "42:NUMBER")
	cssTokensAssertTokens(t, "\\2d\t42", "2d:BAD_DIMENSION", " ", "42:NUMBER")
	cssTokensAssertTokens(t, "\\2d\n42", "2d:BAD_DIMENSION", " ", "42:NUMBER")
}

func TestCSSTokensOrphanedCloseBrackets(t *testing.T) {
	for _, test := range []struct{ want, input string }{
		{"{foo bar}", "{foo]bar"},
		// A close with no open partner is dropped; one whose partner is
		// below other opens closes those first.
		{"((( )))", "(((]]]"},
		{"[()]", "[(])"},
		{"a(b c)d", "a(b]c)d"},
		{"rgb(1 2)", "rgb(1]2)"},
		{"foo bar", "foo)bar"},
		{"((()))", ")))((("},
		{"{[()]}", "{[(}])"},
		{"x y z", "x]y)z}"},
	} {
		if got := cssTokensTestLex(t, test.input).normalizedCSS; got != test.want {
			t.Errorf("%q: got %q, want %q", test.input, got, test.want)
		}
	}
}

// TestCSSTokensOrphanedCloseBracketsAreDroppedInLinearTime: dropping a close
// bracket with no open partner used to walk the whole stack of open
// brackets, so a run of unmatched closes after a run of opens took time
// quadratic in the input: 320 KB took twenty seconds.
func TestCSSTokensOrphanedCloseBracketsAreDroppedInLinearTime(t *testing.T) {
	n := 400000
	css := strings.Repeat("(", n) + strings.Repeat("]", n)
	start := time.Now()
	tokens := cssTokensLex(css)
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Errorf("took %v", elapsed)
	}
	if got, want := len(tokens.normalizedCSS), 2*n+1; got != want {
		t.Errorf("len = %d, want %d", got, want)
	}
}

func TestCSSTokensAtDirectives(t *testing.T) {
	cssTokensAssertTokens(t,
		"@import \"foo/bar\"; @ at, @34",
		"@import:AT", " ", "'foo/bar':STRING", ";:SEMICOLON",
		" ", "@:DELIM", " ", "at:IDENT", ",:COMMA", " ",
		"@:DELIM", " ", "34:NUMBER")
}

func TestCSSTokensHash(t *testing.T) {
	cssTokensAssertTokens(t,
		"#fff #foo #-moz-foo #abcd #abcdef #012f34 #888 #42foo # #",
		"#fff:HASH_UNRESTRICTED", " ",
		"#foo:HASH_ID", " ",
		"#-moz-foo:HASH_ID", " ",
		"#abcd:HASH_UNRESTRICTED", " ",
		"#abcdef:HASH_UNRESTRICTED", " ",
		"#012f34:HASH_UNRESTRICTED", " ",
		"#888:HASH_UNRESTRICTED", " ",
		"#42foo:HASH_ID", " ",
		"#:DELIM", " ", "#:DELIM")
}

func TestCSSTokensSignsAndDots(t *testing.T) {
	cssTokensAssertTokens(t,
		"- . + +1 + 1 (1 + 1)--> .5 -.5 +.5 ++.5 .foo -",
		"-:IDENT", " ", ".:DELIM", " ", "+:DELIM", " ", "1:NUMBER", " ",
		"+:DELIM", " ", "1:NUMBER", " ", "(:LEFT_PAREN", "1:NUMBER", " ",
		"+:DELIM", " ", "1:NUMBER", "):RIGHT_PAREN", " ", "0.5:NUMBER", " ",
		"-0.5:NUMBER", " ", "0.5:NUMBER", " ", "+:DELIM", " ", "0.5:NUMBER",
		" ", ".foo:DOT_IDENT", " ", "-:IDENT")
	// TODO: is a single "-" an IDENT or a DELIM?  "--"?  "---"?
}

func TestCSSTokensMultiCharPunctuation(t *testing.T) {
	cssTokensAssertTokens(t,
		"|| ~= === |= =^= $= *= = : % & ~",
		"||:COLUMN", " ", "~=:MATCH", " ", "=:DELIM", "=:DELIM", "=:DELIM", " ",
		"|=:MATCH", " ", "=:DELIM", "^=:MATCH", " ", "$=:MATCH", " ",
		"*=:MATCH", " ", "=:DELIM", " ", "::COLON", " ", "%:DELIM", " ",
		"&:DELIM", " ", "~:DELIM")
}

func TestCSSTokensNul(t *testing.T) {
	cssTokensAssertTokens(t, "\u0000")
	cssTokensAssertTokens(t, "\u0000x\u0000", "x:IDENT")
}

func TestCSSTokensNumbers(t *testing.T) {
	cssTokensAssertTokens(t,
		"0 -0 +0 0.0 -0.0 -.0 0e12 0e-12 0e+12",
		"0:NUMBER", " ",
		"0:NUMBER", " ",
		"0:NUMBER", " ",
		"0:NUMBER", " ",
		"0:NUMBER", " ",
		"0:NUMBER", " ",
		"0:NUMBER", " ",
		"0:NUMBER", " ",
		"0:NUMBER")
	cssTokensAssertTokens(t,
		"1 -1 +1 1.0 -1.0 -.1e1 10e-1 .1e+1",
		"1:NUMBER", " ",
		"-1:NUMBER", " ",
		"1:NUMBER", " ",
		"1:NUMBER", " ",
		"-1:NUMBER", " ",
		"-0.1e1:NUMBER", " ",
		"10e-1:NUMBER", " ",
		"0.1e1:NUMBER")
	cssTokensAssertTokens(t,
		".1 -.1 +.1 0.1 -0.100 -.1e0 10e-2% .01e+01 IN",
		"0.1:NUMBER", " ",
		"-0.1:NUMBER", " ",
		"0.1:NUMBER", " ",
		"0.1:NUMBER", " ",
		"-0.1:NUMBER", " ",
		"-0.1:NUMBER", " ",
		"10e-2%:PERCENTAGE", " ",
		"0.01e1in:DIMENSION")
	cssTokensAssertTokens(t, "01234.567890", "1234.56789:NUMBER")
}

func TestCSSTokensUrls(t *testing.T) {
	cssTokensAssertTokens(t,
		"url() url('..')url( \"foo\" ) URL( f\"/(bar'\\\\baz ) url('foo \\a b')"+
			"Url( \u0080\u1234\U00010402\\110000)",
		"url(''):URL", " ",
		"url('..'):URL",
		"url('foo'):URL", " ",
		"url('f%22/%28bar%27%5cbaz'):URL", " ",
		"url('foo%20%0ab'):URL",
		"url('%c2%80%e1%88%b4%f0%90%90%82%ef%bf%bd'):URL",
	)
}

func TestCSSTokensFunctions(t *testing.T) {
	cssTokensAssertTokens(t, "( rgb(0,0,0) rgba(0,50%,0,100%)",
		"(:LEFT_PAREN",
		" ",
		"rgb(:FUNCTION",
		"0:NUMBER",
		",:COMMA",
		"0:NUMBER",
		",:COMMA",
		"0:NUMBER",
		"):RIGHT_PAREN",
		" ",
		"rgba(:FUNCTION",
		"0:NUMBER",
		",:COMMA",
		"50%:PERCENTAGE",
		",:COMMA",
		"0:NUMBER",
		",:COMMA",
		"100%:PERCENTAGE",
		"):RIGHT_PAREN",
		"):RIGHT_PAREN")
}

func TestCSSTokensUnicodeRanges(t *testing.T) {
	cssTokensAssertTokens(t,
		"U+2028 U+000-49F U+2000-27FF U+2900-2BFF U+1D400-1D7FF"+
			" u+ff?? u+d8??-dc??",
		"U+2028:UNICODE_RANGE", " ",
		"U+000-49f:UNICODE_RANGE", " ",
		"U+2000-27ff:UNICODE_RANGE", " ",
		"U+2900-2bff:UNICODE_RANGE", " ",
		"U+1d400-1d7ff:UNICODE_RANGE", " ",
		"U+ff??:UNICODE_RANGE", " ",
		// Question-marked ranges cannot be dashed.
		"U+d8??:UNICODE_RANGE", " ",
		"-dc:IDENT",
		"?:DELIM", "?:DELIM")
	cssTokensAssertTokens(t,
		"U+?",
		"U:IDENT", "+:DELIM", " ", "?:DELIM")
	// TODO: invalid code-units in unicode ranges, and out of order values.
}

func TestCSSTokensUnicodeRangeWithDanglingDash(t *testing.T) {
	cssTokensAssertTokens(t,
		"U+a-x",
		"U+a:UNICODE_RANGE", " ", "-x:IDENT")
	cssTokensAssertTokens(t,
		"u+ABCDEF-x",
		"U+abcdef:UNICODE_RANGE", " ", "-x:IDENT")
	// A lone '-' has always lexed as a (bogus) identifier.
	cssTokensAssertTokens(t,
		"U+a-",
		"U+a:UNICODE_RANGE", " ", "-:IDENT")
	cssTokensAssertTokens(t,
		"U+a- *",
		"U+a:UNICODE_RANGE", " ", "-:IDENT", " ", "*:DELIM")
	cssTokensAssertTokens(t,
		"U+a-.5",
		"U+a:UNICODE_RANGE", " ", "-0.5:NUMBER")
	// The CDC token "-->" is ignorable, so "U+a-->*" is the range U+a
	// followed by the delimiter '*'.  This is the shape that issue #245 hit.
	cssTokensAssertTokens(t,
		"U+a-->*",
		"U+a:UNICODE_RANGE", " ", "*:DELIM")
	// A real range end is still consumed.
	cssTokensAssertTokens(t,
		"U+a-b-x",
		"U+a-b:UNICODE_RANGE", "-x:IDENT")
}

func TestCSSTokensTokenMerging(t *testing.T) {
	cssTokensAssertTokens(t,
		"/\\* */", "/:DELIM", " ", "*:DELIM", " ", "*:DELIM", "/:DELIM")
	cssTokensAssertTokens(t,
		"/\\/", "/:DELIM", " ", "/:DELIM")
	cssTokensAssertTokens(t,
		"url\\('evil:magic()') uRl\\('.')",
		// url is not an allowable identifier.
		"(:LEFT_PAREN", "'evil:magic()':STRING", "):RIGHT_PAREN", " ",
		"(:LEFT_PAREN", "'.':STRING", "):RIGHT_PAREN")
	cssTokensAssertTokens(t,
		"foo\\(1,2)",
		"foo:IDENT",
		" ",
		// TODO: Should we be more aggressive with functions than just making
		// sure there is a space between the name and a parenthesis?
		"(:LEFT_PAREN", "1:NUMBER", ",:COMMA", "2:NUMBER",
		"):RIGHT_PAREN")
}

func TestCSSTokensLex01(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"body {\n"+
			"	color:green;\n"+
			"}\r\n"+
			"\n"+
			"div#foo { content:\"bar{foo}\"; }",
		"body", " ", "{", " ",
		"color", ":", "green", ";", " ",
		"}", " ",
		"div", "#foo", " ", "{", " ", "content", ":", "'bar{foo}'", ";", " ", "}")
}

func TestCSSTokensLex02(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"body div {\n"+
			"\tcolor:red;\n"+
			"}\n",
		"body", " ", "div", " ", "{", " ",
		"color", ":", "red", ";", " ",
		"}")
}

func TestCSSTokensLex03(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"div#foo { background:url(img/blubb.png) top left repeat-y; }\n"+
			"\n"+
			"body { font-family:Verdana, Geneva, Arial, Helvetica, sans-serif; font-size:12px; }\n"+
			"\n"+
			"@import url(\"foo.css\");\n"+
			"\n"+
			"@import \"bar.css\" screen;",
		"div", "#foo", " ", "{",
		" ", "background", ":", "url('img/blubb.png')",
		" ", "top", " ", "left", " ", "repeat-y", ";", " ", "}", " ",
		"body", " ", "{", " ", "font-family", ":", "Verdana", ",",
		" ", "Geneva", ",", " ", "Arial", ",", " ", "Helvetica", ",",
		" ", "sans-serif", ";",
		" ", "font-size", ":", "12px", ";", " ", "}", " ",
		"@import", " ", "url('foo.css')", ";", " ",
		"@import", " ", "'bar.css'", " ", "screen", ";")
}

func TestCSSTokensLex04(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"\n"+
			"\n"+
			"/* Komentar! */\n"+
			"@media projection {\n"+
			"\t#blubb {\n"+
			"\t\tfont-weight: /* Komentar! */ bold;\n"+
			"\t\tcontent:';{!\"\"())!\"';\n"+
			"\t}\n"+
			"}\n"+
			"#gnnf{\n"+
			"\tbackground:green url('img/beispiel.png') top left no-repeat;\n"+
			"\ttext-align:left\n"+
			"}",
		"@media", " ", "projection", " ", "{", " ",
		"#blubb", " ", "{", " ",
		"font-weight", ":", " ", "bold", ";", " ",
		"content", ":", "';{!\\22\\22())!\\22'", ";", " ",
		"}", " ",
		"}", " ",
		"#gnnf", "{", " ",
		"background", ":", "green", " ", "url('img/beispiel.png')",
		" ", "top", " ", "left", " ", "no-repeat", ";", " ",
		"text-align", ":", "left", " ",
		"}")
}

func TestCSSTokensLex05(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"/**\n"+
			" * FETTER Komentar!\n"+
			" * \n"+
			" * Bla bla bla\n"+
			" */\n"+
			"@media screen {\n"+
			"\t#test[foo] {\n"+
			"\t\tcolor:red !important;\n"+
			"\t}\n"+
			"\t#test[foo] {\n"+
			"\t\tcolor:blue;\n"+
			"\t}\n"+
			"}",
		"@media", " ", "screen", " ", "{", " ",
		"#test", "[", "foo", "]", " ", "{", " ",
		"color", ":", "red", " ", "!", "important", ";", " ",
		"}", " ",
		"#test", "[", "foo", "]", " ", "{", " ",
		"color", ":", "blue", ";", " ",
		"}", " ",
		"}")
}

func TestCSSTokensLex06(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"#blah[rel=\"/{_-;!\"] div > #blargh span.narf {\n"+
			"\tbackground:green;\n"+
			"\ttext-align:left;\n"+
			"}",
		"#blah", "[", "rel", "=", "'/{_-;!'", "]", " ", "div",
		" ", ">", " ", "#blargh", " ", "span", ".narf", " ", "{", " ",
		"background", ":", "green", ";", " ",
		"text-align", ":", "left", ";", " ",
		"}")
}

func TestCSSTokensLex07(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"/* Komentar! */\n"+
			"@media print {\n"+
			"\t#gnarf {\n"+
			"\t\tfont-weight:normal;\n"+
			"\t\tfont-size:2em\n"+
			"\t}\n"+
			"}",
		"@media", " ", "print", " ", "{", " ",
		"#gnarf", " ", "{", " ",
		"font-weight", ":", "normal", ";", " ",
		"font-size", ":", "2em", " ",
		"}", " ",
		"}")
}

func TestCSSTokensLex08(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"#foobar {\n"+
			"\tfont-family:\"Trebuchet MS\", Verdana, Arial, sans-serif;\n"+
			"}",
		"#foobar", " ", "{", " ",
		"font-family", ":", "'Trebuchet MS'", ",", " ", "Verdana", ",",
		" ", "Arial", ",", " ", "sans-serif", ";", " ",
		"}")
}

func TestCSSTokensLex09(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"p { color:red !important; }\n"+
			".foo { color:green; }",
		"p", " ", "{", " ", "color", ":", "red", " ", "!", "important", ";",
		" ", "}", " ",
		".foo", " ", "{", " ", "color", ":", "green", ";", " ", "}")
}

func TestCSSTokensLex10(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"@media screen{\n"+
			"\t#wrapper {\n"+
			"\t\tcolor:blue;\n"+
			"\t\tfont-weight:bold !important;\n"+
			"\t\ttext-decoration:underline;\n"+
			"\t}\n"+
			"\t#wrapper {\n"+
			"\t\tcolor:red;\n"+
			"\t\tfont-weight:normal;\n"+
			"\t\tfont-style:italic;\n"+
			"\t}\n"+
			"}\n"+
			"\n"+
			"@media print {\n"+
			"\t#wrapper {\n"+
			"\t\tcolor:green;\n"+
			"\t}\n"+
			"}",
		"@media", " ", "screen", "{", " ",
		"#wrapper", " ", "{", " ",
		"color", ":", "blue", ";", " ",
		"font-weight", ":", "bold", " ", "!", "important", ";", " ",
		"text-decoration", ":", "underline", ";", " ",
		"}", " ",
		"#wrapper", " ", "{", " ",
		"color", ":", "red", ";", " ",
		"font-weight", ":", "normal", ";", " ",
		"font-style", ":", "italic", ";", " ",
		"}", " ",
		"}", " ",
		"@media", " ", "print", " ", "{", " ",
		"#wrapper", " ", "{", " ",
		"color", ":", "green", ";", " ",
		"}", " ",
		"}")
}

func TestCSSTokensLex11(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"\n"+
			"ADDRESS,\n"+
			"BLOCKQUOTE, \n"+
			"BODY, DD, DIV, \n"+
			"DL, DT, \n"+
			"FIELDSET, FORM,\n"+
			"FRAME, FRAMESET,\n"+
			"H1, H2, H3, H4, \n"+
			"H5, H6, IFRAME, \n"+
			"NOFRAMES, \n"+
			"OBJECT, OL, P, \n"+
			"UL, APPLET, \n"+
			"CENTER, DIR, \n"+
			"HR, MENU, PRE   { display: block }\n"+
			"LI              { display: list-item }\n"+
			"HEAD            { display: none }\n"+
			"TABLE           { display: table }\n"+
			"TR              { display: table-row }\n"+
			"THEAD           { display: table-header-group }\n"+
			"TBODY           { display: table-row-group }\n"+
			"TFOOT           { display: table-footer-group }\n"+
			"COL             { display: table-column }\n"+
			"COLGROUP        { display: table-column-group }\n"+
			"TD, TH          { display: table-cell }\n"+
			"CAPTION         { display: table-caption }\n"+
			"TH              { font-weight: bolder; text-align: center }\n"+
			"CAPTION         { text-align: center }\n"+
			"BODY            { padding: 8px; line-height: 1.33 }\n"+
			"H1              { font-size: 2em; margin: .67em 0 }\n"+
			"H2              { font-size: 1.5em; margin: .83em 0 }\n"+
			"H3              { font-size: 1.17em; margin: 1em 0 }\n"+
			"H4, P,\n"+
			"BLOCKQUOTE, UL,\n"+
			"FIELDSET, FORM,\n"+
			"OL, DL, DIR,\n"+
			"MENU            { margin: 1.33em 0 }\n"+
			"H5              { font-size: .83em; line-height: 1.17em; margin: 1.67em 0 }\n"+
			"H6              { font-size: .67em; margin: 2.33em 0 }\n"+
			"H1, H2, H3, H4,\n"+
			"H5, H6, B,\n"+
			"STRONG          { font-weight: bolder }\n"+
			"BLOCKQUOTE      { margin-left: 40px; margin-right: 40px }\n"+
			"I, CITE, EM,\n"+
			"VAR, ADDRESS    { font-style: italic }\n"+
			"PRE, TT, CODE,\n"+
			"KBD, SAMP       { font-family: monospace }\n"+
			"PRE             { white-space: pre }\n"+
			"BIG             { font-size: 1.17em }\n"+
			"SMALL, SUB, SUP { font-size: .83em }\n"+
			"SUB             { vertical-align: sub }\n"+
			"SUP             { vertical-align: super }\n"+
			"S, STRIKE, DEL  { text-decoration: line-through }\n"+
			"HR              { border: 1px inset }\n"+
			"OL, UL, DIR,\n"+
			"MENU, DD        { margin-left: 40px }\n"+
			"OL              { list-style-type: decimal }\n"+
			"OL UL, UL OL,\n"+
			"UL UL, OL OL    { margin-top: 0; margin-bottom: 0 }\n"+
			"U, INS          { text-decoration: underline }\n"+
			"CENTER          { text-align: center }\n"+
			"BR:before       { content: \"\\A\" }\n"+
			"COLOR_NOHASH\t{ color:987E81 }",
		"ADDRESS", ",", " ",
		"BLOCKQUOTE", ",", " ",
		"BODY", ",", " ", "DD", ",", " ", "DIV", ",", " ",
		"DL", ",", " ", "DT", ",", " ",
		"FIELDSET", ",", " ", "FORM", ",", " ",
		"FRAME", ",", " ", "FRAMESET", ",", " ",
		"H1", ",", " ", "H2", ",", " ", "H3", ",", " ", "H4", ",", " ",
		"H5", ",", " ", "H6", ",", " ", "IFRAME", ",", " ",
		"NOFRAMES", ",", " ",
		"OBJECT", ",", " ", "OL", ",", " ", "P", ",", " ",
		"UL", ",", " ", "APPLET", ",", " ",
		"CENTER", ",", " ", "DIR", ",", " ",
		"HR", ",", " ", "MENU", ",", " ", "PRE", " ", "{",
		" ", "display", ":", " ", "block", " ", "}", " ",
		"LI", " ", "{", " ", "display", ":", " ", "list-item", " ", "}", " ",
		"HEAD", " ", "{", " ", "display", ":", " ", "none", " ", "}", " ",
		"TABLE", " ", "{", " ", "display", ":", " ", "table", " ", "}", " ",
		"TR", " ", "{", " ", "display", ":", " ", "table-row", " ", "}", " ",
		"THEAD", " ", "{",
		" ", "display", ":", " ", "table-header-group", " ", "}", " ",
		"TBODY", " ", "{",
		" ", "display", ":", " ", "table-row-group", " ", "}", " ",
		"TFOOT", " ", "{",
		" ", "display", ":", " ", "table-footer-group", " ", "}", " ",
		"COL", " ", "{", " ", "display", ":", " ", "table-column", " ", "}", " ",
		"COLGROUP", " ", "{",
		" ", "display", ":", " ", "table-column-group", " ", "}", " ",
		"TD", ",", " ", "TH", " ", "{",
		" ", "display", ":", " ", "table-cell", " ", "}", " ",
		"CAPTION", " ", "{",
		" ", "display", ":", " ", "table-caption", " ", "}", " ",
		"TH", " ", "{",
		" ", "font-weight", ":", " ", "bolder", ";",
		" ", "text-align", ":", " ", "center", " ", "}", " ",
		"CAPTION", " ", "{",
		" ", "text-align", ":", " ", "center", " ", "}", " ",
		"BODY", " ", "{",
		" ", "padding", ":", " ", "8px", ";",
		" ", "line-height", ":", " ", "1.33", " ", "}", " ",
		"H1", " ", "{",
		" ", "font-size", ":", " ", "2em", ";",
		" ", "margin", ":", " ", "0.67em", " ", "0", " ", "}", " ",
		"H2", " ", "{",
		" ", "font-size", ":", " ", "1.5em", ";",
		" ", "margin", ":", " ", "0.83em", " ", "0", " ", "}", " ",
		"H3", " ", "{",
		" ", "font-size", ":", " ", "1.17em", ";",
		" ", "margin", ":", " ", "1em", " ", "0", " ", "}", " ",
		"H4", ",", " ", "P", ",", " ",
		"BLOCKQUOTE", ",", " ", "UL", ",", " ",
		"FIELDSET", ",", " ", "FORM", ",", " ",
		"OL", ",", " ", "DL", ",", " ", "DIR", ",", " ",
		"MENU", " ", "{", " ", "margin", ":", " ", "1.33em", " ", "0", " ", "}", " ",
		"H5", " ", "{", " ", "font-size", ":", " ", "0.83em", ";",
		" ", "line-height", ":", " ", "1.17em", ";",
		" ", "margin", ":", " ", "1.67em", " ", "0", " ", "}", " ",
		"H6", " ", "{", " ", "font-size", ":", " ", "0.67em", ";",
		" ", "margin", ":", " ", "2.33em", " ", "0", " ", "}", " ",
		"H1", ",", " ", "H2", ",", " ", "H3", ",", " ", "H4", ",", " ",
		"H5", ",", " ", "H6", ",", " ", "B", ",", " ",
		"STRONG", " ", "{", " ", "font-weight", ":", " ", "bolder", " ", "}", " ",
		"BLOCKQUOTE", " ", "{", " ", "margin-left", ":", " ", "40px", ";",
		" ", "margin-right", ":", " ", "40px", " ", "}", " ",
		"I", ",", " ", "CITE", ",", " ", "EM", ",", " ",
		"VAR", ",", " ", "ADDRESS", " ", "{",
		" ", "font-style", ":", " ", "italic", " ", "}", " ",
		"PRE", ",", " ", "TT", ",", " ", "CODE", ",", " ",
		"KBD", ",", " ", "SAMP", " ", "{",
		" ", "font-family", ":", " ", "monospace", " ", "}", " ",
		"PRE", " ", "{", " ", "white-space", ":", " ", "pre", " ", "}", " ",
		"BIG", " ", "{", " ", "font-size", ":", " ", "1.17em", " ", "}", " ",
		"SMALL", ",", " ", "SUB", ",", " ", "SUP", " ", "{", " ", "font-size",
		":", " ", "0.83em", " ", "}", " ",
		"SUB", " ", "{", " ", "vertical-align", ":", " ", "sub", " ", "}", " ",
		"SUP", " ", "{", " ", "vertical-align", ":", " ", "super", " ", "}", " ",
		"S", ",", " ", "STRIKE", ",", " ", "DEL", " ", "{",
		" ", "text-decoration", ":", " ", "line-through", " ", "}", " ",
		"HR", " ", "{", " ", "border", ":", " ", "1px", " ", "inset", " ", "}", " ",
		"OL", ",", " ", "UL", ",", " ", "DIR", ",", " ",
		"MENU", ",", " ", "DD", " ", "{",
		" ", "margin-left", ":", " ", "40px", " ", "}", " ",
		"OL", " ", "{", " ", "list-style-type", ":", " ", "decimal", " ", "}", " ",
		"OL", " ", "UL", ",", " ", "UL", " ", "OL", ",", " ",
		"UL", " ", "UL", ",", " ", "OL", " ", "OL", " ", "{",
		" ", "margin-top", ":", " ", "0", ";",
		" ", "margin-bottom", ":", " ", "0", " ", "}", " ",
		"U", ",", " ", "INS", " ", "{",
		" ", "text-decoration", ":", " ", "underline", " ", "}", " ",
		"CENTER", " ", "{", " ", "text-align", ":", " ", "center", " ", "}", " ",
		"BR", ":", "before", " ", "{",
		" ", "content", ":", " ", "'\\a'", " ", "}", " ",
		"COLOR_NOHASH", " ", "{", " ", "color", ":", "987e81", " ", "}")
}

func TestCSSTokensLex12(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"/* An example of style for HTML 4.0's ABBR/ACRONYM elements */\n"+
			"\n"+
			"ABBR, ACRONYM   { font-variant: small-caps; letter-spacing: 0.1em }\n"+
			"A[href]         { text-decoration: underline }\n"+
			":focus          { outline: thin dotted invert }",
		"ABBR", ",", " ", "ACRONYM", " ", "{",
		" ", "font-variant", ":", " ", "small-caps", ";",
		" ", "letter-spacing", ":", " ", "0.1em", " ", "}", " ",
		"A", "[", "href", "]", " ", "{",
		" ", "text-decoration", ":", " ", "underline", " ", "}", " ",
		":", "focus", " ", "{",
		" ", "outline", ":", " ", "thin", " ", "dotted", " ", "invert", " ", "}")
}

func TestCSSTokensLex13(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"/* Begin bidirectionality settings (do not change) */\n"+
			"BDO[DIR=\"ltr\"]  { direction: ltr; unicode-bidi: bidi-override }\n"+
			"BDO[DIR=\"rtl\"]  { direction: rtl; unicode-bidi: bidi-override }\n"+
			"\n"+
			"*[DIR=\"ltr\"]    { direction: ltr; unicode-bidi: embed }\n"+
			"*[DIR=\"rtl\"]    { direction: rtl; unicode-bidi: embed }\n"+
			"\n"+
			"/* Elements that are block-level in HTML4 */\n"+
			"ADDRESS, BLOCKQUOTE, BODY, DD, DIV, DL, DT, FIELDSET, \n"+
			"FORM, FRAME, FRAMESET, H1, H2, H3, H4, H5, H6, IFRAME,\n"+
			"NOSCRIPT, NOFRAMES, OBJECT, OL, P, UL, APPLET, CENTER, \n"+
			"DIR, HR, MENU, PRE, LI, TABLE, TR, THEAD, TBODY, TFOOT, \n"+
			"COL, COLGROUP, TD, TH, CAPTION \n"+
			"                { unicode-bidi: embed }\n"+
			"/* End bidi settings */",
		"BDO", "[", "DIR", "=", "'ltr'", "]", " ", "{",
		" ", "direction", ":", " ", "ltr", ";",
		" ", "unicode-bidi", ":", " ", "bidi-override", " ", "}", " ",
		"BDO", "[", "DIR", "=", "'rtl'", "]", " ", "{",
		" ", "direction", ":", " ", "rtl", ";",
		" ", "unicode-bidi", ":", " ", "bidi-override", " ", "}", " ",
		"*", "[", "DIR", "=", "'ltr'", "]", " ", "{",
		" ", "direction", ":", " ", "ltr", ";",
		" ", "unicode-bidi", ":", " ", "embed", " ", "}", " ",
		"*", "[", "DIR", "=", "'rtl'", "]", " ", "{",
		" ", "direction", ":", " ", "rtl", ";",
		" ", "unicode-bidi", ":", " ", "embed", " ", "}", " ",
		"ADDRESS", ",", " ", "BLOCKQUOTE", ",", " ", "BODY", ",",
		" ", "DD", ",", " ", "DIV", ",", " ", "DL", ",", " ", "DT", ",",
		" ", "FIELDSET", ",", " ",
		"FORM", ",", " ", "FRAME", ",", " ", "FRAMESET", ",", " ", "H1", ",",
		" ", "H2", ",", " ", "H3", ",", " ", "H4", ",", " ", "H5", ",",
		" ", "H6", ",", " ", "IFRAME", ",", " ",
		"NOSCRIPT", ",", " ", "NOFRAMES", ",", " ", "OBJECT", ",",
		" ", "OL", ",", " ", "P", ",", " ", "UL", ",", " ", "APPLET", ",",
		" ", "CENTER", ",", " ",
		"DIR", ",", " ", "HR", ",", " ", "MENU", ",", " ", "PRE", ",",
		" ", "LI", ",", " ", "TABLE", ",", " ", "TR", ",", " ", "THEAD", ",",
		" ", "TBODY", ",", " ", "TFOOT", ",", " ",
		"COL", ",", " ", "COLGROUP", ",", " ", "TD", ",", " ", "TH", ",",
		" ", "CAPTION", " ",
		"{", " ", "unicode-bidi", ":", " ", "embed", " ", "}")
}

func TestCSSTokensLex14(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"\n"+
			"@media print {\n"+
			"  /* @page         { margin: 10% }  */ /* not allowed according to spec */\n"+
			"  H1, H2, H3,\n"+
			"  H4, H5, H6    { page-break-after: avoid; page-break-inside: avoid }\n"+
			"  BLOCKQUOTE, \n"+
			"  PRE           { page-break-inside: avoid }\n"+
			"  UL, OL, DL    { page-break-before: avoid }\n"+
			"}",
		"@media", " ", "print", " ", "{", " ",
		"H1", ",", " ", "H2", ",", " ", "H3", ",", " ",
		"H4", ",", " ", "H5", ",", " ", "H6", " ", "{",
		" ", "page-break-after", ":", " ", "avoid", ";",
		" ", "page-break-inside", ":", " ", "avoid", " ", "}", " ",
		"BLOCKQUOTE", ",", " ",
		"PRE", " ", "{", " ", "page-break-inside", ":", " ", "avoid", " ", "}", " ",
		"UL", ",", " ", "OL", ",", " ", "DL", " ", "{",
		" ", "page-break-before", ":", " ", "avoid", " ", "}", " ",
		"}")
}

func TestCSSTokensLex15(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"@media speech {\n"+
			"  H1, H2, H3, \n"+
			"  H4, H5, H6    { voice-family: paul, male; stress: 20; richness: 90 }\n"+
			"  H1            { pitch: x-low; pitch-range: 90 }\n"+
			"  H2            { pitch: x-low; pitch-range: 80 }\n"+
			"  H3            { pitch: low; pitch-range: 70 }\n"+
			"  H4            { pitch: medium; pitch-range: 60 }\n"+
			"  H5            { pitch: medium; pitch-range: 50 }\n"+
			"  H6            { pitch: medium; pitch-range: 40 }\n"+
			"  LI, DT, DD    { pitch: medium; richness: 60 }\n"+
			"  DT            { stress: 80 }\n"+
			"  PRE, CODE, TT { pitch: medium; pitch-range: 0; stress: 0; richness: 80 }\n"+
			"  EM            { pitch: medium; pitch-range: 60; stress: 60; richness: 50 }\n"+
			"  STRONG        { pitch: medium; pitch-range: 60; stress: 90; richness: 90 }\n"+
			"  DFN           { pitch: high; pitch-range: 60; stress: 60 }\n"+
			"  S, STRIKE     { richness: 0 }\n"+
			"  I             { pitch: medium; pitch-range: 60; stress: 60; richness: 50 }\n"+
			"  B             { pitch: medium; pitch-range: 60; stress: 90; richness: 90 }\n"+
			"  U             { richness: 0 }\n"+
			"  A:link        { voice-family: harry, male }\n"+
			"  A:visited     { voice-family: betty, female }\n"+
			"  A:active      { voice-family: betty, female; pitch-range: 80; pitch: x-high }\n"+
			"}",
		"@media", " ", "speech", " ", "{", " ",
		"H1", ",", " ", "H2", ",", " ", "H3", ",", " ",
		"H4", ",", " ", "H5", ",", " ", "H6",
		" ", "{", " ", "voice-family", ":", " ", "paul", ",", " ", "male", ";",
		" ", "stress", ":", " ", "20", ";", " ", "richness", ":", " ", "90",
		" ", "}", " ",
		"H1", " ", "{", " ", "pitch", ":", " ", "x-low", ";",
		" ", "pitch-range", ":", " ", "90", " ", "}", " ",
		"H2", " ", "{", " ", "pitch", ":", " ", "x-low", ";",
		" ", "pitch-range", ":", " ", "80", " ", "}", " ",
		"H3", " ", "{", " ", "pitch", ":", " ", "low", ";",
		" ", "pitch-range", ":", " ", "70", " ", "}", " ",
		"H4", " ", "{", " ", "pitch", ":", " ", "medium", ";",
		" ", "pitch-range", ":", " ", "60", " ", "}", " ",
		"H5", " ", "{", " ", "pitch", ":", " ", "medium", ";",
		" ", "pitch-range", ":", " ", "50", " ", "}", " ",
		"H6", " ", "{", " ", "pitch", ":", " ", "medium", ";",
		" ", "pitch-range", ":", " ", "40", " ", "}", " ",
		"LI", ",", " ", "DT", ",", " ", "DD", " ", "{",
		" ", "pitch", ":", " ", "medium", ";",
		" ", "richness", ":", " ", "60", " ", "}", " ",
		"DT", " ", "{", " ", "stress", ":", " ", "80", " ", "}", " ",
		"PRE", ",", " ", "CODE", ",", " ", "TT", " ", "{",
		" ", "pitch", ":", " ", "medium", ";",
		" ", "pitch-range", ":", " ", "0", ";",
		" ", "stress", ":", " ", "0", ";",
		" ", "richness", ":", " ", "80", " ", "}", " ",
		"EM", " ", "{", " ", "pitch", ":", " ", "medium", ";",
		" ", "pitch-range", ":", " ", "60", ";",
		" ", "stress", ":", " ", "60", ";",
		" ", "richness", ":", " ", "50", " ", "}", " ",
		"STRONG", " ", "{", " ", "pitch", ":", " ", "medium", ";",
		" ", "pitch-range", ":", " ", "60", ";",
		" ", "stress", ":", " ", "90", ";",
		" ", "richness", ":", " ", "90", " ", "}", " ",
		"DFN", " ", "{", " ", "pitch", ":", " ", "high", ";",
		" ", "pitch-range", ":", " ", "60", ";", " ",
		"stress", ":", " ", "60", " ", "}", " ",
		"S", ",", " ", "STRIKE", " ", "{",
		" ", "richness", ":", " ", "0", " ", "}", " ",
		"I", " ", "{", " ", "pitch", ":", " ", "medium", ";",
		" ", "pitch-range", ":", " ", "60", ";",
		" ", "stress", ":", " ", "60", ";",
		" ", "richness", ":", " ", "50", " ", "}", " ",
		"B", " ", "{", " ", "pitch", ":", " ", "medium", ";",
		" ", "pitch-range", ":", " ", "60", ";",
		" ", "stress", ":", " ", "90", ";",
		" ", "richness", ":", " ", "90", " ", "}", " ",
		"U", " ", "{", " ", "richness", ":", " ", "0", " ", "}", " ",
		"A", ":", "link", " ", "{",
		" ", "voice-family", ":", " ", "harry", ",", " ", "male", " ", "}", " ",
		"A", ":", "visited", " ", "{",
		" ", "voice-family", ":", " ", "betty", ",", " ", "female", " ", "}", " ",
		"A", ":", "active", " ", "{",
		" ", "voice-family", ":", " ", "betty", ",", " ", "female", ";",
		" ", "pitch-range", ":", " ", "80", ";",
		" ", "pitch", ":", " ", "x-high", " ", "}", " ",
		"}")
}

func TestCSSTokensLex16(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"FOO > BAR + BAZ {  }",
		"FOO", " ", ">", " ", "BAR", " ", "+", " ", "BAZ", " ", "{", " ", "}")
}

func TestCSSTokensLex17(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"A[href] BOO[zwop |= \"hello\"]:blinky {\n"+
			"  color: #fff;\n"+
			"  background: +#000000 ! important\n"+
			"}",
		"A", "[", "href", "]",
		" ", "BOO", "[", "zwop", " ", "|=", " ", "'hello'", "]", ":", "blinky",
		" ", "{", " ",
		"color", ":", " ", "#fff", ";", " ",
		"background", ":", " ", "+", " ", "#000000", " ", "!", " ", "important",
		" ",
		"}")
}

func TestCSSTokensLex18(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		".myclass[attr ~= almost] #id:hover(languidly) {\n"+
			"  font-weight: super(bold / italic)\n"+
			"}",
		".myclass", "[", "attr", " ", "~=", " ", "almost", "]",
		" ", "#id", ":", "hover(", "languidly", ")", " ", "{", " ",
		"font-weight", ":", " ", "super(", "bold", " ", "/", " ", "italic", ")",
		" ", "}")
}

func TestCSSTokensLex19(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"/* The RHS of the attribute comparison operators parse to quoted\n"+
			" * parse to quoted strings since they are surrounded by quotes. */\n"+
			"foo[attr = 'bar'] {}\n"+
			"foo[attr = \"bar\"] {}\n"+
			"foo[attr ~= 'bar baz'] {}\n"+
			"foo[attr |= 'bar-baz'] {}",
		"foo", "[", "attr", " ", "=", " ", "'bar'", "]", " ", "{", "}", " ",
		"foo", "[", "attr", " ", "=", " ", "'bar'", "]", " ", "{", "}", " ",
		"foo", "[", "attr", " ", "~=", " ", "'bar baz'", "]", " ", "{", "}", " ",
		"foo", "[", "attr", " ", "|=", " ", "'bar-baz'", "]", " ", "{", "}")
}

func TestCSSTokensLex20(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"/* The RHS of the attribute comparison operator in the following cases\n"+
			" * will parse to an IdentLiteral since it is unquoted. */\n"+
			"foo[attr = bar] {}\n"+
			"foo[attr |= bar-baz] {}",
		"foo", "[", "attr", " ", "=", " ", "bar", "]", " ", "{", "}", " ",
		"foo", "[", "attr", " ", "|=", " ", "bar-baz", "]", " ", "{", "}")
}

func TestCSSTokensLex21(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"foo.bar { }",
		"foo", ".bar", " ", "{", " ", "}")
}

func TestCSSTokensLex22(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"foo .bar { }",
		"foo", " ", ".bar", " ", "{", " ", "}")
}

func TestCSSTokensLex23(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"foo .quoted { content: 'contains \\'quotes\\'' }",
		"foo", " ", ".quoted", " ", "{", " ", "content", ":", " ",
		"'contains \\27quotes\\27'", " ", "}")
}

func TestCSSTokensLex24(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"foo .dquoted { content: \"'contains'\\\\\\\"double quotes\\\"\" }",
		"foo", " ", ".dquoted", " ", "{", " ", "content", ":", " ",
		"'\\27 contains\\27\\\\\\22 double quotes\\22'", " ", "}")
}

func TestCSSTokensLex25(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"foo .long { content: 'spans \\\n"+
			"multiple \\\n"+
			"lines' }\n",
		"foo", " ", ".long", " ", "{", " ", "content", ":", " ",
		"'spans multiple lines'", " ", "}")
}

func TestCSSTokensLex26(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"foo .extended-unicode { content: 'a1 \\61\\31  \\0000611 \\000061 1 \\0061\\0031' }",
		"foo", " ", ".extended-unicode", " ", "{", " ", "content", ":", " ",
		"'a1 a1 a1 a1 a1'", " ", "}")
}

func TestCSSTokensLex27(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"/* CSS 2.1 allows _ in identifiers */\n"+
			"#a_b {}\n"+
			".a_b {}",
		"#a_b", " ", "{", "}", " ", ".a_b", " ", "{", "}")
}

func TestCSSTokensLex28(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"#xxx {\n"+
			"  filter:alpha(opacity=50);\n"+
			"}",
		"#xxx", " ", "{", " ",
		"filter", ":", "alpha(", "opacity", "=", "50", ")", ";", " ",
		"}")
}

func TestCSSTokensLex29(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"p { margin: -3px -3px }\n"+
			"p { margin: -3px 3px }",
		"p", " ", "{", " ", "margin", ":", " ", "-3px", " ", "-3px", " ", "}", " ",
		"p", " ", "{", " ", "margin", ":", " ", "-3px", " ", "3px", " ", "}")
}

func TestCSSTokensLex30(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"<!-- \n"+
			"p { content: '-->foo<!--' }  /* - -> bar <!--- */\n"+
			"-->",
		"p", " ", "{", " ", "content", ":",
		" ", "'--\\3e foo\\3c!--'", " ", "}")
}

func TestCSSTokensLex31(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"@bogus hello {\n"+
			"  balanced { curly \"brackets\" };\n"+
			"}",
		"@bogus", " ", "hello", " ", "{", " ",
		"balanced", " ", "{", " ", "curly", " ", "'brackets'", " ", "}", ";",
		" ", "}")
}

func TestCSSTokensLex32(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"/* Not treated as part of the bogus symbol block */\n"+
			"* { color: red }",
		"*", " ", "{", " ", "color", ":", " ", "red", " ", "}")
}

func TestCSSTokensLex33(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"@unknown('hi');",
		"@unknown", "(", "'hi'", ")", ";")
}

func TestCSSTokensLex34(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"/* list applies to body, input, and td.  Extraneous , skip. */\n"+
			"body, input, , td {\n"+
			"  /* missing property name causes skip until ; */\n"+
			"  Arial, sans-serif;\n"+
			"  color: blue;\n"+
			"  /* missing value.  skipped. */\n"+
			"  background-color:\n"+
			"}",
		"body", ",", " ", "input", ",", " ", ",", " ", "td",
		" ", "{", " ", "Arial", ",", " ", "sans-serif", ";",
		" ", "color", ":", " ", "blue", ";",
		" ", "background-color", ":", " ", "}")
}

func TestCSSTokensLex35(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"/* not thrown out, but 2 digit color is discarded */\n"+
			"@media print {\n"+
			"  * { color: black !important; background-color: #ff }\n"+
			"}",
		"@media", " ", "print", " ", "{",
		" ", "*", " ", "{", " ", "color", ":", " ", "black", " ", "!", "important", ";", " ", "background-color", ":", " ", "#ff", " ", "}", " ", "}")
}

func TestCSSTokensLex36(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"@page :{broken { margin-left: 4cm; }  /* extra { */",
		"@page", " ", ":", "{", "broken", " ", "{",
		" ", "margin-left", ":", " ", "4cm", ";", " ", "}", " ", "}")
}

func TestCSSTokensLex37(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"@page .broken {}  /* no colon */",
		"@page", " ", ".broken", " ", "{", "}")
}

func TestCSSTokensLex38(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"@page :{}  /* no pseudo-page */",
		"@page", " ", ":", "{", "}")
}

func TestCSSTokensLex39(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"@page :broken {  /* missing '}' */",
		"@page", " ", ":", "broken", " ", "{", " ", "}")
}

func TestCSSTokensLex40(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"@page :left { margin-left: 4cm;; size: 8.5in 11in; }  /* ok */",
		"@page", " ", ":", "left", " ", "{",
		" ", "margin-left", ":", " ", "4cm", ";", ";",
		" ", "size", ":", " ", "8.5in", " ", "11in", ";", " ", "}")
}

func TestCSSTokensLex41(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"/* missing property */\n"+
			"body { : blue }",
		"body", " ", "{", " ", ":", " ", "blue", " ", "}")
}

func TestCSSTokensLex42(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"color: blue;",
		"color", ":", " ", "blue", ";")
}

func TestCSSTokensLex43(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"a:visited, :unvisited, a::before { color: blue }",
		"a", ":", "visited", ",",
		" ", ":", "unvisited", ",",
		" ", "a", ":", ":", "before",
		" ", "{", " ", "color", ":", " ", "blue", " ", "}")
}

func TestCSSTokensLex44(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"/* not a valid wildcard wiseguy */\n"+
			"? { color: blue }",
		"?", " ", "{", " ", "color", ":", " ", "blue", " ", "}")
}

func TestCSSTokensLex45(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"/* lots of invalid selectors */\n"+
			".3, #333, a[href='foo', a[href=], a[='foo'], body:, ok {}",
		"0.3", ",",
		" ", "#333", ",",
		" ", "a", "[", "href", "=", "'foo'", ",",
		" ", "a", "[", "href", "=", "]", ",",
		" ", "a", "[", "=", "'foo'", "]", ",",
		" ", "body", ":", ",",
		" ", "ok", " ", "{", "}",
		"]")
}

func TestCSSTokensLex46(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"/* all invalid selectors */\n"+
			"#333, .3, .,  {}",
		"#333", ",", " ", "0.3", ",", " ", ".", " ", ",", " ", "{", "}")
}

func TestCSSTokensLex47(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"/* valid selectors missing a body */\n"+
			"a, b, i, p, q, s, u, ;",
		"a", ",", " ", "b", ",", " ", "i", ",", " ", "p", ",", " ", "q", ",",
		" ", "s", ",", " ", "u", ",", " ", ";")
}

func TestCSSTokensLex48(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"/* expression cruft. Make sure parsing before and after ok. */\n"+
			"a1 { a: ok;  color: red:;              a: ok }  /* cruft after : */\n"+
			"a2 { a: ok;  width: 0 !import;         a: ok }  /* !important misspelled */\n"+
			"a3 { a: ok;  unicode-range: U+0-FFFF;  a: ok }  /* ok */ \n"+
			"a4 { a: ok;  color: #g00;              a: ok }  /* bad hex digit */\n"+
			"a5 { a: ok;  image: url('::');       a: ok }  /* malformed URI */\n"+
			"a6 { a: ok;  image: url(::);           a: ok }  /* malformed URI */",
		"a1", " ", "{", " ", "a", ":", " ", "ok", ";",
		" ", "color", ":", " ", "red", ":", ";",
		" ", "a", ":", " ", "ok", " ", "}", " ",
		"a2", " ", "{", " ", "a", ":", " ", "ok", ";",
		" ", "width", ":", " ", "0", " ", "!", "import", ";",
		" ", "a", ":", " ", "ok", " ", "}", " ",
		"a3", " ", "{", " ", "a", ":", " ", "ok", ";",
		" ", "unicode-range", ":", " ", "U+0-ffff", ";",
		" ", "a", ":", " ", "ok", " ", "}", " ",
		"a4", " ", "{", " ", "a", ":", " ", "ok", ";",
		" ", "color", ":", " ", "#g00",
		";", " ", "a", ":", " ", "ok", " ", "}", " ",
		"a5", " ", "{", " ", "a", ":", " ", "ok", ";",
		" ", "image", ":", " ", "url('::')", ";",
		" ", "a", ":", " ", "ok", " ", "}", " ",
		"a6", " ", "{", " ", "a", ":", " ", "ok", ";",
		" ", "image", ":", " ", "url('::')", ";",
		" ", "a", ":", " ", "ok", " ", "}")
}

func TestCSSTokensLex49(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"/* functions allow for lots of mischief */\n"+
			"a7 { a: ok;  font-size: expression(Math.random());  a: ok }  /* ok.  TODO */\n"+
			"a8 { a: ok;  font-size: expression(Math.random();   a: ok }  /* missing paren */\n"+
			"a9 { a: ok;  font-size: expression();               a: ok }  /* missing param */\n"+
			"aa { a: ok;  font-size: expression({});             a: ok }  /* bad param */",
		"a7", " ", "{", " ", "a", ":", " ", "ok", ";", " ", "font-size", ":",
		" ", "expression(", "Math", ".random", " ", "(", ")", ")", ";",
		" ", "a", ":", " ", "ok", " ", "}", " ",
		"a8", " ", "{", " ", "a", ":", " ", "ok", ";", " ", "font-size", ":",
		" ", "expression(", "Math", ".random", " ", "(", ")", ";",
		" ", "a", ":", " ", "ok", " ", ")", "}", " ",
		"a9", " ", "{", " ", "a", ":", " ", "ok", ";", " ", "font-size", ":",
		" ", "expression(", ")", ";", " ", "a", ":", " ", "ok", " ", "}", " ",
		"aa", " ", "{", " ", "a", ":", " ", "ok", ";", " ", "font-size", ":",
		" ", "expression(", "{", "}", ")", ";",
		" ", "a", ":", " ", "ok", " ", "}")
}

func TestCSSTokensLex50(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"@font-face; @font-face {}\n"+
			"@font-face @font-face"+
			" { font-family: Letters; src: url('Letters.ttf') }",
		"@font-face", ";", " ", "@font-face", " ", "{", "}", " ",
		"@font-face", " ", "@font-face", " ", "{",
		" ", "font-family", ":", " ", "Letters", ";",
		" ", "src", ":", " ", "url('Letters.ttf')", " ", "}")
}

func TestCSSTokensLex51(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"@charset \"utf-8\";",
		"@charset", " ", "'utf-8'", ";")
}

func TestCSSTokensLex52(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"@import url('nonsense.css') mumbling, blather;",
		"@import", " ", "url('nonsense.css')",
		" ", "mumbling", ",", " ", "blather", ";")
}

func TestCSSTokensLex53(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"@page { background: url('sparkley.jpg'); }",
		"@page", " ", "{", " ", "background", ":",
		" ", "url('sparkley.jpg')", ";", " ", "}")
}

func TestCSSTokensLex54(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"@charset \"non-utf-8\";",
		"@charset", " ", "'non-utf-8'", ";")
}

func TestCSSTokensLex55(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"/* non utf-8 */\n"+
			"@import 'foo.css';\n"+
			"@unknown('hi');",
		"@import", " ", "'foo.css'", ";", " ",
		"@unknown", "(", "'hi'", ")", ";")
}

func TestCSSTokensLex56(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"\ufeff"+
			"values: 100% -12.5% '' \"\" .5em 0 12 url() url('') url(\"\");",
		// Do not treat a BOM as a part of an identifier.
		"values", ":", " ", "100%", " ", "-12.5%", " ", "''", " ", "''",
		" ", "0.5em", " ", "0", " ", "12",
		" ", "url('')", " ", "url('')", " ", "url('')", ";")
}

func TestCSSTokensLex57(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"// line comment 1\nline2\n//line comment 3\r\nline4//line comment 4\f",
		"line2", " ", "line4")
}

func TestCSSTokensLex58(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"\"\\\r\n\"",
		"''")
}

func TestCSSTokensLex59(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"url()",
		"url('')")
}

func TestCSSTokensLex60(t *testing.T) {
	cssTokensAssertLexedCSS(t,
		"\t\ufeff x",
		"x")
}

func TestCSSTokensLex61(t *testing.T) {
	cssTokensAssertTokens(t,
		"x.1",
		"x:IDENT", " ", "0.1:NUMBER")
}

func TestCSSTokensLex62(t *testing.T) {
	cssTokensAssertTokens(t,
		"0.. 1. . 0e1. 0e1 .",
		"0:NUMBER", " ", ".:DELIM", " ", "1:NUMBER", " ", ".:DELIM", " ",
		"0:NUMBER", " ", ".:DELIM", " ", "0:NUMBER", " ", ".:DELIM")
}

func TestCSSTokensLex63(t *testing.T) {
	cssTokensAssertTokens(t,
		"[[ ]]>",
		"[:LEFT_SQUARE",
		"[:LEFT_SQUARE",
		" ",
		"]:RIGHT_SQUARE",
		"]:RIGHT_SQUARE",
		" ", // Inserted
		">:DELIM")
	cssTokensAssertTokens(t,
		"[[ ]] >",
		"[:LEFT_SQUARE",
		"[:LEFT_SQUARE",
		" ",
		"]:RIGHT_SQUARE",
		"]:RIGHT_SQUARE",
		" ",
		">:DELIM")
}

func TestCSSTokensLex64(t *testing.T) {
	cssTokensAssertTokens(t,
		"<![CDATA[",
		"<:DELIM",
		" ", // inserted
		"!:DELIM",
		"[:LEFT_SQUARE",
		"CDATA:IDENT",
		"[:LEFT_SQUARE",
		"]:RIGHT_SQUARE",
		"]:RIGHT_SQUARE")
	cssTokensAssertTokens(t,
		"<\\![\\43 DATA[",
		"<:DELIM",
		" ", // inserted
		"!:DELIM",
		"[:LEFT_SQUARE",
		"CDATA:IDENT",
		"[:LEFT_SQUARE",
		"]:RIGHT_SQUARE",
		"]:RIGHT_SQUARE")
}

func TestCSSTokensLex65(t *testing.T) {
	cssTokensAssertTokens(t,
		"<\\/St\\79le",
		"<:DELIM",
		" ", // inserted
		"/:DELIM",
		" ", // inserted
		"Style:IDENT")
}

func TestCSSTokensLex66(t *testing.T) {
	cssTokensAssertTokens(t,
		"/\\/foo\n/\\*bar*/",
		"/:DELIM",
		" ",
		"/:DELIM",
		" ",
		"foo:IDENT",
		" ",
		"/:DELIM",
		" ",
		"*:DELIM",
		"bar:IDENT",
		"*:DELIM",
		"/:DELIM")
}

func TestCSSTokensLex67(t *testing.T) {
	cssTokensAssertTokens(t,
		"0 .-42",
		"0:NUMBER",
		" ",
		".:DELIM",
		" ",
		"-42:NUMBER")
}

func TestCSSTokensLex68(t *testing.T) {
	cssTokensAssertTokens(t,
		"#.42",
		"#:DELIM",
		" ",
		"0.42:NUMBER",
	)
	cssTokensAssertTokens(t,
		"#-.42",
		"#-:HASH_ID",
		" ",
		"0.42:NUMBER",
	)
}

func TestCSSTokensLex69(t *testing.T) {
	cssTokensAssertTokens(t,
		"font: 24ex\x00pression",
		"font:IDENT",
		"::COLON",
		" ",
		"24ex:DIMENSION",
		" ",
		"pression:IDENT")
}
