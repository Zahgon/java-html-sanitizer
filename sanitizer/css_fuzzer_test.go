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
// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/CssFuzzerTest.java.

package sanitizer

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"testing"
	"time"
)

// cssFuzzerTestSeed seeds the generators so that a failure can be replayed.
const cssFuzzerTestSeed = 20261011

var cssFuzzerTestTokenParts = []string{
	"'", "\"", "<!--", "-->", "/*", "*/", "***", "//", "\r", "\n",
	"<", ">", "/", ",", ";", ":", "(", "url", "Url", ")", "[", "]", "{", "}",
	"\\", "\\a", "\\d", "\\0", " ", "\t", "42", ".", "ex", "auto", "foo", "BAr",
	"important", "!", "\ufeff", "\u0000", "\u00a0", "\ufffd", "\U00010402",
	"\u007f", "\u000c", "CDATA", "style",
}

var cssFuzzerTestFrequentTokenParts = []string{
	"*/", " ", "\t", "\r", "\n",
}

var cssFuzzerTestDisallowedInOutput = []string{
	"</style", "<![CDATA[", "]]>", "\r", "\n",
}

// TestCSSFuzzerBracketPairingMatchesAStackWalk: the lexer pairs brackets as
// a plain stack walk does: a close bracket with a partner closes everything
// opened after that partner, one without is dropped, and whatever is still
// open at the end is closed.  The lexer keeps a count of open brackets per
// kind so that it can drop an orphan without walking, so compare the two on
// random bracket soup, function openers included.  A count that fell behind
// the stack would drop a close that has a partner, and show up here.
func TestCSSFuzzerBracketPairingMatchesAStackWalk(t *testing.T) {
	rnd := rand.New(rand.NewSource(cssFuzzerTestSeed))
	parts := []string{"(", ")", "[", "]", "{", "}", "f(", " ", "x"}
	for run, nRuns := 0, 1<<14; run < nRuns; run++ {
		var sb strings.Builder
		for j := rnd.Intn(48); j > 0; j-- {
			sb.WriteString(parts[rnd.Intn(len(parts))])
		}
		css := sb.String()
		if want, got := cssFuzzerTestBracketsAfterAStackWalk(css),
			cssFuzzerTestBracketsOnly(cssTokensLex(css).normalizedCSS); got != want {
			t.Fatalf("seed=%d, css=`%s`: got %q, want %q", cssFuzzerTestSeed, css, got, want)
		}
	}
}

func cssFuzzerTestBracketsOnly(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if strings.IndexByte("()[]{}", s[i]) >= 0 {
			sb.WriteByte(s[i])
		}
	}
	return sb.String()
}

func cssFuzzerTestBracketsAfterAStackWalk(s string) string {
	var out []byte
	// The close brackets owed, innermost last.
	var owed []byte
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if open := strings.IndexByte("([{", ch); open >= 0 {
			out = append(out, ch)
			owed = append(owed, ")]}"[open])
		} else if strings.IndexByte(")]}", ch) >= 0 {
			if partner := strings.LastIndexByte(string(owed), ch); partner >= 0 {
				for k := len(owed) - 1; k >= partner; k-- {
					out = append(out, owed[k])
				}
				owed = owed[:partner]
			}
		}
	}
	for k := len(owed) - 1; k >= 0; k-- {
		out = append(out, owed[k])
	}
	return string(out)
}

func TestCSSFuzzerUnderStress(t *testing.T) {
	rnd := rand.New(rand.NewSource(cssFuzzerTestSeed))
	for run, nRuns := 0, 1<<16; run < nRuns; run++ {
		// Compose a random string from token parts.
		var sb strings.Builder
		nParts := rnd.Intn(64) + 16
		for j := nParts; j > 0; j-- {
			switch die := rnd.Intn(32); die {
			case 0:
				sb.WriteRune(rune(rnd.Intn(0x80)))
			case 1:
				sb.WriteRune(rune(rnd.Intn(0x1800)))
			default:
				arr := cssFuzzerTestFrequentTokenParts
				if die&1 != 0 {
					arr = cssFuzzerTestTokenParts
				}
				sb.WriteString(arr[rnd.Intn(len(arr))])
			}
		}
		randomCSS := sb.String()

		msg := fmt.Sprintf("seed=%d, css=`%s`", cssFuzzerTestSeed, randomCSS)
		started := time.Now()
		tokens := cssTokensLex(randomCSS)

		// Test idempotent
		renormalized := cssTokensLex(tokens.normalizedCSS).normalizedCSS
		if renormalized != tokens.normalizedCSS {
			if renormalized != cssFuzzerTestFixDigitSpaceUnit(tokens) {
				for it := tokens.iterator(); it.hasNext(); it.advance() {
					t.Log(it.token() + ":" + it.tokenType().String())
				}
				t.Fatalf("not idempotent, %s: %q != %q", msg, tokens.normalizedCSS, renormalized)
			}
		}
		if elapsed := time.Since(started); elapsed >= time.Second {
			t.Logf("`%s` is slow (%v). seed=%d", randomCSS, elapsed, cssFuzzerTestSeed)
		}

		// Test normalized CSS does not contain HTML/XML breaking tokens.
		for _, disallowed := range cssFuzzerTestDisallowedInOutput {
			if strings.Contains(tokens.normalizedCSS, disallowed) {
				t.Fatalf("contains %s, %s", disallowed, msg)
			}
		}

		// Test that tokens are roughly well-formed.
		nTokens := 0
		for it := tokens.iterator(); it.hasNext(); {
			typ := it.tokenType()
			token := it.next()
			if filter, ok := cssFuzzerTestTokenTypeFilters[typ]; ok && !filter.MatchString(token) {
				t.Fatalf("%v `%s`, %s", typ, token, msg)
			}
			nTokens++
		}

		// Test that walking the bracket list works.
		reverse := make([]int, nTokens)
		for j := range reverse {
			reverse[j] = -1
		}
		for j := 0; j < nTokens; j++ {
			if partner := tokens.brackets.partner(j); partner != -1 {
				reverse[partner] = j
			}
		}
		for j := 0; j < nTokens; j++ {
			if reverse[j] != -1 && reverse[reverse[j]] != j {
				t.Fatalf("bracket %d: %s", j, msg)
			}
		}
	}
}

// cssFuzzerTestTokenTypeFilters match the whole of a token of each type.
var cssFuzzerTestTokenTypeFilters = func() map[cssTokensTokenType]*regexp.Regexp {
	const (
		number     = `-?(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?(?:e-?[1-9][0-9]*)?`
		identStart = `[a-zA-Z_\x{80}-\x{10FFFF}\-]`
		identPart  = `(?:` + identStart + `|[0-9])`
		ident      = identStart + identPart + `*`
	)
	filters := map[cssTokensTokenType]string{
		cssTokensTokenTypeAt:               `@` + ident,
		cssTokensTokenTypeColon:            `:`,
		cssTokensTokenTypeColumn:           `\|\|`,
		cssTokensTokenTypeComma:            `,`,
		cssTokensTokenTypeDelim:            `[^\w\x00- \x{80}-\x{FFFF}\-]`,
		cssTokensTokenTypeDimension:        number + `[a-z]+`,
		cssTokensTokenTypeDotIdent:         `\.` + ident,
		cssTokensTokenTypeFunction:         ident + `[(]`,
		cssTokensTokenTypeHashId:           `#` + identPart + `+`,
		cssTokensTokenTypeHashUnrestricted: `#[a-fA-F0-9]+`,
		cssTokensTokenTypeIdent:            ident,
		cssTokensTokenTypeLeftCurly:        `[{]`,
		cssTokensTokenTypeLeftParen:        `[(]`,
		cssTokensTokenTypeLeftSquare:       `[\[]`,
		cssTokensTokenTypeMatch:            `[~^$|*]=`,
		cssTokensTokenTypeNumber:           number,
		cssTokensTokenTypePercentage:       number + `%`,
		cssTokensTokenTypeRightCurly:       `[}]`,
		cssTokensTokenTypeRightParen:       `[)]`,
		cssTokensTokenTypeRightSquare:      `[\]]`,
		cssTokensTokenTypeSemicolon:        `;`,
		cssTokensTokenTypeString:           `'(?:[^'\r\n\\]|\\[^\r\n])*'`,
		cssTokensTokenTypeUnicodeRange:     `U\+[0-9a-f]{1,6}(?:-[0-9a-f]{1,6}|\?{0,5})?`,
		cssTokensTokenTypeURL:              `url\('[0-9A-Za-z\-_.~:/?#\[\]@!$&+,;=%]*'\)`,
		cssTokensTokenTypeWhitespace:       ` `,
	}
	compiled := make(map[cssTokensTokenType]*regexp.Regexp, len(filters))
	for typ, pattern := range filters {
		compiled[typ] = regexp.MustCompile(`^(?:` + pattern + `)$`)
	}
	return compiled
}()

// cssFuzzerTestFixDigitSpaceUnit undoes a common source of non-idempotency:
// "1:NUMBER ex:IDENT" -> "1ex:DIMENSION", which causes no problems in
// practice.  This hack helps ignore it.
func cssFuzzerTestFixDigitSpaceUnit(tokens *cssTokens) string {
	var sb strings.Builder
	for it := tokens.iterator(); it.hasNext(); {
		if it.tokenType() != cssTokensTokenTypeNumber {
			sb.WriteString(it.next())
			continue
		}
		for {
			sb.WriteString(it.next())
			if !(it.hasNext() && it.tokenType() == cssTokensTokenTypeNumber) {
				break
			}
		}
		if it.hasNext() && it.tokenType() == cssTokensTokenTypeWhitespace {
			it.advance()
			numberFollower, hasFollower := "", false
			if it.hasNext() {
				token := it.token()
				switch it.tokenType() {
				case cssTokensTokenTypeIdent:
					if cssTokensIsWellKnownUnit(token) {
						numberFollower, hasFollower = token, true
						it.advance()
						if it.hasNext() && strings.HasPrefix(it.token(), ".") {
							numberFollower += " "
						}
						it.backup()
					}
				case cssTokensTokenTypeFunction:
					if cssTokensIsWellKnownUnit(token[:len(token)-1]) {
						numberFollower, hasFollower = token, true
					}
				case cssTokensTokenTypeDelim:
					if token == "%" {
						numberFollower, hasFollower = token, true
					}
				}
			}
			if !hasFollower {
				sb.WriteByte(' ')
			} else {
				// Drop the space and append a lower-case version of the unit.
				sb.WriteString(stringsToLowerCase(numberFollower))
				it.advance()
			}
		}
	}
	return sb.String()
}
