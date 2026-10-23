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
// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/CssTokens.java.

package sanitizer

import (
	"unicode"
)

// cssTokens is the result of lexing a string of CSS: a string of normalized
// CSS with certain useful properties detailed below, split into tokens.
//
//   - All runs of white-space and comment tokens (including CDO and CDC)
//     have been replaced with a single space character.
//   - All strings are quoted and escapes are escaped according to the
//     following scheme:
//     NUL             \0
//     line feed       \a
//     vertical feed   \c
//     carriage return \d
//     double quote    \22
//     ampersand &     \26
//     single quote    \27
//     left-angle <    \3c
//     rt-angle >      \3e
//     back slash      \\
//     all others      raw
//   - All url(...) tokens are quoted.
//   - All keywords, identifiers, and hex literals are lower-case and have
//     embedded escape sequences decoded.
//   - All brackets nest properly.
//   - Does not contain any case-insensitive variant of the sequences
//     <!--, -->, <![CDATA[, ]]>, or </style.
//   - All delimiters that can start longer tokens are followed by a space.
//
// The lexer works on UTF-16 code units, so escapes, surrogates and offsets
// are handled per code unit; normalizedCSS is the re-encoded result.
type cssTokens struct {
	// normalizedCSS is the normalized form of the lexed CSS.
	normalizedCSS string
	// brackets maps bracket tokens to their partners.
	brackets cssTokensBrackets
	// tokenBreaks holds the byte offset into normalizedCSS of the start of
	// each token, followed by len(normalizedCSS).
	tokenBreaks []int
	tokenTypes  []cssTokensTokenType
}

// start returns a cursor positioned at the first token.
func (t *cssTokens) start() *cssTokensTokenIterator {
	return &cssTokensTokenIterator{tokens: t, limit: len(t.tokenTypes)}
}

// iterator is an alias for start.
func (t *cssTokens) iterator() *cssTokensTokenIterator { return t.start() }

// cssTokensLex lexes the given CSS into normalized tokens.
func cssTokensLex(css string) *cssTokens {
	lexer := newCSSTokensLexer(css)
	lexer.lex()
	return lexer.build()
}

// cssTokensTokenIterator is a cursor into a list of tokens.
type cssTokensTokenIterator struct {
	tokens *cssTokens
	index  int
	limit  int
}

func (it *cssTokensTokenIterator) hasNext() bool {
	return it.hasToken()
}

// next returns the current token and advances past it.
// It panics if there is no current token.
func (it *cssTokensTokenIterator) next() string {
	if !it.hasToken() {
		panic("cssTokensTokenIterator: no such element")
	}
	token := it.token()
	it.advance()
	return token
}

// spliceToEnd returns a cursor over the tokens between the current bracket
// token and its partner, and moves this cursor past the partner.
// It returns nil if the current token has no partner.
func (it *cssTokensTokenIterator) spliceToEnd() *cssTokensTokenIterator {
	if !it.hasNext() {
		panic("cssTokensTokenIterator: no such element")
	}
	end := it.tokens.brackets.partner(it.index)
	if end < 0 {
		return nil
	}
	between := &cssTokensTokenIterator{
		tokens: it.tokens, index: it.index + 1, limit: end}
	it.index = end + 1
	return between
}

func (it *cssTokensTokenIterator) tokenIndex() int {
	return it.index
}

func (it *cssTokensTokenIterator) startOffset() int {
	return it.tokens.tokenBreaks[it.index]
}

func (it *cssTokensTokenIterator) endOffset() int {
	return it.tokens.tokenBreaks[it.index+1]
}

// token is the text of the current token.
func (it *cssTokensTokenIterator) token() string {
	return it.tokens.normalizedCSS[it.startOffset():it.endOffset()]
}

func (it *cssTokensTokenIterator) hasToken() bool {
	return it.index < it.limit
}

// hasTokenAfterSpace skips over any white-space tokens and reports whether
// a token remains.
func (it *cssTokensTokenIterator) hasTokenAfterSpace() bool {
	for it.hasToken() {
		if it.tokenType() != cssTokensTokenTypeWhitespace {
			return true
		}
		it.advance()
	}
	return false
}

// tokenType is the type of the current token.
func (it *cssTokensTokenIterator) tokenType() cssTokensTokenType {
	return it.tokens.tokenTypes[it.index]
}

func (it *cssTokensTokenIterator) seek(newTokenIndex int) {
	it.index = newTokenIndex
}

func (it *cssTokensTokenIterator) advance() {
	if !it.hasToken() {
		panic("cssTokensTokenIterator: no such element")
	}
	it.index++
}

func (it *cssTokensTokenIterator) backup() {
	if it.index == 0 {
		panic("cssTokensTokenIterator: no such element")
	}
	it.index--
}

// cssTokensTokenType is the kind of a CSS token.
type cssTokensTokenType int

const (
	// cssTokensTokenTypeIdent is an identifier.
	cssTokensTokenTypeIdent cssTokensTokenType = iota
	// cssTokensTokenTypeDotIdent is an identifier prefixed with a period.
	cssTokensTokenTypeDotIdent
	// cssTokensTokenTypeFunction is a function name and opening bracket.
	cssTokensTokenTypeFunction
	// cssTokensTokenTypeAt is an @<identifier> directive token.
	cssTokensTokenTypeAt
	// cssTokensTokenTypeHashId is a hash token that contains non-hex
	// characters.
	cssTokensTokenTypeHashId
	// cssTokensTokenTypeHashUnrestricted is a hash token that could be a
	// color literal.
	cssTokensTokenTypeHashUnrestricted
	// cssTokensTokenTypeString is a quoted string.
	cssTokensTokenTypeString
	// cssTokensTokenTypeURL is a URL of the form url("...").
	cssTokensTokenTypeURL
	// cssTokensTokenTypeDelim is a single character.
	cssTokensTokenTypeDelim
	// cssTokensTokenTypeNumber is a scalar numeric value.
	cssTokensTokenTypeNumber
	// cssTokensTokenTypePercentage is a percentage.
	cssTokensTokenTypePercentage
	// cssTokensTokenTypeDimension is a numeric value with a unit suffix.
	cssTokensTokenTypeDimension
	// cssTokensTokenTypeBadDimension is a numeric value with an unknown unit
	// suffix.
	cssTokensTokenTypeBadDimension
	// cssTokensTokenTypeUnicodeRange is U+<hex-or-qmark>.
	cssTokensTokenTypeUnicodeRange
	// cssTokensTokenTypeMatch is an include-match, dash-match, prefix-match,
	// suffix-match, or substring-match.
	cssTokensTokenTypeMatch
	// cssTokensTokenTypeColumn is ||.
	cssTokensTokenTypeColumn
	// cssTokensTokenTypeWhitespace is a run of white-space, comment, CDO, and
	// CDC tokens.
	cssTokensTokenTypeWhitespace
	// cssTokensTokenTypeColon is :.
	cssTokensTokenTypeColon
	// cssTokensTokenTypeSemicolon is ;.
	cssTokensTokenTypeSemicolon
	// cssTokensTokenTypeComma is ,.
	cssTokensTokenTypeComma
	// cssTokensTokenTypeLeftSquare is [.
	cssTokensTokenTypeLeftSquare
	// cssTokensTokenTypeRightSquare is ].
	cssTokensTokenTypeRightSquare
	// cssTokensTokenTypeLeftParen is (.
	cssTokensTokenTypeLeftParen
	// cssTokensTokenTypeRightParen is ).
	cssTokensTokenTypeRightParen
	// cssTokensTokenTypeLeftCurly is {.
	cssTokensTokenTypeLeftCurly
	// cssTokensTokenTypeRightCurly is }.
	cssTokensTokenTypeRightCurly
)

var cssTokensTokenTypeNames = [...]string{
	"IDENT", "DOT_IDENT", "FUNCTION", "AT", "HASH_ID", "HASH_UNRESTRICTED",
	"STRING", "URL", "DELIM", "NUMBER", "PERCENTAGE", "DIMENSION",
	"BAD_DIMENSION", "UNICODE_RANGE", "MATCH", "COLUMN", "WHITESPACE",
	"COLON", "SEMICOLON", "COMMA", "LEFT_SQUARE", "RIGHT_SQUARE",
	"LEFT_PAREN", "RIGHT_PAREN", "LEFT_CURLY", "RIGHT_CURLY",
}

// String returns the upper-case name of the token type, such as "DOT_IDENT".
func (t cssTokensTokenType) String() string {
	return cssTokensTokenTypeNames[t]
}

// cssTokensBrackets maps tokens to their partners.  A close bracket token
// like ( may have a partner token like ) if properly nested, and vice-versa.
type cssTokensBrackets struct {
	// brackets holds, for each bracket, its token index and the index of its
	// partner token, or -1 if it has none.  Sorted by the first of each pair.
	brackets []int
}

// partner returns the index of the partner token or -1 if none.
func (b cssTokensBrackets) partner(tokenIndex int) int {
	bracketIndex := b.bracketIndexForToken(tokenIndex)
	if bracketIndex < 0 {
		return -1
	}
	return b.brackets[(bracketIndex<<1)+1]
}

func (b cssTokensBrackets) bracketIndexForToken(target int) int {
	// Binary search by leftmost element of pair.
	left := 0
	right := len(b.brackets) >> 1
	for left < right {
		mid := left + ((right - left) >> 1)
		value := b.brackets[mid<<1]
		if value == target {
			return mid
		}
		if value < target {
			left = mid + 1
		} else {
			right = mid
		}
	}
	return -1
}

var cssTokensEmpty = &cssTokens{tokenBreaks: []int{}, tokenTypes: []cssTokensTokenType{}}

// cssTokensLexer tokenizes according to section 4 of
// http://dev.w3.org/csswg/css-syntax/
//
// It reads and writes UTF-16 code units, so a lone surrogate is an ordinary
// code unit and offsets count code units.
type cssTokensLexer struct {
	css []uint16
	sb  []uint16
	pos int

	// tokenTypes is nil until lexing finds some content.
	tokenTypes  []cssTokensTokenType
	tokenBreaks []int

	// brackets holds, for each bracket, 2 ints: the token index of the
	// bracket, and the token index of its partner.
	// The slice is sorted by the first int.
	// The second int is -1 when the bracket has not yet been closed.
	brackets []int
	// open holds, for each bracket that has not been closed, 2 ints:
	// its index in brackets and the character of its close bracket.
	// This is a bracket stack so the slice is sorted by the first int.
	open []int
	// openCounts holds, for each kind of close bracket, how many brackets on
	// open it would close, so that a close bracket with no open partner is
	// dropped without walking the stack.  Walking it made a run of unmatched
	// closes after a run of opens take time quadratic in the input.  Indexed
	// by cssTokensLexerBracketKind.
	openCounts [3]int
}

// cssTokensLexerBracketKind is an index into openCounts for a close bracket
// character.
func cssTokensLexerBracketKind(closeBracket int) int {
	switch closeBracket {
	case ')':
		return 0
	case ']':
		return 1
	case '}':
		return 2
	default:
		panic("Invalid close bracket " + string(rune(closeBracket)))
	}
}

func newCSSTokensLexer(css string) *cssTokensLexer {
	return &cssTokensLexer{css: utf16Units(css)}
}

func (l *cssTokensLexer) openBracket(bracketChar uint16) cssTokensTokenType {
	var closeBracket int
	var typ cssTokensTokenType
	switch bracketChar {
	case '(':
		closeBracket, typ = ')', cssTokensTokenTypeLeftParen
	case '[':
		closeBracket, typ = ']', cssTokensTokenTypeLeftSquare
	case '{':
		closeBracket, typ = '}', cssTokensTokenTypeLeftCurly
	default:
		panic("Invalid open bracket " + string(rune(bracketChar)))
	}
	l.open = append(l.open, len(l.brackets), closeBracket)
	l.openCounts[cssTokensLexerBracketKind(closeBracket)]++
	l.brackets = append(l.brackets, len(l.tokenBreaks), -1)
	l.sb = append(l.sb, bracketChar)
	return typ
}

func (l *cssTokensLexer) closeBracket(bracketChar uint16) {
	if l.openCounts[cssTokensLexerBracketKind(int(bracketChar))] == 0 {
		// Drop an orphaned close bracket.
		l.breakOutput()
		return
	}
	// The count says a partner is on the stack, so this walk ends at it.
	// The bound stays as a second line of defence: were the count ever to
	// drift from the stack, the bracket is dropped rather than the walk
	// reading off the bottom of the stack.
	openLimitAfterClose := len(l.open)
	for {
		if openLimitAfterClose == 0 {
			l.breakOutput()
			return
		}
		openLimitAfterClose -= 2
		if int(bracketChar) == l.open[openLimitAfterClose+1] {
			break
		}
	}
	l.closeBrackets(openLimitAfterClose)
}

func (l *cssTokensLexer) closeBrackets(openLimitAfterClose int) {
	closeTokenIndex := len(l.tokenBreaks)
	for len(l.open) > openLimitAfterClose {
		// Pop the stack.
		n := len(l.open)
		closeBracket := l.open[n-1]
		openBracketIndex := l.open[n-2]
		l.open = l.open[:n-2]
		l.openCounts[cssTokensLexerBracketKind(closeBracket)]--
		openTokenIndex := l.brackets[openBracketIndex]
		// Update open bracket to point to its partner.
		l.brackets[openBracketIndex+1] = closeTokenIndex
		// Emit the close bracket.
		l.brackets = append(l.brackets, closeTokenIndex, openTokenIndex)
		l.sb = append(l.sb, uint16(closeBracket))
		closeTokenIndex++
	}
}

func (l *cssTokensLexer) build() *cssTokens {
	// Close any still open brackets.
	startOfCloseBrackets := len(l.sb)
	l.closeBrackets(0)
	l.emitMergedTokens(startOfCloseBrackets, len(l.sb))

	if l.tokenTypes == nil {
		return cssTokensEmpty
	}

	// Strip any trailing space off, since it may have been inserted by a
	// breakAfter call anyway.
	cssEnd := len(l.sb)
	if cssEnd > 0 && l.sb[cssEnd-1] == ' ' {
		cssEnd--
		l.tokenTypes = l.tokenTypes[:len(l.tokenTypes)-1]
		l.tokenBreaks = l.tokenBreaks[:len(l.tokenBreaks)-1]
	}

	// Re-encode the output, token by token, and translate the token breaks
	// from UTF-16 offsets to byte offsets.  Store the end of the output as a
	// final break to simplify finding the end of a token.
	out := make([]byte, 0, cssEnd)
	byteBreaks := make([]int, len(l.tokenBreaks)+1)
	prev := 0
	for i, brk := range l.tokenBreaks {
		out = append(out, fromUTF16Units(l.sb[prev:brk])...)
		byteBreaks[i] = len(out)
		prev = brk
	}
	out = append(out, fromUTF16Units(l.sb[prev:cssEnd])...)
	byteBreaks[len(l.tokenBreaks)] = len(out)

	return &cssTokens{
		normalizedCSS: string(out),
		brackets:      cssTokensBrackets{brackets: l.brackets},
		tokenBreaks:   byteBreaks,
		tokenTypes:    l.tokenTypes,
	}
}

func (l *cssTokensLexer) lex() {
	// Fast-track no content.
	l.consumeIgnorable()
	l.sb = l.sb[:0]
	cssLimit := len(l.css)
	if l.pos == cssLimit {
		return
	}

	l.tokenTypes = []cssTokensTokenType{}

	css := l.css
	for l.pos < cssLimit {
		// SPEC: 4. Tokenization
		// The output of the tokenization step is a stream of zero
		// or more of the following tokens: <ident>, <function>,
		// <at-keyword>, <hash>, <string>, <bad-string>, <url>,
		// <bad-url>, <delim>, <number>, <percentage>,
		// <dimension>, <unicode-range>, <include-match>,
		// <dash-match>, <prefix-match>, <suffix-match>,
		// <substring-match>, <column>, <whitespace>, <CDO>,
		// <CDC>, <colon>, <semicolon>, <comma>, <[>, <]>,
		// <(>, <)>, <{>, and <}>.

		// IMPLEMENTS: 4.3 Consume a token
		ch := css[l.pos]
		startOfOutputToken := len(l.sb)
		var typ cssTokensTokenType
		switch ch {
		case '\t', '\n', '\f', '\r', ' ', 0xfeff:
			l.consumeIgnorable()
			typ = cssTokensTokenTypeWhitespace
		case '/':
			lookahead := l.charAt(l.pos + 1)
			if lookahead == '/' || lookahead == '*' {
				l.consumeIgnorable()
				typ = cssTokensTokenTypeWhitespace
			} else {
				l.consumeDelim(ch)
				typ = cssTokensTokenTypeDelim
			}
		case '<':
			if l.consumeIgnorable() { // <!--
				typ = cssTokensTokenTypeWhitespace
			} else {
				l.consumeDelim('<')
				typ = cssTokensTokenTypeDelim
			}
		case '>':
			l.breakOutput()
			l.sb = append(l.sb, '>')
			typ = cssTokensTokenTypeDelim
			l.pos++
		case '@':
			if l.consumeAtKeyword() {
				typ = cssTokensTokenTypeAt
			} else {
				l.consumeDelim(ch)
				typ = cssTokensTokenTypeDelim
			}
		case '#':
			l.sb = append(l.sb, '#')
			if hashType, ok := l.consumeHash(); ok {
				typ = hashType
			} else {
				l.pos++
				l.sb = append(l.sb, ' ')
				typ = cssTokensTokenTypeDelim
			}
		case '"', '\'':
			typ = l.consumeString()
		case 'U', 'u':
			// SPEC handle URL under "ident like token".
			if l.consumeUnicodeRange() {
				typ = cssTokensTokenTypeUnicodeRange
			} else if identType, ok := l.consumeIdentOrURLOrFunction(); ok {
				typ = identType
			} else {
				// Make progress even in the face of errors.
				typ = cssTokensTokenTypeWhitespace
				l.breakOutput()
				l.pos++
			}
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			typ = l.consumeNumberOrPercentageOrDimension()
		case '+', '-', '.':
			lookahead := l.charAt(l.pos + 1)
			if cssTokensIsDecimal(lookahead) ||
				(lookahead == '.' && l.pos+2 < cssLimit &&
					cssTokensIsDecimal(css[l.pos+2])) {
				typ = l.consumeNumberOrPercentageOrDimension()
			} else if ch == '+' {
				l.consumeDelim(ch)
				typ = cssTokensTokenTypeDelim
			} else if ch == '-' {
				if l.consumeIgnorable() { // -->
					typ = cssTokensTokenTypeWhitespace
				} else if identType, ok := l.consumeIdentOrURLOrFunction(); ok {
					typ = identType
				} else {
					l.breakOutput()
					l.consumeDelim(ch)
					typ = cssTokensTokenTypeDelim
				}
			} else if cssTokensIsIdentPart(int(lookahead)) {
				// treat ".<IDENT>" as one token.
				startOfToken := l.pos
				l.sb = append(l.sb, '.')
				l.pos++
				l.consumeIdent(false)
				if l.pos != startOfToken+1 {
					typ = cssTokensTokenTypeDotIdent
					if l.pos < cssLimit && css[l.pos] == '(' {
						// A dotted identifier followed by a parenthesis is
						// ambiguously a function.
						l.sb = append(l.sb, ' ')
					}
				} else {
					typ = cssTokensTokenTypeDelim
					l.sb = append(l.sb, ' ')
				}
			} else {
				l.consumeDelim('.')
				typ = cssTokensTokenTypeDelim
			}
		case ':':
			l.consumeDelim(ch)
			typ = cssTokensTokenTypeColon
		case ';':
			l.consumeDelim(ch)
			typ = cssTokensTokenTypeSemicolon
		case ',':
			l.consumeDelim(ch)
			typ = cssTokensTokenTypeComma
		case '[', '(', '{':
			typ = l.openBracket(ch)
			l.pos++
		case '}', ')', ']':
			l.closeBracket(ch)
			l.pos++
			// Use DELIM so that a later loop will split output into multiple
			// tokens since we may have inserted missing close brackets for
			// unclosed open brackets already on the stack.
			typ = cssTokensTokenTypeDelim
		case '~', '|', '^', '$', '*':
			lookahead := l.charAt(l.pos + 1)
			if lookahead == '=' {
				l.consumeMatch(ch)
				typ = cssTokensTokenTypeMatch
			} else if ch == '|' && lookahead == '|' {
				l.consumeColumn()
				typ = cssTokensTokenTypeColumn
			} else {
				l.consumeDelim(ch)
				typ = cssTokensTokenTypeDelim
			}
		case '_', '\\':
			// Optimistically parse as an ident.
			if identType, ok := l.consumeIdentOrURLOrFunction(); ok {
				typ = identType
			} else {
				l.pos++ // drop
				l.breakOutput()
				typ = cssTokensTokenTypeWhitespace
			}
		default:
			chlower := ch | 32
			if 'a' <= chlower && chlower <= 'z' || ch >= 0x80 {
				if identType, ok := l.consumeIdentOrURLOrFunction(); ok {
					typ = identType
				} else { // Occurs on undefined-codepoints.
					l.pos++
					l.breakOutput()
					typ = cssTokensTokenTypeWhitespace
				}
			} else if ch > 0x20 {
				l.consumeDelim(ch)
				typ = cssTokensTokenTypeDelim
			} else { // Ignore.
				l.consumeIgnorable()
				typ = cssTokensTokenTypeWhitespace
			}
		}
		endOfOutputToken := len(l.sb)
		if endOfOutputToken > startOfOutputToken {
			if typ == cssTokensTokenTypeDelim {
				l.emitMergedTokens(startOfOutputToken, endOfOutputToken)
			} else {
				if typ != cssTokensTokenTypeWhitespace &&
					l.sb[startOfOutputToken] == ' ' {
					l.emitToken(cssTokensTokenTypeWhitespace, startOfOutputToken)
					startOfOutputToken++
				}
				l.emitToken(typ, startOfOutputToken)
				// Token emitters can emit a space after a token to avoid
				// possible merges with following tokens
				if typ != cssTokensTokenTypeWhitespace {
					sbLen := len(l.sb)
					if startOfOutputToken+1 < sbLen && l.sb[sbLen-1] == ' ' {
						l.emitToken(cssTokensTokenTypeWhitespace, sbLen-1)
					}
				}
			}
		}
	}
}

// charAt returns the code unit at i or 0 if i is past the end of the input.
func (l *cssTokensLexer) charAt(i int) uint16 {
	if i < len(l.css) {
		return l.css[i]
	}
	return 0
}

func (l *cssTokensLexer) emitMergedTokens(start, end int) {
	// Handle breakOutput and merging of output tokens.
	for e := start; e < end; e++ {
		var delimType cssTokensTokenType
		switch l.sb[e] {
		case ' ':
			delimType = cssTokensTokenTypeWhitespace
		case '}':
			delimType = cssTokensTokenTypeRightCurly
		case ')':
			delimType = cssTokensTokenTypeRightParen
		case ']':
			delimType = cssTokensTokenTypeRightSquare
		default:
			delimType = cssTokensTokenTypeDelim
		}
		l.emitToken(delimType, e)
	}
}

func (l *cssTokensLexer) emitToken(typ cssTokensTokenType, startOfOutputToken int) {
	n := len(l.tokenBreaks)
	if n == 0 || l.tokenBreaks[n-1] != startOfOutputToken {
		l.tokenBreaks = append(l.tokenBreaks, startOfOutputToken)
		l.tokenTypes = append(l.tokenTypes, typ)
	}
}

func (l *cssTokensLexer) consumeDelim(ch uint16) {
	l.sb = append(l.sb, ch)
	switch ch {
	// Prevent token merging.
	case '~', '|', '^', '$', '\\', '.', '+', '-', '@', '/', '<':
		l.sb = append(l.sb, ' ')
	}
	l.pos++
}

func (l *cssTokensLexer) consumeIgnorable() bool {
	css := l.css
	cssLimit := len(css)
	posBefore := l.pos
	for l.pos < cssLimit {
		ch := css[l.pos]
		if ch <= 0x20 ||
			// Treat a BOM as white-space so that it is ignored at the
			// beginning of a file.
			ch == 0xfeff {
			l.pos++
		} else if l.pos+1 == cssLimit {
			break
		} else if ch == '/' {
			next := css[l.pos+1]
			if next == '*' {
				l.pos += 2
				for l.pos < cssLimit {
					ast := cssIndexOfUnit(css, '*', l.pos)
					if ast < 0 {
						l.pos = cssLimit // Unclosed /* comment */
						break
					}
					// Advance over a run of '*'s.
					l.pos = ast + 1
					for l.pos < cssLimit && css[l.pos] == '*' {
						l.pos++
					}
					if l.pos < cssLimit && css[l.pos] == '/' {
						l.pos++
						break
					}
				}
			} else if next == '/' { // Non-standard but widely supported
				for l.pos++; l.pos < cssLimit; l.pos++ {
					if cssTokensIsLineTerminator(css[l.pos]) {
						break
					}
				}
			} else {
				break
			}
		} else if ch == '<' {
			if l.pos+3 < cssLimit &&
				'!' == css[l.pos+1] &&
				'-' == css[l.pos+2] &&
				'-' == css[l.pos+3] {
				l.pos += 4
			} else {
				break
			}
		} else if ch == '-' {
			if l.pos+2 < cssLimit &&
				'-' == css[l.pos+1] &&
				'>' == css[l.pos+2] {
				l.pos += 3
			} else {
				break
			}
		} else {
			break
		}
	}
	if l.pos == posBefore {
		return false
	}
	l.breakOutput()
	return true
}

func (l *cssTokensLexer) breakOutput() {
	last := len(l.sb) - 1
	if last >= 0 && l.sb[last] != ' ' {
		l.sb = append(l.sb, ' ')
	}
}

func (l *cssTokensLexer) consumeColumn() {
	l.pos += 2
	l.sb = append(l.sb, '|', '|')
}

func (l *cssTokensLexer) consumeMatch(ch uint16) {
	l.pos += 2
	l.sb = append(l.sb, ch, '=')
}

func (l *cssTokensLexer) consumeIdent(allowFirstDigit bool) {
	cssLimit := len(l.css)
	last, nCodepoints := -1, 0
	sbAtStart := len(l.sb)
	posAtStart := l.pos
	for l.pos < cssLimit {
		posBefore := l.pos

		decoded := l.readCodepoint()
		if decoded == '\\' {
			decoded = l.consumeAndDecodeEscapeSequence()
		} else {
			l.pos++
		}

		if decoded >= 0 && cssTokensIsIdentPart(decoded) {
			if !allowFirstDigit && nCodepoints < 2 &&
				'0' <= decoded && decoded <= '9' {
				// Don't allow encoded identifiers that look like numeric
				// tokens like \-1 or ones that start with an encoded decimal
				// digit.
				if last == '-' || last == -1 {
					l.pos = posAtStart
					l.sb = l.sb[:sbAtStart]
					return
				}
			}
			l.sb = cssAppendCodePoint(l.sb, decoded)
			last = decoded
			nCodepoints++
		} else {
			l.pos = posBefore
			return
		}
	}
}

func (l *cssTokensLexer) consumeAtKeyword() bool {
	bufferLengthBeforeWrite := len(l.sb)
	l.sb = append(l.sb, '@')
	l.pos++
	posBeforeKeyword := l.pos
	l.consumeIdent(false)
	if l.pos == posBeforeKeyword {
		l.pos--                               // back up over '@'
		l.sb = l.sb[:bufferLengthBeforeWrite] // Unwrite the '@'
		return false
	}
	return true
}

func (l *cssTokensLexer) consumeAndDecodeEscapeSequence() int {
	css := l.css
	cssLimit := len(css)
	if l.pos+1 >= cssLimit {
		return -1
	}
	esc := css[l.pos+1]
	if cssTokensIsLineTerminator(esc) {
		return -1
	}
	escLower := esc | 32
	if ('0' <= esc && esc <= '9') || ('a' <= escLower && escLower <= 'f') {
		hexValue := 0
		hexStart := l.pos + 1
		hexLimit := min(l.pos+7, cssLimit)
		hexEnd := hexStart
		for {
			if esc <= '9' {
				hexValue = (hexValue << 4) | int(esc-'0')
			} else {
				hexValue = (hexValue << 4) | int(escLower-('a'-10))
			}
			hexEnd++
			if hexEnd == hexLimit {
				break
			}
			esc = css[hexEnd]
			escLower = esc | 32
			if !(('0' <= esc && esc <= '9') || ('a' <= escLower && escLower <= 'f')) {
				break
			}
		}
		if !cssTokensIsDefined(hexValue) {
			hexValue = 0xfffd
		}
		l.pos = hexEnd
		if l.pos < cssLimit {
			// A sequence of hex digits can be followed by a space that allows
			// so that code-point U+A followed by the letter 'b' can be
			// rendered as "\a b" since "\ab" specifies the single code-point
			// U+AB.
			next := css[l.pos]
			if next == ' ' || next == '\t' || cssTokensIsLineTerminator(next) {
				l.pos++
			}
		}
		return hexValue
	}
	l.pos += 2
	return int(esc)
}

// cssTokensHexEncodedBitmask has a bit set for each code point that
// encodeCharOntoOutput writes as an escape ending in a hex digit.
const cssTokensHexEncodedBitmask = uint64(1)<<0 | cssTokensLineTerminatorBitmask |
	uint64(1)<<'"' | uint64(1)<<'\'' | uint64(1)<<'&' | uint64(1)<<'<' | uint64(1)<<'>'

func cssTokensIsHexEncoded(codepoint int) bool {
	return 0 <= codepoint && codepoint < 63 &&
		0 != (uint64(1)<<codepoint)&cssTokensHexEncodedBitmask
}

func (l *cssTokensLexer) encodeCharOntoOutput(codepoint, last int) {
	switch codepoint {
	case '\\':
		l.appendASCII(`\\`)
	case 0:
		l.appendASCII(`\0`)
	case '\n':
		l.appendASCII(`\a`)
	case '\f':
		l.appendASCII(`\c`)
	case '\r':
		l.appendASCII(`\d`)
	case '"':
		l.appendASCII(`\22`)
	case '&':
		l.appendASCII(`\26`)
	case '\'':
		l.appendASCII(`\27`)
	case '<':
		l.appendASCII(`\3c`)
	case '>':
		l.appendASCII(`\3e`)
	// The set of escapes above that end with a hex digit must appear in
	// cssTokensHexEncodedBitmask.
	case '-':
		l.sb = append(l.sb, '-')
	default:
		if cssTokensIsHexEncoded(last) &&
			// We need to put a space after a trailing hex digit if the next
			// encoded character on the output would be another hex digit or
			// a space character.  The other space characters are handled
			// above.
			(codepoint == ' ' || codepoint == '\t' ||
				('0' <= codepoint && codepoint <= '9') ||
				('a' <= (codepoint|32) && (codepoint|32) <= 'f')) {
			l.sb = append(l.sb, ' ')
		}
		l.sb = cssAppendCodePoint(l.sb, codepoint)
	}
}

// appendASCII appends an ASCII string to the output.
func (l *cssTokensLexer) appendASCII(s string) {
	for i := 0; i < len(s); i++ {
		l.sb = append(l.sb, uint16(s[i]))
	}
}

func (l *cssTokensLexer) consumeNumberOrPercentageOrDimension() cssTokensTokenType {
	css := l.css
	cssLimit := len(css)
	isZero := true
	intStart := l.pos
	if intStart < cssLimit {
		ch := css[intStart]
		if ch == '-' || ch == '+' {
			intStart++
		}
	}
	// Find the integer part after any sign.
	intEnd := intStart
	for ; intEnd < cssLimit; intEnd++ {
		ch := css[intEnd]
		if !('0' <= ch && ch <= '9') {
			break
		}
		if ch != '0' {
			isZero = false
		}
	}
	// Find a fraction like ".5" or ".".
	fractionStart := intEnd
	fractionEnd := fractionStart
	if fractionEnd < cssLimit && '.' == css[fractionEnd] {
		fractionEnd++
		for ; fractionEnd < cssLimit; fractionEnd++ {
			ch := css[fractionEnd]
			if !('0' <= ch && ch <= '9') {
				break
			}
			if ch != '0' {
				isZero = false
			}
		}
	}
	exponentStart := fractionEnd
	exponentIntStart := exponentStart
	exponentEnd := exponentStart
	isExponentZero := true
	if exponentStart < cssLimit && 'e' == (css[exponentStart]|32) {
		// 'e' and 'e' in "5e-f" for a
		exponentEnd = exponentStart + 1
		if exponentEnd < cssLimit {
			ch := css[exponentEnd]
			if ch == '+' || ch == '-' {
				exponentEnd++
			}
		}
		exponentIntStart = exponentEnd
		for ; exponentEnd < cssLimit; exponentEnd++ {
			ch := css[exponentEnd]
			if !('0' <= ch && ch <= '9') {
				break
			}
			if ch != '0' {
				isExponentZero = false
			}
		}
		// Since
		//    dimension := <number> <ident>
		// the below are technically valid dimensions even though they appear
		// to have incomplete exponents:
		//    5e
		//    5ex
		//    5e-
		if exponentEnd == exponentIntStart { // Incomplete exponent.
			exponentIntStart = exponentStart
			exponentEnd = exponentStart
			isExponentZero = true
		}
	}

	unitStart := exponentEnd
	// Skip over space between number and unit.
	// Many user-agents allow "5 ex" instead of "5ex".
	for unitStart < cssLimit {
		ch := css[unitStart]
		if ch == ' ' || cssTokensIsLineTerminator(ch) {
			unitStart++
		} else {
			break
		}
	}

	if len(l.sb) != 0 && cssTokensIsIdentPart(int(l.sb[len(l.sb)-1])) {
		l.sb = append(l.sb, ' ')
	}
	// Normalize the number onto the buffer.
	// We will normalize and unit later.
	// Skip the sign if it is positive.
	if intStart != l.pos && '-' == css[l.pos] && !isZero {
		l.sb = append(l.sb, '-')
	}
	if isZero {
		l.sb = append(l.sb, '0')
	} else {
		// Strip leading zeroes from the integer and exponent and trailing
		// zeroes from the fraction.
		for intStart < intEnd && css[intStart] == '0' {
			intStart++
		}
		for fractionEnd > fractionStart && css[fractionEnd-1] == '0' {
			fractionEnd--
		}
		if intStart == intEnd {
			l.sb = append(l.sb, '0') // .5 -> 0.5
		} else {
			l.sb = append(l.sb, css[intStart:intEnd]...)
		}
		if fractionEnd > fractionStart+1 { // 5. -> 5; 5.0 -> 5
			l.sb = append(l.sb, css[fractionStart:fractionEnd]...)
		}
		if !isExponentZero {
			l.sb = append(l.sb, 'e')
			// 1e+1 -> 1e1
			if '-' == css[exponentIntStart-1] {
				l.sb = append(l.sb, '-')
			}
			for exponentIntStart < exponentEnd && css[exponentIntStart] == '0' {
				exponentIntStart++
			}
			l.sb = append(l.sb, css[exponentIntStart:exponentEnd]...)
		}
	}

	var unitEnd int
	var typ cssTokensTokenType
	if unitStart < cssLimit && '%' == css[unitStart] {
		unitEnd = unitStart + 1
		typ = cssTokensTokenTypePercentage
		l.sb = append(l.sb, '%')
	} else {
		// The grammar says that any identifier following a number is a unit.
		bufferBeforeUnit := len(l.sb)
		l.pos = unitStart
		l.consumeIdent(false)
		bufferAfterUnit := len(l.sb)
		knownUnit := cssTokensIsWellKnownUnitUTF16(l.sb[bufferBeforeUnit:bufferAfterUnit])
		if unitStart == exponentEnd || // No intervening space
			knownUnit {
			unitEnd = l.pos
			// 3IN -> 3in
			for i := bufferBeforeUnit; i < bufferAfterUnit; i++ {
				ch := l.sb[i]
				if 'A' <= ch && ch <= 'Z' {
					l.sb[i] = ch | 32
				}
			}
		} else {
			unitStart = exponentEnd
			unitEnd = exponentEnd
			l.sb = l.sb[:bufferBeforeUnit]
		}
		switch {
		case unitStart == unitEnd:
			typ = cssTokensTokenTypeNumber
		case knownUnit:
			typ = cssTokensTokenTypeDimension
		default:
			typ = cssTokensTokenTypeBadDimension
		}
	}
	l.pos = unitEnd
	if typ != cssTokensTokenTypePercentage &&
		l.pos < cssLimit && css[l.pos] == '.' {
		l.sb = append(l.sb, ' ')
	}
	return typ
}

func (l *cssTokensLexer) consumeString() cssTokensTokenType {
	css := l.css
	cssLimit := len(css)

	delim := css[l.pos]
	l.pos++
	startOfStringOnOutput := len(l.sb)
	l.sb = append(l.sb, '\'')
	last := -1
	closed := false
	for l.pos < cssLimit {
		ch := css[l.pos]
		if ch == delim {
			l.pos++
			closed = true
			break
		}
		if cssTokensIsLineTerminator(ch) {
			break
		}
		decoded := int(ch)
		if ch == '\\' {
			if l.pos+1 < cssLimit && cssTokensIsLineTerminator(css[l.pos+1]) {
				// consume it but generate no tokens.
				// Lookahead to treat a \r\n sequence as one line-terminator.
				if l.pos+2 < cssLimit &&
					css[l.pos+1] == '\r' && css[l.pos+2] == '\n' {
					l.pos += 3
				} else {
					l.pos += 2
				}
				continue
			}
			decoded = l.consumeAndDecodeEscapeSequence()
			if decoded < 0 {
				break
			}
		} else {
			l.pos++
		}
		l.encodeCharOntoOutput(decoded, last)
		last = decoded
	}
	if closed {
		l.sb = append(l.sb, '\'')
		return cssTokensTokenTypeString
	}
	// Drop <bad-string>s
	l.sb = l.sb[:startOfStringOnOutput]
	l.breakOutput()
	return cssTokensTokenTypeWhitespace
}

// consumeHash consumes the identifier part of a hash token.  It reports
// false, leaving the position on the '#', if there is none.
func (l *cssTokensLexer) consumeHash() (cssTokensTokenType, bool) {
	l.pos++
	beforeIdent := l.pos
	l.consumeIdent(true)
	if l.pos == beforeIdent {
		l.pos = beforeIdent - 1
		return 0, false
	}
	for i := beforeIdent; i < l.pos; i++ {
		chLower := l.css[i] | 32
		if !(('0' <= chLower && chLower <= '9') ||
			('a' <= chLower && chLower <= 'f')) {
			return cssTokensTokenTypeHashId, true
		}
	}
	return cssTokensTokenTypeHashUnrestricted, true
}

// consumeUnicodeRange consumes a unicode range, restoring the position and
// the output if there is none.
func (l *cssTokensLexer) consumeUnicodeRange() (ok bool) {
	css := l.css
	cssLimit := len(css)

	start := l.pos
	startOfOutput := len(l.sb)
	defer func() {
		if !ok {
			l.pos = start
			l.sb = l.sb[:startOfOutput]
		}
	}()
	l.pos++
	if l.pos == cssLimit || css[l.pos] != '+' {
		return false
	}
	l.pos++
	l.appendASCII("U+")
	numStartDigits := 0
	for l.pos < cssLimit && numStartDigits < 6 {
		chLower := css[l.pos] | 32
		if ('0' <= chLower && chLower <= '9') ||
			('a' <= chLower && chLower <= 'f') {
			l.sb = append(l.sb, chLower)
			numStartDigits++
			l.pos++
		} else {
			break
		}
	}
	if numStartDigits == 0 {
		return false
	}
	hasQmark := false
	for l.pos < cssLimit && numStartDigits < 6 && css[l.pos] == '?' {
		hasQmark = true
		l.sb = append(l.sb, '?')
		numStartDigits++
		l.pos++
	}
	if l.pos < cssLimit && css[l.pos] == '-' {
		if !hasQmark {
			// Look for end of range.
			l.pos++
			startOfDash := len(l.sb)
			l.sb = append(l.sb, '-')
			numEndDigits := 0
			for l.pos < cssLimit && numEndDigits < 6 {
				chLower := css[l.pos] | 32
				if ('0' <= chLower && chLower <= '9') ||
					('a' <= chLower && chLower <= 'f') {
					numEndDigits++
					l.pos++
					l.sb = append(l.sb, chLower)
				} else {
					break
				}
			}
			if numEndDigits == 0 {
				// Not a range after all.  Back up over the '-' so it is
				// lexed as its own token, and drop it from the output as
				// well, so that it is not emitted twice.  Emitting it as part
				// of the range meant "U+a-x" normalized to "U+a- -x", which
				// is not idempotent (issue #245).  A trailing space keeps the
				// range from merging with whatever follows.
				l.pos--
				l.sb = l.sb[:startOfDash]
				l.sb = append(l.sb, ' ')
			}
		} else {
			l.sb = append(l.sb, ' ')
		}
	}
	return true
}

// consumeIdentOrURLOrFunction reports false if there is no identifier at
// the current position.
func (l *cssTokensLexer) consumeIdentOrURLOrFunction() (cssTokensTokenType, bool) {
	cssLimit := len(l.css)
	bufferStart := len(l.sb)
	posBefore := l.pos
	l.consumeIdent(false)
	if l.pos == posBefore {
		return 0, false
	}
	parenAfter := l.pos < cssLimit && l.css[l.pos] == '('
	if len(l.sb)-bufferStart == 3 &&
		'u' == (l.sb[bufferStart]|32) &&
		'r' == (l.sb[bufferStart+1]|32) &&
		'l' == (l.sb[bufferStart+2]|32) {
		if parenAfter && l.consumeURLValue() {
			l.sb[bufferStart] = 'u'
			l.sb[bufferStart+1] = 'r'
			l.sb[bufferStart+2] = 'l'
			return cssTokensTokenTypeURL, true
		}
		l.sb = l.sb[:bufferStart]
		l.breakOutput()
		return cssTokensTokenTypeWhitespace, true
	} else if parenAfter {
		l.openBracket('(')
		l.pos++
		return cssTokensTokenTypeFunction, true
	}
	if l.pos+1 < cssLimit && '.' == l.css[l.pos] {
		// Prevent merging of ident and number as in
		//     border:solid.1cm black
		// when .1 is rewritten to 0.1 becoming
		//     border:solid0.1cm black
		next := l.css[l.pos+1]
		if '0' <= next && next <= '9' {
			l.sb = append(l.sb, ' ')
		}
	}
	return cssTokensTokenTypeIdent, true
}

func (l *cssTokensLexer) consumeURLValue() bool {
	css := l.css
	cssLimit := len(css)
	if l.pos == cssLimit || css[l.pos] != '(' {
		return false
	}
	l.pos++
	// skip space.
	for ; l.pos < cssLimit; l.pos++ {
		ch := css[l.pos]
		if ch != ' ' && !cssTokensIsLineTerminator(ch) {
			break
		}
	}
	// Find the value.
	if l.pos >= cssLimit {
		return false
	}
	var delim int
	if ch := css[l.pos]; ch == '"' || ch == '\'' {
		delim = int(ch)
		l.pos++
	}
	l.appendASCII("('")
	for l.pos < cssLimit {
		decoded := l.readCodepoint()
		if delim != 0 {
			if decoded == delim {
				l.pos++
				break
			}
		} else if decoded <= ' ' || decoded == ')' {
			break
		}
		if decoded == '\\' {
			decoded = l.consumeAndDecodeEscapeSequence()
			if decoded < 0 {
				return false
			}
		} else {
			l.pos++
		}
		// Any character not in the RFC 3986 safe set is %-encoded.
		switch {
		case decoded < len(cssTokensURLSafe) && cssTokensURLSafe[decoded]:
			l.sb = cssAppendCodePoint(l.sb, decoded)
		case decoded < 0x80:
			l.appendPercentEncoded(decoded)
		case decoded < 0x800:
			l.appendPercentEncoded(0xc0 | ((decoded >> 6) & 0x1f))
			l.appendPercentEncoded(0x80 | (decoded & 0x3f))
		case decoded < 0x10000:
			l.appendPercentEncoded(0xe0 | ((decoded >> 12) & 0xf))
			l.appendPercentEncoded(0x80 | ((decoded >> 6) & 0x3f))
			l.appendPercentEncoded(0x80 | (decoded & 0x3f))
		default:
			l.appendPercentEncoded(0xf0 | ((decoded >> 18) & 0x7))
			l.appendPercentEncoded(0x80 | ((decoded >> 12) & 0x3f))
			l.appendPercentEncoded(0x80 | ((decoded >> 6) & 0x3f))
			l.appendPercentEncoded(0x80 | (decoded & 0x3f))
		}
	}

	// skip space.
	for ; l.pos < cssLimit; l.pos++ {
		ch := css[l.pos]
		if ch != ' ' && !cssTokensIsLineTerminator(ch) {
			break
		}
	}
	if l.pos < cssLimit && css[l.pos] == ')' {
		l.pos++
	} // else broken-url
	l.appendASCII("')")
	return true
}

// appendPercentEncoded appends an octet as %xx.
func (l *cssTokensLexer) appendPercentEncoded(octet int) {
	l.sb = append(l.sb, '%',
		uint16(cssTokensHexDigits[(octet>>4)&0xf]),
		uint16(cssTokensHexDigits[octet&0xf]))
}

// readCodepoint reads the codepoint at pos, leaving pos at the index of the
// last code unit.
func (l *cssTokensLexer) readCodepoint() int {
	ch := l.css[l.pos]
	if isHighSurrogate(rune(ch)) && l.pos+1 < len(l.css) {
		next := l.css[l.pos+1]
		if isLowSurrogate(rune(next)) {
			l.pos++
			return int(combineSurrogates(rune(ch), rune(next)))
		}
	}
	return int(ch)
}

func cssTokensIsIdentPart(cp int) bool {
	if cp >= 0x80 {
		return cssTokensIsDefined(cp) && cp != 0xfeff
	}
	return cssTokensIdentPartASCII[cp]
}

// cssTokensIsDefined reports whether Unicode assigns cp a general category
// other than unassigned (Cn); surrogates and private use code points count as
// assigned.
func cssTokensIsDefined(cp int) bool {
	if cp < 0 || cp > unicode.MaxRune {
		return false
	}
	if 0xd800 <= cp && cp <= 0xdfff {
		return true
	}
	return unicode.In(rune(cp), unicode.L, unicode.M, unicode.N, unicode.P,
		unicode.S, unicode.Z, unicode.C)
}

func cssTokensIsDecimal(ch uint16) bool {
	return '0' <= ch && ch <= '9'
}

var cssTokensIdentPartASCII = func() (t [128]bool) {
	for i := '0'; i <= '9'; i++ {
		t[i] = true
	}
	for i := 'A'; i <= 'Z'; i++ {
		t[i] = true
	}
	for i := 'a'; i <= 'z'; i++ {
		t[i] = true
	}
	t['_'] = true
	t['-'] = true
	return t
}()

const cssTokensLineTerminatorBitmask = 1<<'\n' | 1<<'\r' | 1<<'\f'

func cssTokensIsLineTerminator(ch uint16) bool {
	return ch < 0x20 && 0 != cssTokensLineTerminatorBitmask&(1<<ch)
}

// Unit types, by the kind of quantity a unit measures.
const (
	cssTokensLengthUnitType = iota
	cssTokensAngleUnitType
	cssTokensTimeUnitType
	cssTokensFrequencyUnitType
	cssTokensResolutionUnitType
)

// cssTokensUnitTrie maps the units the lexer knows to their unit types.
// See http://dev.w3.org/csswg/css-values/#lengths and
// http://dev.w3.org/csswg/css-values/#other-units
var cssTokensUnitTrie = map[string]int{
	"em":   cssTokensLengthUnitType,
	"ex":   cssTokensLengthUnitType,
	"ch":   cssTokensLengthUnitType, // Width of zero character
	"rem":  cssTokensLengthUnitType, // Root element font-size
	"vh":   cssTokensLengthUnitType,
	"vw":   cssTokensLengthUnitType,
	"vmin": cssTokensLengthUnitType,
	"vmax": cssTokensLengthUnitType,
	// Grid track flex factor.  Only meaningful in grid-template-* values,
	// which are not in DEFAULT, but the lexer has to recognize the unit for a
	// policy that opts into grid to see "1fr" at all.
	"fr":   cssTokensLengthUnitType,
	"px":   cssTokensLengthUnitType,
	"mm":   cssTokensLengthUnitType,
	"cm":   cssTokensLengthUnitType,
	"in":   cssTokensLengthUnitType,
	"pt":   cssTokensLengthUnitType,
	"pc":   cssTokensLengthUnitType,
	"deg":  cssTokensAngleUnitType,
	"rad":  cssTokensAngleUnitType,
	"grad": cssTokensAngleUnitType,
	"turn": cssTokensAngleUnitType,
	"s":    cssTokensTimeUnitType,
	"ms":   cssTokensTimeUnitType,
	"hz":   cssTokensFrequencyUnitType,
	"khz":  cssTokensFrequencyUnitType,
	"dpi":  cssTokensResolutionUnitType,
	"dpcm": cssTokensResolutionUnitType,
	"dppx": cssTokensResolutionUnitType,
}

// cssTokensIsWellKnownUnit reports whether s, ignoring the case of ASCII
// letters, is a unit the lexer knows.
func cssTokensIsWellKnownUnit(s string) bool {
	if s == "" {
		return false
	}
	_, ok := cssTokensUnitTrie[stringsToLowerCase(s)]
	return ok
}

// cssTokensIsWellKnownUnitUTF16 is cssTokensIsWellKnownUnit for a run of
// lexer output.
func cssTokensIsWellKnownUnitUTF16(s []uint16) bool {
	const longestUnit = 4
	if len(s) == 0 || len(s) > longestUnit {
		return false
	}
	var buf [longestUnit]byte
	for i, ch := range s {
		if ch >= 0x80 {
			return false
		}
		buf[i] = byte(ch)
	}
	return cssTokensIsWellKnownUnit(string(buf[:len(s)]))
}

// cssTokensURLSafe marks the ASCII characters that a url(...) token keeps
// as they are.
var cssTokensURLSafe = func() (t [128]bool) {
	// From RFC 3986
	// unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
	for i := 'A'; i <= 'Z'; i++ {
		t[i] = true
	}
	for i := 'a'; i <= 'z'; i++ {
		t[i] = true
	}
	for i := '0'; i <= '9'; i++ {
		t[i] = true
	}
	t['-'] = true
	t['.'] = true
	t['_'] = true
	t['~'] = true
	// gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@"
	t[':'] = true
	t['/'] = true
	t['?'] = true
	t['#'] = true
	t['['] = true
	t[']'] = true
	t['@'] = true
	// sub-delims  = "!" / "$" / "&" / "'" / "(" / ")"
	//             / "*" / "+" / "," / ";" / "="
	// The quote, the parentheses and the asterisk are left out: they are
	// only used in the obsolete mark rule and are special in unquoted URLs
	// or comment delimiters.
	t['!'] = true
	t['$'] = true
	t['&'] = true
	t['+'] = true
	t[','] = true
	t[';'] = true
	t['='] = true
	// % is used to encode unsafe octets.
	t['%'] = true
	return t
}()

const cssTokensHexDigits = "0123456789abcdef"

// cssIndexOfUnit returns the index of the first ch in s at or after from,
// or -1.
func cssIndexOfUnit(s []uint16, ch uint16, from int) int {
	for i := from; i < len(s); i++ {
		if s[i] == ch {
			return i
		}
	}
	return -1
}

// cssAppendCodePoint appends the UTF-16 encoding of a code point, one code
// unit or a surrogate pair, to units.
func cssAppendCodePoint(units []uint16, cp int) []uint16 {
	if cp >= 0x10000 {
		cp -= 0x10000
		return append(units, 0xd800+uint16(cp>>10), 0xdc00+uint16(cp&0x3ff))
	}
	return append(units, uint16(cp))
}
