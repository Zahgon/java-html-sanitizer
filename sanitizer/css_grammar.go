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
// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/CssGrammar.java.

package sanitizer

// cssGrammarMaxFunctionDepth is the deepest a declaration's value may nest
// functions before the declaration is dropped without being parsed.
//
// cssGrammarParsePropertyValue recurses once per function, so a value that
// nests functions without bound would use stack without bound.  Nothing in
// CSSSchema has a use for anything like this depth: a colour function inside
// a gradient, or a calc() inside a transform, nests two or three levels.
const cssGrammarMaxFunctionDepth = 16

func cssGrammarErrorRecoveryUntilSemiOrCloseBracket(it *cssTokensTokenIterator) {
	bracketDepth := 0
	for ; it.hasNext(); it.advance() {
		switch it.tokenType() {
		case cssTokensTokenTypeSemicolon:
			it.advance()
			return
		case cssTokensTokenTypeLeftCurly, cssTokensTokenTypeLeftParen,
			cssTokensTokenTypeLeftSquare:
			bracketDepth++
		case cssTokensTokenTypeRightCurly, cssTokensTokenTypeRightParen,
			cssTokensTokenTypeRightSquare:
			bracketDepth--
			if bracketDepth <= 0 {
				if bracketDepth != 0 {
					it.advance()
				}
				return
			}
		}
	}
}

// cssGrammarParsePropertyGroup parses a run of CSS declarations as found in
// a style attribute, reporting them to handler.
func cssGrammarParsePropertyGroup(css string, handler cssGrammarPropertyHandler) {
	// Split tokens by semicolons/curly-braces, then by first colon,
	// dropping spaces and comments to identify property names and token runs
	// that form the value.

	tokens := cssTokensLex(css)
	it := tokens.iterator()
	for it.hasTokenAfterSpace() {
		// Check that we have an identifier that might be a property name.
		if it.tokenType() != cssTokensTokenTypeIdent {
			cssGrammarErrorRecoveryUntilSemiOrCloseBracket(it)
			continue
		}

		name := it.next()

		// Look for a colon.
		if !(it.hasTokenAfterSpace() && it.token() == ":") {
			cssGrammarErrorRecoveryUntilSemiOrCloseBracket(it)
			continue
		}
		it.advance()

		if cssGrammarSkipIfNestedTooDeeply(it) {
			continue
		}

		handler.startProperty(stringsToLowerCase(name))
		cssGrammarParsePropertyValue(it, handler)
		handler.endProperty()
	}
}

// cssGrammarSkipIfNestedTooDeeply moves the iterator past the end of the
// declaration and returns true if the value at the iterator's position nests
// functions deeper than cssGrammarMaxFunctionDepth, so the handler never
// hears of it.  Otherwise it leaves the iterator where it was and returns
// false.
//
// The declaration ends where cssGrammarParsePropertyValue would stop: at the
// first semicolon that is inside no function, or at the end of the input.  A
// semicolon inside a function ends only that function's arguments, and one
// inside a bare bracket ends the declaration.  Stopping exactly there
// matters: stopping later and seeking back would read the same tokens again
// for the next declaration, and again for the one after, which is quadratic.
// Within a function, the value parse reads nothing after a semicolon, while
// this scan still counts the functions there, so a declaration can be dropped
// for nesting the parse would never have reached.  That can lose valid CSS:
// if() separates its branches with semicolons, and a declaration such as
// "margin: 1px if(media(print): 2px; else: calc(...))" is dropped whole, 1px
// and all, once its later branch nests deep enough to pass the limit.  The
// loss is conservative, dropping what could have been kept, and only a value
// nested that deeply is affected.
//
// The lexer pairs every bracket, closing what the input left open and
// dropping what it never opened, so a close bracket here always closes the
// innermost open one.  functionAt records, per depth, whether that open
// bracket is a function, so every open and close costs constant time however
// deep the value goes.  A close bracket with no open partner in this value is
// left over from an earlier declaration that ended inside it, and is ignored,
// as the value parse ignores it.
//
// Every function the value parse recurses into lies in this range and is
// counted here, so the recursion that follows goes no more than
// cssGrammarMaxFunctionDepth frames deep, however long the input.
func cssGrammarSkipIfNestedTooDeeply(it *cssTokensTokenIterator) bool {
	start := it.tokenIndex()
	functionAt := make([]bool, 0, 16)
	functionDepth := 0
	tooDeep := false
declaration:
	for it.hasNext() {
		typ := it.tokenType()
		it.advance()
		switch typ {
		case cssTokensTokenTypeSemicolon:
			if functionDepth == 0 {
				break declaration
			}
		case cssTokensTokenTypeFunction, cssTokensTokenTypeLeftCurly,
			cssTokensTokenTypeLeftParen, cssTokensTokenTypeLeftSquare:
			isFunction := typ == cssTokensTokenTypeFunction
			functionAt = append(functionAt, isFunction)
			if isFunction {
				functionDepth++
				if functionDepth > cssGrammarMaxFunctionDepth {
					tooDeep = true
				}
			}
		case cssTokensTokenTypeRightCurly, cssTokensTokenTypeRightParen,
			cssTokensTokenTypeRightSquare:
			if depth := len(functionAt); depth != 0 {
				if functionAt[depth-1] {
					functionDepth--
				}
				functionAt = functionAt[:depth-1]
			}
		}
	}
	if !tooDeep {
		it.seek(start)
	}
	return tooDeep
}

func cssGrammarParsePropertyValue(it *cssTokensTokenIterator, handler cssGrammarPropertyHandler) {
propertyValueLoop:
	for it.hasNext() {
		typ := it.tokenType()
		token := it.token()
		switch typ {
		case cssTokensTokenTypeSemicolon:
			it.advance()
			break propertyValueLoop
		case cssTokensTokenTypeFunction:
			actuals := it.spliceToEnd()
			handler.startFunction(token)
			cssGrammarParsePropertyValue(actuals, handler)
			handler.endFunction(token)
			continue // Skip the advance over token.
		case cssTokensTokenTypeIdent:
			handler.identifier(token)
		case cssTokensTokenTypeHashUnrestricted:
			if len(token) == 4 || len(token) == 7 {
				handler.hash(token)
			}
		case cssTokensTokenTypeString:
			handler.quotedString(token)
		case cssTokensTokenTypeURL:
			handler.url(token)
		case cssTokensTokenTypeDimension, cssTokensTokenTypeNumber,
			cssTokensTokenTypePercentage:
			handler.quantity(token)
		case cssTokensTokenTypeAt, cssTokensTokenTypeBadDimension,
			cssTokensTokenTypeColumn, cssTokensTokenTypeDotIdent,
			cssTokensTokenTypeHashId, cssTokensTokenTypeMatch,
			cssTokensTokenTypeUnicodeRange, cssTokensTokenTypeWhitespace:
		case cssTokensTokenTypeLeftCurly, cssTokensTokenTypeLeftParen,
			cssTokensTokenTypeLeftSquare, cssTokensTokenTypeRightCurly,
			cssTokensTokenTypeRightParen, cssTokensTokenTypeRightSquare,
			cssTokensTokenTypeComma, cssTokensTokenTypeColon,
			cssTokensTokenTypeDelim:
			handler.punctuation(token)
		}
		it.advance()
	}
}

// cssGrammarCSSContent decodes any escape sequences and strips any quotes
// from the input.
//
// It works on UTF-16 code units.  A trailing backslash is kept, and an escape
// naming a code point past U+10FFFF decodes as U+FFFD; the lexer never
// produces a token with either.
func cssGrammarCSSContent(token string) string {
	units := utf16Units(token)
	n := len(units)
	pos := 0
	var sb []uint16
	decoded := false
	if n >= 2 {
		ch0 := units[0]
		if ch0 == '"' || ch0 == '\'' {
			if ch0 == units[n-1] {
				pos = 1
				n--
				decoded = true
			}
		}
	}
	for {
		esc := cssIndexOfUnit(units, '\\', pos)
		if esc < 0 {
			break
		}
		end := esc + 2
		if esc > n || end > len(units) {
			break
		}
		decoded = true
		sb = append(sb, units[pos:esc]...)
		codepoint := int(units[end-1])
		if cssGrammarIsHex(codepoint) {
			// Parse \hhhhh<opt-break> where hhhhh is one or more hex digits
			// and <opt-break> is an optional space or tab character that can
			// be used to separate an escape sequence from a following literal
			// hex digit.
			for end < n && cssGrammarIsHex(int(units[end])) {
				end++
			}
			codepoint = cssGrammarParseHex(units[esc+1 : end])
			if end < n {
				ch := units[end]
				if ch == ' ' || ch == '\t' { // Ignorable hex follower.
					end++
				}
			}
		}
		sb = cssAppendCodePoint(sb, codepoint)
		pos = end
	}
	if !decoded {
		return token
	}
	if pos < n {
		sb = append(sb, units[pos:n]...)
	}
	return fromUTF16Units(sb)
}

// cssGrammarParseHex returns the value of the hex digits, or U+FFFD, the
// unknown code point, if the value is past U+10FFFF.
func cssGrammarParseHex(digits []uint16) int {
	value := 0
	for _, ch := range digits {
		var digit int
		switch {
		case '0' <= ch && ch <= '9':
			digit = int(ch - '0')
		case 'a' <= ch && ch <= 'f':
			digit = int(ch-'a') + 10
		default:
			digit = int(ch-'A') + 10
		}
		value = value<<4 | digit
		if value > 0x10ffff {
			return 0xfffd // Unknown codepoint.
		}
	}
	return value
}

func cssGrammarIsHex(codepoint int) bool {
	return ('0' <= codepoint && codepoint <= '9') ||
		('A' <= codepoint && codepoint <= 'F') ||
		('a' <= codepoint && codepoint <= 'f')
}

// cssGrammarPropertyHandler receives the parts of the declarations that
// cssGrammarParsePropertyGroup finds.
type cssGrammarPropertyHandler interface {
	startProperty(propertyName string)
	quantity(token string)
	identifier(token string)
	hash(token string)
	quotedString(token string)
	url(token string)
	punctuation(token string)
	startFunction(token string)
	endFunction(token string)
	endProperty()
}
