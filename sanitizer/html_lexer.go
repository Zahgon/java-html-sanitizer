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

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/HtmlLexer.java.

package sanitizer

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// htmlLexer is a flexible lexer for HTML.
// This is hairy code, but it is outside the TCB for the HTML sanitizer.
//
// Token offsets are byte offsets into the input.  An htmlLexer is not safe
// for concurrent use.
type htmlLexer struct {
	lazyTokenStream
	input    string
	splitter *htmlInputSplitter
	state    htmlLexerState
	// lookahead holds tokens read from the splitter but not yet consumed.
	lookahead []htmlToken
}

// newHTMLLexer returns a lexer for input.
func newHTMLLexer(input string) *htmlLexer {
	l := &htmlLexer{
		input:    input,
		splitter: newHTMLInputSplitter(input),
		state:    htmlLexerStateOutsideTag,
	}
	l.lazyTokenStream.produce = l.produce
	return l
}

// cancelPendingLiteralContent cancels the literal-content mode tentatively
// selected from a start tag's name.  The tree-construction context can show
// that an HTML raw-text or RCDATA name actually denotes a foreign element,
// where those tokenizer modes do not apply.
func (l *htmlLexer) cancelPendingLiteralContent() {
	l.splitter.cancelPendingLiteralContent()
}

// htmlLexerCanonicalElementName normalizes the case of names that are not
// name-spaced.  This lower-cases HTML element names, but not ones for
// embedded SVG or MathML.
func htmlLexerCanonicalElementName(elementName string) string {
	if strings.IndexByte(elementName, ':') >= 0 {
		return elementName
	}
	if _, ok := htmlLexerMixedCaseForeignElementNames[elementName]; ok {
		return elementName
	}
	return stringsToLowerCase(elementName)
}

// htmlLexerCanonicalAttributeName normalizes the case of names that are not
// name-spaced.  This lower-cases HTML attribute names, but not ones for
// embedded SVG or MathML.
func htmlLexerCanonicalAttributeName(attribName string) string {
	if strings.IndexByte(attribName, ':') >= 0 {
		return attribName
	}
	if _, ok := htmlLexerMixedCaseForeignAttributeNames[attribName]; ok {
		return attribName
	}
	return stringsToLowerCase(attribName)
}

// htmlLexerCanonicalKeywordAttributeValue normalizes the case of keywords in
// attribute values.
func htmlLexerCanonicalKeywordAttributeValue(keywordValue string) string {
	return stringsToLowerCase(keywordValue)
}

// htmlLexerState is the state of an FSM that lets us reclassify text tokens
// inside tags as attribute names/values.
type htmlLexerState int

const (
	htmlLexerStateOutsideTag htmlLexerState = iota
	htmlLexerStateInTag
	htmlLexerStateSawName
	htmlLexerStateSawEq
)

// produce returns the next token, if one is available.  This may require
// fetching and combining multiple tokens from the underlying splitter.
func (l *htmlLexer) produce() (htmlToken, bool) {
	for {
		token, ok := l.readToken()
		if !ok {
			return htmlToken{}, false
		}

		switch token.typ {
		// Keep track of whether we're inside a tag or not.
		case htmlTokenTypeTagbegin:
			l.state = htmlLexerStateInTag
		case htmlTokenTypeTagend:
			if l.state == htmlLexerStateSawEq {
				// Distinguish <input type=checkbox checked=> from
				// <input type=checkbox checked>
				l.pushbackToken(token)
				l.state = htmlLexerStateInTag
				return htmlTokenInstance(
					token.start, token.start, htmlTokenTypeAttrvalue), true
			}

			l.state = htmlLexerStateOutsideTag

		// Drop ignorable tokens by reading the next one.
		case htmlTokenTypeIgnorable:
			continue

		// Collapse adjacent text nodes if we're outside a tag, or otherwise,
		// recognize attribute names and values.
		default:
			switch l.state {
			case htmlLexerStateOutsideTag:
				if token.typ == htmlTokenTypeText ||
					token.typ == htmlTokenTypeUnescaped {
					token = l.collapseSubsequent(token)
				}
			case htmlLexerStateInTag:
				if token.typ == htmlTokenTypeText &&
					!token.tokenInContextMatches(l.input, "=") {
					// Reclassify as attribute name
					token = htmlInputSplitterReclassify(
						token, htmlTokenTypeAttrname)
					l.state = htmlLexerStateSawName
				}
			case htmlLexerStateSawName:
				if token.typ == htmlTokenTypeText {
					if token.tokenInContextMatches(l.input, "=") {
						l.state = htmlLexerStateSawEq
						// Skip the '=' token
						continue
					}
					// Reclassify as attribute name
					token = htmlInputSplitterReclassify(
						token, htmlTokenTypeAttrname)
				} else {
					l.state = htmlLexerStateInTag
				}
			case htmlLexerStateSawEq:
				if token.typ == htmlTokenTypeText ||
					token.typ == htmlTokenTypeQstring {
					if token.typ == htmlTokenTypeText {
						// Collapse adjacent text nodes to properly handle
						//   <a onclick=this.clicked=true>
						//   <a title=foo bar>
						token = l.collapseAttributeName(token)
					}
					// Reclassify as value
					token = htmlInputSplitterReclassify(
						token, htmlTokenTypeAttrvalue)
					l.state = htmlLexerStateInTag
				}
			}
		}

		return token, true
	}
}

// collapseSubsequent collapses all the following tokens of the same type
// into token.
func (l *htmlLexer) collapseSubsequent(token htmlToken) htmlToken {
	collapsed := token
	for {
		next, ok := l.peekToken(0)
		if !ok || next.typ != token.typ {
			return collapsed
		}
		collapsed = htmlLexerJoin(collapsed, next)
		l.readToken()
	}
}

// collapseAttributeName collapses into an unquoted attribute value the
// tokens after it that are not parts of an attribute name.
func (l *htmlLexer) collapseAttributeName(token htmlToken) htmlToken {
	// We want to collapse tokens into the value that are not parts of an
	// attribute value.  We should include any space or text adjacent to the
	// value, but should stop at any of the following constructions:
	//   space end-of-file              e.g. name=foo_
	//   space valueless-attrib-name    e.g. name=foo checked
	//   space tag-end                  e.g. name=foo />
	//   space text space? '='          e.g. name=foo bar=
	nToMerge := 0
	for {
		t, ok := l.peekToken(nToMerge)
		if !ok {
			break
		}
		if t.typ == htmlTokenTypeIgnorable {
			tok, ok := l.peekToken(nToMerge + 1)
			if !ok || tok.typ != htmlTokenTypeText {
				break
			}
			if htmlLexerIsValuelessAttribute(l.input[tok.start:tok.end]) {
				break
			}
			eq, ok := l.peekToken(nToMerge + 2)
			if ok && eq.typ == htmlTokenTypeIgnorable {
				eq, ok = l.peekToken(nToMerge + 3)
			}
			if !ok || eq.tokenInContextMatches(l.input, "=") {
				break
			}
		} else if t.typ != htmlTokenTypeText {
			break
		}
		nToMerge++
	}
	if nToMerge == 0 {
		return token
	}

	end := token.end
	for ; nToMerge > 0; nToMerge-- {
		t, _ := l.readToken()
		end = t.end
	}

	return htmlTokenInstance(token.start, end, htmlTokenTypeText)
}

// htmlLexerJoin returns a token of a's type spanning a and b.
func htmlLexerJoin(a, b htmlToken) htmlToken {
	return htmlTokenInstance(a.start, b.end, a.typ)
}

// readToken consumes and returns the next token from the lookahead or the
// splitter.
func (l *htmlLexer) readToken() (htmlToken, bool) {
	if len(l.lookahead) != 0 {
		t := l.lookahead[0]
		l.lookahead = l.lookahead[1:]
		return t, true
	}
	if l.splitter.hasNext() {
		return l.splitter.next(), true
	}
	return htmlToken{}, false
}

// peekToken returns the i-th token after the current one without consuming
// it.
func (l *htmlLexer) peekToken(i int) (htmlToken, bool) {
	for len(l.lookahead) <= i && l.splitter.hasNext() {
		l.lookahead = append(l.lookahead, l.splitter.next())
	}
	if len(l.lookahead) > i {
		return l.lookahead[i], true
	}
	return htmlToken{}, false
}

// pushbackToken makes token the next one readToken returns.
func (l *htmlLexer) pushbackToken(token htmlToken) {
	l.lookahead = append([]htmlToken{token}, l.lookahead...)
}

// htmlLexerIsValuelessAttribute reports whether the attribute can appear in
// HTML without a value.
func htmlLexerIsValuelessAttribute(attribName string) bool {
	_, ok := htmlLexerValuelessAttribNames[htmlLexerCanonicalAttributeName(attribName)]
	return ok
}

// htmlLexerValuelessAttribNames are the attributes that may appear without a
// value, from http://issues.apache.org/jira/browse/XALANC-519
var htmlLexerValuelessAttribNames = htmlLexerSetOf(
	"checked", "compact", "declare", "defer", "disabled",
	"ismap", "multiple", "nohref", "noresize", "noshade",
	"nowrap", "readonly", "selected")

// htmlLexerMixedCaseForeignAttributeNames are the SVG and MathML attribute
// names that are not lower-cased.
var htmlLexerMixedCaseForeignAttributeNames = htmlLexerSetOf(
	"attributeName",
	"attributeType",
	"baseFrequency",
	"baseProfile",
	"calcMode",
	"clipPathUnits",
	"contentScriptType",
	"defaultAction",
	"definitionURL",
	"diffuseConstant",
	"edgeMode",
	"externalResourcesRequired",
	"filterUnits",
	"focusHighlight",
	"gradientTransform",
	"gradientUnits",
	"initialVisibility",
	"kernelMatrix",
	"kernelUnitLength",
	"keyPoints",
	"keySplines",
	"keyTimes",
	"lengthAdjust",
	"limitingConeAngle",
	"markerHeight",
	"markerUnits",
	"markerWidth",
	"maskContentUnits",
	"maskUnits",
	"mediaCharacterEncoding",
	"mediaContentEncodings",
	"mediaSize",
	"mediaTime",
	"numOctaves",
	"pathLength",
	"patternContentUnits",
	"patternTransform",
	"patternUnits",
	"playbackOrder",
	"pointsAtX",
	"pointsAtY",
	"pointsAtZ",
	"preserveAlpha",
	"preserveAspectRatio",
	"primitiveUnits",
	"refX",
	"refY",
	"repeatCount",
	"repeatDur",
	"requiredExtensions",
	"requiredFeatures",
	"requiredFonts",
	"requiredFormats",
	"schemaLocation",
	"snapshotTime",
	"specularConstant",
	"specularExponent",
	"spreadMethod",
	"startOffset",
	"stdDeviation",
	"stitchTiles",
	"surfaceScale",
	"syncBehavior",
	"syncBehaviorDefault",
	"syncMaster",
	"syncTolerance",
	"syncToleranceDefault",
	"systemLanguage",
	"tableValues",
	"targetX",
	"targetY",
	"textLength",
	"timelineBegin",
	"transformBehavior",
	"viewBox",
	"xChannelSelector",
	"yChannelSelector",
	"zoomAndPan",
)

// htmlLexerMixedCaseForeignElementNames are the SVG and MathML element names
// that are not lower-cased.
var htmlLexerMixedCaseForeignElementNames = htmlLexerSetOf(
	"animateColor",
	"animateMotion",
	"animateTransform",
	"clipPath",
	"feBlend",
	"feColorMatrix",
	"feComponentTransfer",
	"feComposite",
	"feConvolveMatrix",
	"feDiffuseLighting",
	"feDisplacementMap",
	"feDistantLight",
	"feDropShadow",
	"feFlood",
	"feFuncA",
	"feFuncB",
	"feFuncG",
	"feFuncR",
	"feGaussianBlur",
	"feImage",
	"feMerge",
	"feMergeNode",
	"feMorphology",
	"feOffset",
	"fePointLight",
	"feSpecularLighting",
	"feSpotLight",
	"feTile",
	"feTurbulence",
	"foreignObject",
	"linearGradient",
	"radialGradient",
	"solidColor",
	"textArea",
	"textPath",
)

// htmlLexerSetOf returns the set of the given names.
func htmlLexerSetOf(names ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(names))
	for _, name := range names {
		set[name] = struct{}{}
	}
	return set
}

// htmlInputSplitter is a token stream that breaks a character stream into
// htmlTokenType{Text,Tagbegin,Tagend,Directive,Comment,Qmarkmeta,...}
// tokens.  The matching of attribute names and values is done in a later
// step.
type htmlInputSplitter struct {
	lazyTokenStream
	// input is the source of HTML character data.
	input string
	// offset is a byte offset into input.
	offset int
	// inTag is true iff the current character is inside a tag.
	inTag bool
	// inEscapeExemptBlock is true if inside a script, xmp, listing, or
	// similar tag whose content does not follow the normal escaping rules.
	inEscapeExemptBlock bool
	// escapeExemptTagName is empty or the name of the close tag required to
	// end the current escape exempt block.  Preformatted tags include
	// <script>, <xmp>, etc. that may contain unescaped HTML input.
	escapeExemptTagName string
	// textEscapingMode is the mode of escapeExemptTagName's content, and is
	// only meaningful while escapeExemptTagName is not empty.
	textEscapingMode HTMLTextEscapingMode
	tagBodyState     htmlInputSplitterTagBodyState
}

// newHTMLInputSplitter returns a splitter for input.
func newHTMLInputSplitter(input string) *htmlInputSplitter {
	s := &htmlInputSplitter{input: input}
	s.lazyTokenStream.produce = s.produce
	return s
}

// produce returns the next token, if any.
func (s *htmlInputSplitter) produce() (htmlToken, bool) {
	token, ok := s.parseToken()
	if !ok {
		return htmlToken{}, false
	}

	// Handle escape-exempt blocks.
	// The parseToken method is only dimly aware of escape-exempt blocks, so
	// here we detect the beginning and ends of escape exempt blocks, and
	// reclassify as UNESCAPED, any tokens that appear in the middle.
	if s.inEscapeExemptBlock {
		if token.typ != htmlTokenTypeServercode {
			// classify RCDATA as text since it can contain entities
			typ := htmlTokenTypeUnescaped
			if s.textEscapingMode == HTMLTextEscapingModeRcdata {
				typ = htmlTokenTypeText
			}
			token = htmlInputSplitterReclassify(token, typ)
		}
	} else {
		switch token.typ {
		case htmlTokenTypeTagbegin:
			canonTagName := s.canonicalElementName(token.start+1, token.end)
			if IsTagFollowedByLiteralContent(canonTagName) {
				s.escapeExemptTagName = canonTagName
				s.textEscapingMode = EscapingModeForTag(canonTagName)
			}
		case htmlTokenTypeTagend:
			s.inEscapeExemptBlock = s.escapeExemptTagName != ""
		}
	}
	return token, true
}

// htmlInputSplitterState is the state of a state machine for optimistically
// identifying tags and other html/xml/phpish structures.
type htmlInputSplitterState int

const (
	htmlInputSplitterStateNone htmlInputSplitterState = iota
	htmlInputSplitterStateTagname
	htmlInputSplitterStateSlash
	htmlInputSplitterStateBang
	htmlInputSplitterStateBangDash
	htmlInputSplitterStateComment
	htmlInputSplitterStateCommentDash
	htmlInputSplitterStateCommentDashDash
	htmlInputSplitterStateCommentDashDashBang
	htmlInputSplitterStateCommentDashAfterBang
	htmlInputSplitterStateCommentStartDash
	htmlInputSplitterStateDirective
	htmlInputSplitterStateDone
	htmlInputSplitterStateBogusComment
	// htmlInputSplitterStateEndTagBogusComment is the state after "</" and a
	// character that cannot start a tag name.
	htmlInputSplitterStateEndTagBogusComment
	htmlInputSplitterStateServerCode
	htmlInputSplitterStateServerCodePct
)

// htmlInputSplitterTagBodyState is where the lexer is within a tag body,
// mirroring the WHATWG tokenizer's attribute states closely enough to decide
// whether a quote character delimits an attribute value or is just part of a
// name or unquoted value.
type htmlInputSplitterTagBodyState int

const (
	// htmlInputSplitterTagBodyStateBeforeName is before an attribute name:
	// after the tag name or a completed value.
	htmlInputSplitterTagBodyStateBeforeName htmlInputSplitterTagBodyState = iota
	// htmlInputSplitterTagBodyStateAfterName is after an attribute name,
	// where '=' introduces its value.
	htmlInputSplitterTagBodyStateAfterName
	// htmlInputSplitterTagBodyStateBeforeValue is after an attribute name
	// and '=', where a quote starts a value.
	htmlInputSplitterTagBodyStateBeforeValue
	// htmlInputSplitterTagBodyStateInUnquotedValue is in an unquoted
	// attribute value, which only whitespace or '>' ends.
	htmlInputSplitterTagBodyStateInUnquotedValue
)

// htmlInputSplitterNoType marks a token whose type is not yet known.
const htmlInputSplitterNoType htmlTokenType = -1

// parseToken breaks the character stream into tokens.
// This method returns a stream of tokens such that each token starts where
// the last token ended.
//
// This property is useful as it allows fetch to collapse and reclassify
// ranges of tokens based on state that is easy to maintain there.
//
// Later passes are responsible for throwing away useless tokens.
func (s *htmlInputSplitter) parseToken() (htmlToken, bool) {
	input := s.input
	start := s.offset
	limit := len(input)
	if start == limit {
		return htmlToken{}, false
	}

	end := start + 1
	typ := htmlInputSplitterNoType

	ch := input[start]
	if s.inTag {
		switch {
		case ch == '>':
			typ = htmlTokenTypeTagend
			s.inTag = false
		case ch == '/':
			if end != limit && input[end] == '>' &&
				s.tagBodyState != htmlInputSplitterTagBodyStateBeforeValue &&
				s.tagBodyState != htmlInputSplitterTagBodyStateInUnquotedValue {
				typ = htmlTokenTypeTagend
				s.inTag = false
				end++
			} else {
				typ = htmlTokenTypeText
			}
		case ch == '=':
			typ = htmlTokenTypeText
		case (ch == '"' || ch == '\'') &&
			s.tagBodyState == htmlInputSplitterTagBodyStateBeforeValue:
			// Only a quote that follows an attribute name and '=' delimits a
			// value.  Anywhere else in a tag the WHATWG tokenizer treats it
			// as an ordinary character of an attribute name or unquoted
			// value, so it must not pair with a later quote and swallow the
			// tag's '>' and whatever follows it (issue #189).
			typ = htmlTokenTypeQstring
			delim := ch
			for ; end < limit; end++ {
				if input[end] == delim {
					end++
					break
				}
			}
		case !stringsIsHTMLSpace(rune(ch)):
			typ = htmlTokenTypeText
			for ; end < limit; end++ {
				ch = input[end]
				// End a text chunk before />
				if s.tagBodyState != htmlInputSplitterTagBodyStateBeforeValue &&
					s.tagBodyState != htmlInputSplitterTagBodyStateInUnquotedValue &&
					ch == '/' && end+1 < limit && input[end+1] == '>' {
					break
				} else if ch == '>' || ch == '=' || stringsIsHTMLSpace(rune(ch)) {
					break
				} else if ch == '"' || ch == '\'' {
					if end+1 < limit {
						ch2 := input[end+1]
						if stringsIsHTMLSpace(rune(ch2)) || ch2 == '>' || ch2 == '/' {
							end++
							break
						}
					}
				}
			}
		default:
			// We skip whitespace tokens inside tag bodies.
			typ = htmlTokenTypeIgnorable
			for end < limit && stringsIsHTMLSpace(rune(input[end])) {
				end++
			}
		}
	} else if ch == '<' {
		if end == limit {
			typ = htmlTokenTypeText
		} else {
			ch = input[end]
			state := htmlInputSplitterStateNone
			switch ch {
			case '/': // close tag?
				state = htmlInputSplitterStateSlash
				end++
			case '!': // Comment or declaration
				if !s.inEscapeExemptBlock {
					state = htmlInputSplitterStateBang
				}
				end++
			case '?':
				if !s.inEscapeExemptBlock {
					state = htmlInputSplitterStateBogusComment
				}
				end++
			case '%':
				state = htmlInputSplitterStateServerCode
				end++
			default:
				if htmlInputSplitterIsIdentStart(ch) && !s.inEscapeExemptBlock {
					state = htmlInputSplitterStateTagname
					end++
				} else if ch == '<' {
					typ = htmlTokenTypeText
				} else {
					end++
				}
			}
			if state != htmlInputSplitterStateNone {
				typ, end, state = s.scanMarkup(start, end, typ, state)
				if end == limit {
					switch state {
					case htmlInputSplitterStateDone:
					case htmlInputSplitterStateBogusComment:
						typ = htmlTokenTypeQmarkmeta
					case htmlInputSplitterStateEndTagBogusComment:
						// A bogus comment that runs to the end of input is
						// still a comment.
						typ = htmlTokenTypeComment
					case htmlInputSplitterStateComment,
						htmlInputSplitterStateCommentDash,
						htmlInputSplitterStateCommentDashDash:
						typ = htmlTokenTypeComment
					case htmlInputSplitterStateDirective,
						htmlInputSplitterStateServerCode,
						htmlInputSplitterStateServerCodePct:
						typ = htmlTokenTypeServercode
					case htmlInputSplitterStateTagname:
						typ = htmlTokenTypeTagbegin
					default:
						typ = htmlTokenTypeText
					}
				}
			}
		}
	}
	if typ == htmlInputSplitterNoType {
		for end < limit && input[end] != '<' {
			end++
		}
		typ = htmlTokenTypeText
	}

	s.offset = end
	result := htmlTokenInstance(start, end, typ)
	if s.inTag {
		s.tagBodyState = s.tagBodyStateAfter(result)
	} else {
		s.tagBodyState = htmlInputSplitterTagBodyStateBeforeName
	}
	return result, true
}

// scanMarkup runs the markup state machine from state over the input from
// end, for the token that starts with the '<' at start.  It returns the
// token's type, if known, the offset after the last character consumed, and
// the final state.
func (s *htmlInputSplitter) scanMarkup(
	start, end int, typ htmlTokenType, state htmlInputSplitterState,
) (htmlTokenType, int, htmlInputSplitterState) {
	input := s.input
	limit := len(input)
	for end < limit {
		ch := input[end]
		switch state {
		case htmlInputSplitterStateTagname:
			if stringsIsHTMLSpace(rune(ch)) || ch == '>' || ch == '/' || ch == '<' {
				// End processing of an escape exempt block when we see
				// a corresponding end tag.
				if s.inEscapeExemptBlock &&
					input[start+1] == '/' &&
					s.textEscapingMode != HTMLTextEscapingModePlainText &&
					s.canonicalElementName(start+2, end) == s.escapeExemptTagName {
					s.inEscapeExemptBlock = false
					s.escapeExemptTagName = ""
				}
				// Don't process content as attributes if we're inside
				// an escape exempt block.
				s.inTag = !s.inEscapeExemptBlock
				return htmlTokenTypeTagbegin, end, htmlInputSplitterStateDone
			}
		case htmlInputSplitterStateSlash:
			switch {
			case htmlInputSplitterIsLetterAt(input, end):
				state = htmlInputSplitterStateTagname
			case s.inEscapeExemptBlock:
				// Literal content: "</" not followed by a letter is
				// text, as it is in a browser's RAWTEXT state.
				if ch == '<' {
					typ = htmlTokenTypeText
				} else {
					end++
				}
				return typ, end, state
			case ch == '>':
				// "</>" is a missing-end-tag-name error for which a
				// browser emits nothing, so it is an empty comment here.
				typ = htmlTokenTypeComment
				state = htmlInputSplitterStateDone
			default:
				// Anything else after "</" is an
				// invalid-first-character-of-tag-name error that starts
				// a bogus comment running to the next '>'.
				state = htmlInputSplitterStateEndTagBogusComment
			}
		case htmlInputSplitterStateBang:
			switch ch {
			case '-':
				state = htmlInputSplitterStateBangDash
			case '>': // <!> is a valid html comment
				state = htmlInputSplitterStateDone
				typ = htmlTokenTypeComment
			default:
				state = htmlInputSplitterStateDirective
			}
		case htmlInputSplitterStateBangDash:
			switch ch {
			case '-':
				state = htmlInputSplitterStateCommentDashAfterBang
			case '>':
				// <!-> is a bogus comment that ends at the first '>'
				state = htmlInputSplitterStateDone
				typ = htmlTokenTypeComment
			default:
				state = htmlInputSplitterStateDirective
			}
		case htmlInputSplitterStateCommentDashAfterBang: // Just after "<!--"
			switch ch {
			case '>': // <!--> is a valid html comment
				state = htmlInputSplitterStateDone
				typ = htmlTokenTypeComment
			case '-':
				state = htmlInputSplitterStateCommentStartDash
			default:
				state = htmlInputSplitterStateComment
			}
		case htmlInputSplitterStateCommentStartDash: // Just after "<!---"
			switch ch {
			case '>': // <!---> is a valid html comment
				state = htmlInputSplitterStateDone
				typ = htmlTokenTypeComment
			case '-':
				// <!---- is in the comment end state, so --!> or more
				// dashes followed by > will close the comment.
				state = htmlInputSplitterStateCommentDashDash
			default:
				state = htmlInputSplitterStateComment
			}
		case htmlInputSplitterStateComment:
			if ch == '-' {
				state = htmlInputSplitterStateCommentDash
			}
		case htmlInputSplitterStateCommentDash:
			// Anything but a second dash is ordinary comment content,
			// so "-x->" must not close the comment.
			if ch == '-' {
				state = htmlInputSplitterStateCommentDashDash
			} else {
				state = htmlInputSplitterStateComment
			}
		case htmlInputSplitterStateCommentDashDash:
			switch ch {
			case '>':
				state = htmlInputSplitterStateDone
				typ = htmlTokenTypeComment
			case '!': // --!> is also valid closing sequence
				state = htmlInputSplitterStateCommentDashDashBang
			case '-':
				state = htmlInputSplitterStateCommentDashDash
			default:
				state = htmlInputSplitterStateComment
			}
		case htmlInputSplitterStateCommentDashDashBang:
			switch ch {
			case '>':
				state = htmlInputSplitterStateDone
				typ = htmlTokenTypeComment
			case '-':
				state = htmlInputSplitterStateCommentDash
			default:
				state = htmlInputSplitterStateComment
			}
		case htmlInputSplitterStateDirective:
			if ch == '>' {
				typ = htmlTokenTypeDirective
				state = htmlInputSplitterStateDone
			}
		case htmlInputSplitterStateBogusComment:
			if ch == '>' {
				typ = htmlTokenTypeQmarkmeta
				state = htmlInputSplitterStateDone
			}
		case htmlInputSplitterStateEndTagBogusComment:
			if ch == '>' {
				typ = htmlTokenTypeComment
				state = htmlInputSplitterStateDone
			}
		case htmlInputSplitterStateServerCode:
			if ch == '%' {
				state = htmlInputSplitterStateServerCodePct
			}
		case htmlInputSplitterStateServerCodePct:
			if ch == '>' {
				typ = htmlTokenTypeServercode
				state = htmlInputSplitterStateDone
			} else if ch != '%' {
				state = htmlInputSplitterStateServerCode
			}
		default:
			panic("Unexpectedly DONE while lexing HTML token stream")
		}
		end++
		if state == htmlInputSplitterStateDone {
			break
		}
	}
	return typ, end, state
}

// cancelPendingLiteralContent stops treating content after the current
// start tag as literal text.
func (s *htmlInputSplitter) cancelPendingLiteralContent() {
	s.inEscapeExemptBlock = false
	s.escapeExemptTagName = ""
}

// tagBodyStateAfter returns the tag body state after t, a token lexed
// inside a tag.
func (s *htmlInputSplitter) tagBodyStateAfter(t htmlToken) htmlInputSplitterTagBodyState {
	switch t.typ {
	case htmlTokenTypeIgnorable:
		// Whitespace ends an unquoted value and is otherwise insignificant.
		if s.tagBodyState == htmlInputSplitterTagBodyStateInUnquotedValue {
			return htmlInputSplitterTagBodyStateBeforeName
		}
		return s.tagBodyState
	case htmlTokenTypeText:
		if s.tagBodyState == htmlInputSplitterTagBodyStateBeforeName ||
			s.tagBodyState == htmlInputSplitterTagBodyStateAfterName {
			if s.tagBodyState == htmlInputSplitterTagBodyStateAfterName &&
				t.tokenInContextMatches(s.input, "=") {
				return htmlInputSplitterTagBodyStateBeforeValue
			}
			// Any other character here, even '=', is part of an attribute
			// name, except that a '/' which does not close the tag puts the
			// tokenizer back before an attribute name, so a name ending in
			// one cannot take a value.
			if s.input[t.end-1] == '/' {
				return htmlInputSplitterTagBodyStateBeforeName
			}
			return htmlInputSplitterTagBodyStateAfterName
		}
		// Text after '=' starts an unquoted value; more text continues it.
		return htmlInputSplitterTagBodyStateInUnquotedValue
	default:
		// A quoted value, tag start, or tag end.
		return htmlInputSplitterTagBodyStateBeforeName
	}
}

// canonicalElementName returns the canonical form of the element name at
// input[start:end].
func (s *htmlInputSplitter) canonicalElementName(start, end int) string {
	return htmlLexerCanonicalElementName(s.input[start:end])
}

// htmlInputSplitterIsIdentStart reports whether ch is an ASCII letter.
func htmlInputSplitterIsIdentStart(ch byte) bool {
	return ch >= 'A' && ch <= 'z' && (ch <= 'Z' || ch >= 'a')
}

// htmlInputSplitterIsLetterAt reports whether the UTF-16 code unit at byte
// offset i of input is a Unicode letter.  The first code unit of a
// supplementary character is a high surrogate, which is not a letter.
func htmlInputSplitterIsLetterAt(input string, i int) bool {
	ch := input[i]
	if ch < utf8.RuneSelf {
		return 'a' <= ch|0x20 && ch|0x20 <= 'z'
	}
	r, _ := wtf8DecodeRune(input[i:])
	return r <= 0xffff && unicode.IsLetter(r)
}

// htmlInputSplitterReclassify returns token with its type replaced by typ.
func htmlInputSplitterReclassify(token htmlToken, typ htmlTokenType) htmlToken {
	return htmlTokenInstance(token.start, token.end, typ)
}

// lazyTokenStream is a stream of HTML tokens that fetches one token at a
// time from produce.
type lazyTokenStream struct {
	tok    htmlToken
	hasTok bool
	// produce returns the next token, or false if there are no more.
	produce func() (htmlToken, bool)
}

// hasNext reports whether there is another token.
func (s *lazyTokenStream) hasNext() bool {
	if !s.hasTok {
		s.tok, s.hasTok = s.produce()
	}
	return s.hasTok
}

// next returns the next token.  It panics if there is none: callers check
// hasNext first.
func (s *lazyTokenStream) next() htmlToken {
	if !s.hasTok {
		s.tok, s.hasTok = s.produce()
	}
	if !s.hasTok {
		panic("no such element")
	}
	s.hasTok = false
	return s.tok
}
