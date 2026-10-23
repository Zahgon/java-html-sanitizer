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
// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/StylingPolicy.java.

package sanitizer

import (
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"
)

const stylingPolicyHexDigits = "0123456789abcdef"

// stylingPolicyMaxCSSURLLength is the longest url(...) kept in a style
// attribute, in UTF-16 code units; longer ones are dropped along with the
// property that contains them.
//
// A length limit keeps downstream code that has bounds of its own out of
// trouble, so a sanitizer is a reasonable place to impose one.  It applies to
// CSS only -- URLs in href and src are not capped.  An earlier limit of 1024
// predates the widespread use of data: URLs for images, which is what made
// the cap visible.  See #187.
const stylingPolicyMaxCSSURLLength = 2048

// stylingPolicy is an HTML sanitizer policy that tries to preserve simple CSS
// by white-listing property values and splitting combo properties into
// multiple more specific ones to reduce the attack-surface.
type stylingPolicy struct {
	cssSchema   *CSSSchema
	urlRewriter stylingPolicyURLRewriter
}

// stylingPolicyURLRewriter vets the content of a url(...) value in CSS: it
// returns the URL to use, or the empty string to drop it.
type stylingPolicyURLRewriter interface {
	apply(url string) string
}

// stylingPolicyURLRewriterFunc adapts a function to a
// stylingPolicyURLRewriter.
type stylingPolicyURLRewriterFunc func(url string) string

func (f stylingPolicyURLRewriterFunc) apply(url string) string { return f(url) }

func newStylingPolicy(cssSchema *CSSSchema, urlRewriter stylingPolicyURLRewriter) *stylingPolicy {
	return &stylingPolicy{cssSchema: cssSchema, urlRewriter: urlRewriter}
}

// Apply sanitizes a style attribute value.
func (p *stylingPolicy) Apply(elementName, attributeName, value string) (string, bool) {
	return p.sanitizeCSSProperties(value)
}

// sanitizeCSSProperties does lossy filtering of CSS properties that allows
// textual styling that affects layout, but does not allow breaking out of a
// clipping region, absolute positioning, image loading, tab index changes, or
// code execution.
//
// It returns a sanitized version of the input, or false if nothing is left.
func (p *stylingPolicy) sanitizeCSSProperties(style string) (string, bool) {
	h := &stylingPolicyHandler{policy: p, cssProperty: cssSchemaDisallowed}
	cssGrammarParsePropertyGroup(style, h)
	if len(h.sanitizedCSS) == 0 {
		return "", false
	}
	return string(h.sanitizedCSS), true
}

// stylingPolicyHandler writes the declarations the CSS grammar finds that
// the schema allows.
type stylingPolicyHandler struct {
	policy        *stylingPolicy
	sanitizedCSS  []byte
	cssProperty   *CSSSchemaProperty
	cssProperties []*CSSSchemaProperty
	// propertyStart is the length of the output before the current property.
	propertyStart  int
	hasTokens      bool
	inQuotedIdents bool
	// lastToken is the previous token of the current property's value, if
	// hasLastToken.
	lastToken    string
	hasLastToken bool
}

func (h *stylingPolicyHandler) setLastToken(token string) {
	h.lastToken, h.hasLastToken = token, true
}

func (h *stylingPolicyHandler) emitToken(token string) {
	h.closeQuotedIdents()
	if h.hasTokens {
		h.sanitizedCSS = append(h.sanitizedCSS, ' ')
	}
	h.sanitizedCSS = append(h.sanitizedCSS, token...)
	h.hasTokens = true
}

func (h *stylingPolicyHandler) closeQuotedIdents() {
	if h.inQuotedIdents {
		h.sanitizedCSS = append(h.sanitizedCSS, '\'')
		h.inQuotedIdents = false
	}
}

func (h *stylingPolicyHandler) sanitizeAndAppendURL(urlContent string) {
	if utf16Length(urlContent) < stylingPolicyMaxCSSURLLength {
		rewrittenURL := h.policy.urlRewriter.apply(urlContent)
		if rewrittenURL != "" {
			if h.hasTokens {
				h.sanitizedCSS = append(h.sanitizedCSS, ' ')
			}
			h.sanitizedCSS = append(h.sanitizedCSS, "url('"...)
			h.appendCSSURLContent(rewrittenURL)
			h.sanitizedCSS = append(h.sanitizedCSS, "')"...)
			h.hasTokens = true
		}
	}
}

func (h *stylingPolicyHandler) appendCSSURLContent(url string) {
	// The URL rewriter may return characters that end or escape the CSS
	// string.  Encode them after rewriting, before adding the delimiters.
	for i := 0; i < len(url); i++ {
		ch := url[i]
		if ch == '\'' || ch == '\\' || ch <= 0x20 || ch == 0x7f {
			h.sanitizedCSS = append(h.sanitizedCSS, '%',
				stylingPolicyHexDigits[ch>>4], stylingPolicyHexDigits[ch&0xf])
		} else {
			h.sanitizedCSS = append(h.sanitizedCSS, ch)
		}
	}
}

func (h *stylingPolicyHandler) url(token string) {
	h.closeQuotedIdents()
	if (h.cssProperty.bits & CSSSchemaBitURL) != 0 {
		urlContent := cssGrammarCSSContent(
			stringsStripHTMLSpaces(token[4 : len(token)-1]))
		h.sanitizeAndAppendURL(urlContent)
	}
	h.setLastToken(token)
}

func (h *stylingPolicyHandler) startProperty(propertyName string) {
	h.cssProperties = h.cssProperties[:0]
	h.cssProperty = h.policy.cssSchema.forKey(propertyName)
	h.hasTokens = false
	h.propertyStart = len(h.sanitizedCSS)
	if len(h.sanitizedCSS) != 0 {
		h.sanitizedCSS = append(h.sanitizedCSS, ';')
	}
	h.sanitizedCSS = append(h.sanitizedCSS, propertyName...)
	h.sanitizedCSS = append(h.sanitizedCSS, ':')
}

func (h *stylingPolicyHandler) startFunction(uncanonToken string) {
	h.closeQuotedIdents()
	h.cssProperties = append(h.cssProperties, h.cssProperty)
	token := stringsToLowerCase(uncanonToken)
	if key, ok := h.cssProperty.fnKeys[token]; ok {
		h.cssProperty = h.policy.cssSchema.forKey(key)
	} else {
		h.cssProperty = cssSchemaDisallowed
	}
	if h.cssProperty != cssSchemaDisallowed {
		h.emitToken(token)
	}
	h.setLastToken(token)
}

func (h *stylingPolicyHandler) quotedString(token string) {
	h.closeQuotedIdents()
	// The contents of a quoted string could be treated as
	// 1. a run of space-separated words, as in a font family name,
	// 2. as a URL,
	// 3. as plain text content as in a list-item bullet,
	// 4. or it could be ambiguous as when multiple bits are set.
	meaning := h.cssProperty.bits & (CSSSchemaBitUnreservedWord | CSSSchemaBitURL)
	if (meaning & (meaning - 1)) == 0 { // meaning is unambiguous
		if meaning == CSSSchemaBitUnreservedWord &&
			len(token) > 2 &&
			stylingPolicyIsSafeQuotedIdentifier(token[1:len(token)-1]) {
			// Emit as written: a font name is a name, not a keyword, so its
			// case matters to the reader even though CSS matches it
			// case-insensitively.
			h.emitToken(token)
		} else if meaning == CSSSchemaBitURL {
			// convert to a URL token and hand-off to the appropriate method
			h.sanitizeAndAppendURL(cssGrammarCSSContent(token))
		}
	}
	h.setLastToken(token)
}

func (h *stylingPolicyHandler) quantity(token string) {
	test := CSSSchemaBitQuantity
	if strings.HasPrefix(token, "-") {
		test = CSSSchemaBitNegative
	}
	_, isLiteral := h.cssProperty.literals[token]
	if (h.cssProperty.bits&test) != 0 ||
		// font-weight uses 100, 200, 300, etc.
		isLiteral {
		h.emitToken(token)
	}
	h.setLastToken(token)
}

func (h *stylingPolicyHandler) punctuation(token string) {
	h.closeQuotedIdents()
	if _, ok := h.cssProperty.literals[token]; ok {
		h.emitToken(token)
	}
	h.setLastToken(token)
}

// stylingPolicyIdentToString is the pair of bits under which a bare word is
// emitted as a quoted name.
const stylingPolicyIdentToString = CSSSchemaBitUnreservedWord | CSSSchemaBitString

func (h *stylingPolicyHandler) identifier(uncanonToken string) {
	token := stringsToLowerCase(uncanonToken)
	_, isLiteral := h.cssProperty.literals[token]
	if h.hasLastToken && h.lastToken == "!" && token == "important" {
		h.emitToken("!important")
	} else if isLiteral {
		h.emitToken(token)
	} else if (h.cssProperty.bits&stylingPolicyIdentToString) == stylingPolicyIdentToString &&
		stylingPolicyIsSafeQuotedIdentifier(uncanonToken) {
		// Same test as the quoted path.  This path had none at all, so a bare
		// name could carry a format character -- a bidi override, say -- into
		// the output, and a name the quoted path would reject survived one
		// pass and vanished on the next.
		if !h.inQuotedIdents {
			h.inQuotedIdents = true
			if h.hasTokens {
				h.sanitizedCSS = append(h.sanitizedCSS, ' ')
			}
			h.sanitizedCSS = append(h.sanitizedCSS, '\'')
			h.hasTokens = true
		} else {
			h.sanitizedCSS = append(h.sanitizedCSS, ' ')
		}
		// As above: emit the name as the author wrote it.  Matching against
		// the schema is case-insensitive, but the output is a name.
		h.sanitizedCSS = append(h.sanitizedCSS, uncanonToken...)
	}
	h.setLastToken(token)
}

func (h *stylingPolicyHandler) hash(token string) {
	h.closeQuotedIdents()
	if (h.cssProperty.bits & CSSSchemaBitHashValue) != 0 {
		h.emitToken(stringsToLowerCase(token))
	}
	h.setLastToken(token)
}

func (h *stylingPolicyHandler) endProperty() {
	if !h.hasTokens {
		h.sanitizedCSS = h.sanitizedCSS[:h.propertyStart]
	} else {
		h.closeQuotedIdents()
	}
	h.lastToken, h.hasLastToken = "", false
}

func (h *stylingPolicyHandler) endFunction(token string) {
	if h.cssProperty != cssSchemaDisallowed {
		h.emitToken(")")
	}
	last := len(h.cssProperties) - 1
	h.cssProperty = h.cssProperties[last]
	h.cssProperties = h.cssProperties[:last]
	h.setLastToken(")")
}

// stylingPolicyIsSafeQuotedIdentifier reports whether the given content of a
// quoted token can be re-emitted between single quotes without any further
// escaping.
//
// This is deliberately a small set.  The CSS lexer normalizes a string's
// contents, so a quote or a backslash reaches us already escaped -- 'it\27s',
// 'a\5c b' -- and re-emitting an escape verbatim would mean reasoning about
// escape parity to be sure the closing quote is still the closing quote.
// Rejecting the backslash outright avoids that question entirely, at the cost
// of dropping the rare font name that needs one.
//
// What it does allow is a letter or digit from the basic multilingual plane,
// a space, and the hyphen, underscore and period that appear in names like
// Foo_Bar and "Helvetica Neue LT Std.55 Roman".  The underscore matters in
// practice because Word emits font names containing one, and because the
// unquoted path already accepted it -- so a name would survive sanitization
// once and be dropped on the way back in.
//
// That covers Latin, Cyrillic, Greek, Han, Hangul, kana and the base letters
// of the Arabic, Hebrew, Devanagari and Thai scripts.  It does not cover a
// name carrying a combining mark -- a Devanagari matra, an Arabic diacritic,
// Hebrew niqqud, a Thai vowel sign -- nor one containing a character outside
// the basic multilingual plane, such as a CJK extension B ideograph.  Those
// never reach this function: the CSS lexer excludes them from a token before
// the policy sees it, and has always done so.  So this test is defence in
// depth for non-ASCII rather than the decisive gate, and relaxing it alone
// would not make such a name work.
func stylingPolicyIsSafeQuotedIdentifier(s string) bool {
	for i := 0; i < len(s); {
		ch := s[i]
		if ch <= 0x20 {
			if ch != '\t' && ch != ' ' {
				return false
			}
			i++
		} else if ch < utf8.RuneSelf {
			chLower := ch | 32
			if !(('0' <= chLower && chLower <= '9') ||
				('a' <= chLower && chLower <= 'z') ||
				'-' == ch || '_' == ch || '.' == ch) {
				return false
			}
			i++
		} else {
			// Non-ASCII font names are ordinary -- CJK families, for
			// instance -- but only letters and digits, so that a format
			// character such as a bidi override cannot ride along.  This
			// judges one UTF-16 code unit at a time, so a supplementary
			// code point, whose surrogates are neither, and a lone
			// surrogate, which decodes as an error, are rejected.
			r, size := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError || r > 0xffff ||
				!(unicode.IsLetter(r) || unicode.IsDigit(r)) {
				return false
			}
			i += size
		}
	}
	return true
}

// equals reports whether o is a styling policy with the same schema and an
// equal URL rewriter.  The url rewriter takes part in equality because
// joining groups policies into a set first: two styling policies that share a
// schema but vet URLs differently must both survive to be joined, or one
// rewriter would be dropped silently.  Schemas compare by identity.
func (p *stylingPolicy) equals(o any) bool {
	that, ok := o.(*stylingPolicy)
	if !ok || that == nil {
		return false
	}
	return p == that ||
		(p.cssSchema == that.cssSchema &&
			stylingPolicyURLRewritersEqual(p.urlRewriter, that.urlRewriter))
}

// stylingPolicyURLRewritersEqual reports whether two URL rewriters are equal.
// A function has no identity in Go, so a stylingPolicyURLRewriterFunc equals
// nothing.
func stylingPolicyURLRewritersEqual(a, b stylingPolicyURLRewriter) bool {
	switch a := a.(type) {
	case *stylingPolicyURLPolicyRewriter:
		return a.equals(b)
	case stylingPolicyURLRewriterFunc:
		return false
	default:
		return a == b
	}
}

// stylingPolicyAttributePoliciesEqual compares two attribute policies with
// their own equals method if they have one, or else by identity.
func stylingPolicyAttributePoliciesEqual(a, b AttributePolicy) bool {
	if eq, ok := a.(interface{ equals(o any) bool }); ok {
		return eq.equals(b)
	}
	if a == nil || b == nil {
		return a == b
	}
	ta, tb := reflect.TypeOf(a), reflect.TypeOf(b)
	return ta == tb && ta.Comparable() && a == b
}

func (p *stylingPolicy) joinStrategy() joinableJoinStrategy[JoinableAttributePolicy] {
	return stylingPolicyStylingPolicyJoinStrategyInstance
}

// stylingPolicyStylingPolicyJoinStrategy joins styling policies.
type stylingPolicyStylingPolicyJoinStrategy struct{}

var stylingPolicyStylingPolicyJoinStrategyInstance = stylingPolicyStylingPolicyJoinStrategy{}

// join joins styling policies into one that applies the intersection of
// their schemas and runs every URL rewriter in turn.
func (stylingPolicyStylingPolicyJoinStrategy) join(
	toJoin []JoinableAttributePolicy,
) JoinableAttributePolicy {
	var cssSchema *CSSSchema
	var urlPolicies []AttributePolicy
	for _, p := range toJoin {
		sp := p.(*stylingPolicy)
		// Joining narrows: a value has to satisfy every policy being joined,
		// which is how every other joined attribute policy behaves and what
		// PolicyFactory.And promises.  Unioning here let a.And(b) allow
		// properties that neither a nor b allowed on its own.
		if cssSchema == nil {
			cssSchema = sp.cssSchema
		} else {
			// Intersecting two schemas cannot fail.
			cssSchema, _ = CSSSchemaIntersection(cssSchema, sp.cssSchema)
		}
		urlPolicies = append(urlPolicies,
			stylingPolicyURLPolicyRewriterToAttributePolicy(sp.urlRewriter))
	}
	// The rewriters are joined as attribute policies rather than composed as
	// functions so that the URL protocol guards the builder put in them meet
	// and join as they do on href: a builder that allowed no protocol yields
	// to one that did, and two allowlists intersect.  A URL still has to
	// satisfy every rewriter, in the order they were joined.
	return newStylingPolicy(
		cssSchema,
		newStylingPolicyURLPolicyRewriter(JoinAttributePolicies(urlPolicies...)))
}

// stylingPolicyURLPolicyRewriter is a url rewriter that applies an attribute
// policy, which is how the builder vets the URLs in a style attribute: the
// policy is the join of the one given to HTMLPolicyBuilder.AllowURLsInStyles
// and the protocol guard.  Keeping the policy reachable, rather than closing
// over it, lets the join strategy above join rewriters as attribute policies.
type stylingPolicyURLPolicyRewriter struct {
	policy AttributePolicy
}

func newStylingPolicyURLPolicyRewriter(policy AttributePolicy) *stylingPolicyURLPolicyRewriter {
	return &stylingPolicyURLPolicyRewriter{policy: policy}
}

func (r *stylingPolicyURLPolicyRewriter) apply(url string) string {
	rewritten, _ := r.policy.Apply("img", "src", url)
	return rewritten
}

// stylingPolicyURLPolicyRewriterToAttributePolicy returns the attribute
// policy that vets a URL the way the rewriter does.
func stylingPolicyURLPolicyRewriterToAttributePolicy(rewriter stylingPolicyURLRewriter) AttributePolicy {
	if r, ok := rewriter.(*stylingPolicyURLPolicyRewriter); ok {
		return r.policy
	}
	return newStylingPolicyRewriterAttributePolicy(rewriter)
}

// equals reports whether o is a rewriter applying an equal attribute policy.
func (r *stylingPolicyURLPolicyRewriter) equals(o any) bool {
	that, ok := o.(*stylingPolicyURLPolicyRewriter)
	return ok && that != nil &&
		stylingPolicyAttributePoliciesEqual(r.policy, that.policy)
}

// stylingPolicyRewriterAttributePolicy is a caller's rewriter as an attribute
// policy.  A rewriter signals "dropped" by returning the empty string, which
// is not a URL, so the empty string becomes the rejection that stops a joined
// policy rather than being passed on to the next one.
type stylingPolicyRewriterAttributePolicy struct {
	rewriter stylingPolicyURLRewriter
}

func newStylingPolicyRewriterAttributePolicy(
	rewriter stylingPolicyURLRewriter,
) *stylingPolicyRewriterAttributePolicy {
	return &stylingPolicyRewriterAttributePolicy{rewriter: rewriter}
}

// Apply rewrites a URL, rejecting it if the rewriter drops it.
func (p *stylingPolicyRewriterAttributePolicy) Apply(
	elementName, attributeName, value string,
) (string, bool) {
	rewritten := p.rewriter.apply(value)
	return rewritten, rewritten != ""
}

// equals reports whether o applies an equal rewriter.
func (p *stylingPolicyRewriterAttributePolicy) equals(o any) bool {
	that, ok := o.(*stylingPolicyRewriterAttributePolicy)
	return ok && that != nil &&
		(p == that || stylingPolicyURLRewritersEqual(p.rewriter, that.rewriter))
}
