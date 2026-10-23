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

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/Sanitizers.java.

package sanitizer

// The Sanitizers… variables are pre-packaged HTML sanitizer policies.
//
// These policies can be used to sanitize content
//
//	sanitizer.Formatting.Sanitize("<b>Hello, World!</b>")
//
// and can be chained
//
//	s := sanitizer.Formatting.And(sanitizer.Blocks)
//	fmt.Println(s.Sanitize("<p>Hello, <b>World!</b>"))
//
// For more fine-grained control over sanitization, use HTMLPolicyBuilder.

// Formatting allows common formatting elements including <b>, <i>,
// etc.
var Formatting = sanitizersToFactory(
	NewHTMLPolicyBuilder().AllowCommonInlineFormattingElements())

// Blocks allows common block elements including <p>, <h1>, etc.
var Blocks = sanitizersToFactory(
	NewHTMLPolicyBuilder().AllowCommonBlockElements())

// Styles allows certain safe CSS properties in style="..."
// attributes.
var Styles = sanitizersToFactory(
	NewHTMLPolicyBuilder().AllowStyling())

// Links allows HTTP, HTTPS, MAILTO, and relative links.
var Links = sanitizersToFactory(NewHTMLPolicyBuilder().
	AllowStandardURLProtocols().AllowElements("a").
	AllowAttributes("href").OnElements("a").RequireRelNofollowOnLinks())

// Tables allows common table elements.
var Tables = sanitizersToFactory(NewHTMLPolicyBuilder().
	AllowStandardURLProtocols().
	AllowElements(
		"table", "tr", "td", "th",
		"colgroup", "caption", "col",
		"thead", "tbody", "tfoot").
	AllowAttributes("summary").OnElements("table").
	AllowAttributes("align", "valign").
	OnElements("table", "tr", "td", "th",
		"colgroup", "col",
		"thead", "tbody", "tfoot").
	AllowAttributes("colspan", "rowspan").Matching(sanitizersInteger).OnElements("td", "th").
	AllowAttributes("headers").Matching(sanitizersIdList).OnElements("td", "th").
	AllowAttributes("scope").MatchingValues(true, "row", "col", "rowgroup", "colgroup").
	OnElements("th").
	AllowTextIn("table")) // WIDGY

// Images allows <img> elements from HTTP, HTTPS, and relative
// sources.  Allows loading elements.
var Images = sanitizersToFactory(NewHTMLPolicyBuilder().
	AllowURLProtocols("http", "https").AllowElements("img").
	AllowAttributes("alt", "src").OnElements("img").
	AllowAttributes("border", "height", "width").Matching(sanitizersInteger).
	OnElements("img").
	AllowAttributes("loading").MatchingValues(true, "lazy", "eager").OnElements("img"))

// sanitizersToFactory returns the factory for one of the canned policies,
// whose configuration has no errors.
func sanitizersToFactory(b *HTMLPolicyBuilder) *PolicyFactory {
	f, err := b.ToFactory()
	if err != nil {
		panic(err)
	}
	return f
}

// sanitizersIntegerPolicy is the type of sanitizersInteger.
type sanitizersIntegerPolicy struct{}

// sanitizersInteger accepts a non-empty run of ASCII digits, truncating any
// fraction after a '.'.
var sanitizersInteger AttributePolicy = &sanitizersIntegerPolicy{}

// Apply returns value, or its integer part, if it is a decimal number.
func (*sanitizersIntegerPolicy) Apply(_, _, value string) (string, bool) {
	n := len(value)
	if n == 0 {
		return "", false
	}
	for i := 0; i < n; i++ {
		ch := value[i]
		if ch == '.' {
			if i == 0 {
				return "", false
			}
			return value[:i], true // truncate to integer.
		} else if !('0' <= ch && ch <= '9') {
			return "", false
		}
	}
	return value, true
}

// sanitizersIdListPolicy is the type of sanitizersIdList.
type sanitizersIdListPolicy struct{}

// sanitizersIdList accepts a space-separated list of ID references, as used
// by the headers attribute on table cells.  Each token is limited to ASCII
// letters, digits and _ - . :, and runs of white-space between tokens
// collapse to a single space.
var sanitizersIdList AttributePolicy = &sanitizersIdListPolicy{}

// Apply returns the normalized list, or rejects it if it is empty or holds
// any other character.
func (*sanitizersIdListPolicy) Apply(_, _, value string) (string, bool) {
	sb := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\f' || ch == '\r' {
			if n := len(sb); n != 0 && sb[n-1] != ' ' {
				sb = append(sb, ' ')
			}
		} else if ('a' <= ch && ch <= 'z') || ('A' <= ch && ch <= 'Z') ||
			('0' <= ch && ch <= '9') ||
			ch == '_' || ch == '-' || ch == '.' || ch == ':' {
			sb = append(sb, ch)
		} else {
			return "", false
		}
	}
	if n := len(sb); n != 0 && sb[n-1] == ' ' {
		sb = sb[:n-1]
	}
	if len(sb) == 0 {
		return "", false
	}
	return string(sb), true
}
