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

// Ported from examples/src/main/java/org/owasp/html/examples/EbayPolicyExample.java.

// Package examples holds example policies built with sanitizer.HTMLPolicyBuilder
// and small test-beds that run them.
package examples

import (
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/OWASP/java-html-sanitizer/sanitizer"
)

// The patterns below match against whole values (see examplesWholeMatch).
// Each accepts exactly the intended set of strings, which takes some care
// with Go's regexp syntax:
//
//   - Whitespace is [\t\n\v\f\r ], spelled out because Go's \s lacks the
//     vertical tab.
//   - Case-insensitive matching folds ASCII letters only.  Go's (?i) also
//     folds the long s (U+017F) with s and the Kelvin sign (U+212A) with k,
//     so ebayPolicyExampleIgnoreCase spells out ASCII case pairs instead.
//   - In ebayPolicyExampleOffsiteURL the greedy [...]* before the trailing
//     whitespace never needs to give back a character, because the only
//     character both that class and the whitespace after it accept is the
//     space.
//   - \p{L}, \p{N} and \p{Zs} are the Unicode letter, number and space
//     separator categories.

// ebayPolicyExampleColorName matches the 16 colors defined by the HTML Spec
// (also used by the CSS Spec).
var ebayPolicyExampleColorName = examplesWholeMatch(
	`(?:aqua|black|blue|fuchsia|gray|grey|green|lime|maroon|navy|olive|purple` +
		`|red|silver|teal|white|yellow)`)

// ebayPolicyExampleColorCode matches a color in hex: HTML/CSS Spec allows 3
// or 6 digit hex to specify color.
var ebayPolicyExampleColorCode = examplesWholeMatch(
	`(?:#(?:[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?))`)

// ebayPolicyExampleNumberOrPercent matches a non-negative integer, optionally
// followed by a percent sign.
var ebayPolicyExampleNumberOrPercent = examplesWholeMatch(
	`[0-9]+%?`)

// ebayPolicyExampleParagraph matches prose.
var ebayPolicyExampleParagraph = examplesWholeMatch(
	`(?:[\p{L}\p{N},'\.\t\n\v\f\r \-_\(\)]|&[0-9]{2};)*`)

// ebayPolicyExampleHTMLId matches an HTML id.
var ebayPolicyExampleHTMLId = examplesWholeMatch(
	`[a-zA-Z0-9\:\-_\.]+`)

// ebayPolicyExampleHTMLTitle matches a title.  To force it to be non-empty,
// use a '+' at the end instead of '*'.
var ebayPolicyExampleHTMLTitle = examplesWholeMatch(
	`[\p{L}\p{N}\t\n\v\f\r \-_',:\[\]!\./\\\(\)&]*`)

// ebayPolicyExampleHTMLClass matches a list of class names.
var ebayPolicyExampleHTMLClass = examplesWholeMatch(
	`[a-zA-Z0-9\t\n\v\f\r ,\-_]+`)

// ebayPolicyExampleOnsiteURL matches a URL without a protocol, or a fragment.
var ebayPolicyExampleOnsiteURL = examplesWholeMatch(
	`(?:[\p{L}\p{N}\\\.\#@\$%\+&;\-_~,\?=/!]+|\#(\w)+)`)

// ebayPolicyExampleOffsiteURL matches an http, https, ftp, ftps or mailto URL.
var ebayPolicyExampleOffsiteURL = examplesWholeMatch(
	`[\t\n\v\f\r ]*(?:(?:ht|f)tps?://|mailto:)[\p{L}\p{N}]` +
		`[\p{L}\p{N}\p{Zs}\.\#@\$%\+&;:\-_~,\?=/!\(\)]*[\t\n\v\f\r ]*`)

// ebayPolicyExampleNumber matches a decimal number.
var ebayPolicyExampleNumber = examplesWholeMatch(
	`[+-]?(?:(?:[0-9]+(?:\.[0-9]*)?)|\.[0-9]+)`)

// ebayPolicyExampleName matches a name.
var ebayPolicyExampleName = examplesWholeMatch(
	`[a-zA-Z0-9\-_\$]+`)

// ebayPolicyExampleAlign matches a horizontal alignment, ignoring case.
var ebayPolicyExampleAlign = examplesWholeMatch(
	ebayPolicyExampleIgnoreCase("center|left|right|justify|char"))

// ebayPolicyExampleValign matches a vertical alignment, ignoring case.
var ebayPolicyExampleValign = examplesWholeMatch(
	ebayPolicyExampleIgnoreCase("baseline|bottom|middle|top"))

// ebayPolicyExampleColorNameOrColorCode accepts a color name or code.
var ebayPolicyExampleColorNameOrColorCode = ebayPolicyExampleMatchesEither(
	ebayPolicyExampleColorName, ebayPolicyExampleColorCode)

// ebayPolicyExampleOnsiteOrOffsiteURL accepts an on-site or off-site URL.
var ebayPolicyExampleOnsiteOrOffsiteURL = ebayPolicyExampleMatchesEither(
	ebayPolicyExampleOnsiteURL, ebayPolicyExampleOffsiteURL)

// ebayPolicyExampleHistoryBack matches the script that goes back a page.
var ebayPolicyExampleHistoryBack = examplesWholeMatch(
	`(?:javascript:)?\Qhistory.go(-1)\E`)

// ebayPolicyExampleOneChar accepts the empty string and any single code
// point, including a line terminator.  A supplementary character counts as
// one, and so does a lone surrogate, which the sanitizer carries in its
// three-byte WTF-8 form.  A regular expression cannot match that form, so
// this is a function.
func ebayPolicyExampleOneChar(value string) bool {
	if value == "" {
		return true
	}
	if len(value) == 3 && value[0] == 0xed && 0xa0 <= value[1] && value[1] <= 0xbf &&
		value[2]&0xc0 == 0x80 {
		return true
	}
	_, size := utf8.DecodeRuneInString(value)
	return size == len(value)
}

// EbayPolicy is a policy based on the AntiSamy EBay
// example
// (http://www.owasp.org/index.php/Category:OWASP_AntiSamy_Project#Stage_2_-_Choosing_a_base_policy_file):
//
//	eBay (http://www.ebay.com/) is the most popular online auction site in
//	the universe, as far as I can tell. It is a public site so anyone is
//	allowed to post listings with rich HTML content. It's not surprising
//	that given the attractiveness of eBay as a target that it has been
//	subject to a few complex XSS attacks. Listings are allowed to contain
//	much more rich content than, say, Slashdot- so it's attack surface is
//	considerably larger. The following tags appear to be accepted by eBay
//	(they don't publish rules): <a>,...
//
// It can be used to produce policies that sanitize to HTML sinks via
// sanitizer.PolicyFactory.Apply.
var EbayPolicy = examplesMustFactory(sanitizer.NewHTMLPolicyBuilder().
	AllowAttributes("id").MatchingPattern(ebayPolicyExampleHTMLId).Globally().
	AllowAttributes("class").MatchingPattern(ebayPolicyExampleHTMLClass).Globally().
	AllowAttributes("lang").MatchingPattern(examplesWholeMatch(`[a-zA-Z]{2,20}`)).
	Globally().
	AllowAttributes("title").MatchingPattern(ebayPolicyExampleHTMLTitle).Globally().
	AllowStyling().
	AllowAttributes("align").MatchingPattern(ebayPolicyExampleAlign).OnElements("p").
	AllowAttributes("for").MatchingPattern(ebayPolicyExampleHTMLId).OnElements("label").
	AllowAttributes("color").MatchingPredicate(ebayPolicyExampleColorNameOrColorCode).
	OnElements("font").
	AllowAttributes("face").
	MatchingPattern(examplesWholeMatch(`[\w;, \-]+`)).
	OnElements("font").
	AllowAttributes("size").MatchingPattern(ebayPolicyExampleNumber).OnElements("font").
	AllowAttributes("href").MatchingPredicate(ebayPolicyExampleOnsiteOrOffsiteURL).
	OnElements("a").
	AllowStandardURLProtocols().
	AllowAttributes("nohref").OnElements("a").
	AllowAttributes("name").MatchingPattern(ebayPolicyExampleName).OnElements("a").
	AllowAttributes(
		"onfocus", "onblur", "onclick", "onmousedown", "onmouseup").
	MatchingPattern(ebayPolicyExampleHistoryBack).OnElements("a").
	RequireRelNofollowOnLinks().
	AllowAttributes("src").MatchingPredicate(ebayPolicyExampleOnsiteOrOffsiteURL).
	OnElements("img").
	AllowAttributes("name").MatchingPattern(ebayPolicyExampleName).
	OnElements("img").
	AllowAttributes("alt").MatchingPattern(ebayPolicyExampleParagraph).
	OnElements("img").
	AllowAttributes("border", "hspace", "vspace").MatchingPattern(ebayPolicyExampleNumber).
	OnElements("img").
	AllowAttributes("border", "cellpadding", "cellspacing").
	MatchingPattern(ebayPolicyExampleNumber).OnElements("table").
	AllowAttributes("bgcolor").MatchingPredicate(ebayPolicyExampleColorNameOrColorCode).
	OnElements("table").
	AllowAttributes("background").MatchingPattern(ebayPolicyExampleOnsiteURL).
	OnElements("table").
	AllowAttributes("align").MatchingPattern(ebayPolicyExampleAlign).
	OnElements("table").
	AllowAttributes("noresize").
	MatchingPattern(examplesWholeMatch(ebayPolicyExampleIgnoreCase("noresize"))).
	OnElements("table").
	AllowAttributes("background").MatchingPattern(ebayPolicyExampleOnsiteURL).
	OnElements("td", "th", "tr").
	AllowAttributes("bgcolor").MatchingPredicate(ebayPolicyExampleColorNameOrColorCode).
	OnElements("td", "th").
	AllowAttributes("abbr").MatchingPattern(ebayPolicyExampleParagraph).
	OnElements("td", "th").
	AllowAttributes("axis", "headers").MatchingPattern(ebayPolicyExampleName).
	OnElements("td", "th").
	AllowAttributes("scope").
	MatchingPattern(examplesWholeMatch(ebayPolicyExampleIgnoreCase("(?:row|col)(?:group)?"))).
	OnElements("td", "th").
	AllowAttributes("nowrap").
	OnElements("td", "th").
	AllowAttributes("height", "width").MatchingPattern(ebayPolicyExampleNumberOrPercent).
	OnElements("table", "td", "th", "tr", "img").
	AllowAttributes("align").MatchingPattern(ebayPolicyExampleAlign).
	OnElements("thead", "tbody", "tfoot", "img",
		"td", "th", "tr", "colgroup", "col").
	AllowAttributes("valign").MatchingPattern(ebayPolicyExampleValign).
	OnElements("thead", "tbody", "tfoot",
		"td", "th", "tr", "colgroup", "col").
	AllowAttributes("charoff").MatchingPattern(ebayPolicyExampleNumberOrPercent).
	OnElements("td", "th", "tr", "colgroup", "col",
		"thead", "tbody", "tfoot").
	AllowAttributes("char").MatchingPredicate(ebayPolicyExampleOneChar).
	OnElements("td", "th", "tr", "colgroup", "col",
		"thead", "tbody", "tfoot").
	AllowAttributes("colspan", "rowspan").MatchingPattern(ebayPolicyExampleNumber).
	OnElements("td", "th").
	AllowAttributes("span", "width").MatchingPattern(ebayPolicyExampleNumberOrPercent).
	OnElements("colgroup", "col").
	AllowElements(
		"a", "label", "noscript", "h1", "h2", "h3", "h4", "h5", "h6",
		"p", "i", "b", "u", "strong", "em", "small", "big", "pre", "code",
		"cite", "samp", "sub", "sup", "strike", "center", "blockquote",
		"hr", "br", "col", "font", "map", "span", "div", "img",
		"ul", "ol", "li", "dd", "dt", "dl", "tbody", "thead", "tfoot",
		"table", "td", "th", "tr", "colgroup", "fieldset", "legend"))

// RunEbayPolicy reads HTML from in and writes content sanitized by
// EbayPolicy to out.  in is decoded as UTF-8 and its
// lines are joined with '\n', so line terminators are normalized and a
// trailing one is dropped.
//
// It returns the first error writing to out, or an error carrying the
// message of the first alert the renderer raises on truly bizarre input;
// either stops the sanitization.
func RunEbayPolicy(in io.Reader, out io.Writer) error {
	return examplesRunTestBed(in, out, EbayPolicy)
}

// ebayPolicyExampleMatchesEither returns a predicate that accepts the values
// that a or b matches.
func ebayPolicyExampleMatchesEither(a, b *regexp.Regexp) func(string) bool {
	return func(s string) bool {
		return a.MatchString(s) || b.MatchString(s)
	}
}

// examplesWholeMatch compiles a pattern that must match a value in its
// entirety.  The pattern is anchored here so that a top-level alternation
// like a|b is anchored as a whole.
func examplesWholeMatch(pattern string) *regexp.Regexp {
	return regexp.MustCompile(`\A(?:` + pattern + `)\z`)
}

// ebayPolicyExampleIgnoreCase returns pattern, which must hold no escapes or
// character classes, with each ASCII letter replaced by a class of its upper
// and lower case forms.  That makes it match ASCII letters in either case and
// no other character, unlike Go's (?i), which also folds U+017F and U+212A.
func ebayPolicyExampleIgnoreCase(pattern string) string {
	var sb strings.Builder
	for i := 0; i < len(pattern); i++ {
		if lower := pattern[i] | 0x20; 'a' <= lower && lower <= 'z' {
			sb.Write([]byte{'[', lower &^ 0x20, lower, ']'})
		} else {
			sb.WriteByte(pattern[i])
		}
	}
	return sb.String()
}

// examplesMustFactory returns the factory b builds, whose configuration is
// known to be valid.
func examplesMustFactory(b *sanitizer.HTMLPolicyBuilder) *sanitizer.PolicyFactory {
	f, err := b.ToFactory()
	if err != nil {
		panic(err)
	}
	return f
}

// examplesRunTestBed reads HTML from in, as RunEbayPolicy describes,
// and writes it to out sanitized by policy.  If the renderer reports
// markup it cannot render, nothing is written and the first report is
// returned as the error; otherwise it returns any error writing to out.
func examplesRunTestBed(in io.Reader, out io.Writer, policy *sanitizer.PolicyFactory) error {
	// Fetch the HTML to sanitize.
	html, err := examplesReadLines(in)
	if err != nil {
		return err
	}
	// Set up an output channel to receive the sanitized HTML.  Our HTML
	// parser is very lenient, but the handler hears about truly bizarre
	// inputs.
	var sanitized strings.Builder
	var alert error
	renderer := sanitizer.NewHTMLStreamRendererToBuilder(&sanitized, func(message string) {
		if alert == nil {
			alert = errors.New(message)
		}
	})
	// Use the policy defined above to sanitize the HTML.
	sanitizer.Sanitize(html, policy.Apply(renderer), nil)
	if alert != nil {
		return alert
	}
	_, err = io.WriteString(out, sanitized.String())
	return err
}

// examplesReadLines reads all of in, decodes it with examplesDecodeUTF8, and
// joins its lines with '\n': "\n", "\r" and "\r\n" all end a line, and a
// line terminator at the end of the input ends the last line rather than
// starting an empty one.
func examplesReadLines(in io.Reader) (string, error) {
	data, err := io.ReadAll(in)
	if err != nil {
		return "", err
	}
	text := examplesDecodeUTF8(data)
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	return strings.TrimSuffix(text, "\n"), nil
}

// examplesDecodeUTF8 decodes b as UTF-8, replacing each malformed sequence
// with one U+FFFD.  Go's conversions yield one U+FFFD per invalid byte; here
// an encoded surrogate such as ED A0 80 is one malformed sequence, and so is
// the valid prefix of a sequence cut short, such as E2 82 before a byte that
// cannot continue it.  The overlong E0 80 80 still becomes three.
func examplesDecodeUTF8(b []byte) string {
	isCont := func(c byte) bool { return c&0xc0 == 0x80 }
	var sb strings.Builder
	sb.Grow(len(b))
	for i, n := 0, len(b); i < n; {
		b1 := b[i]
		// bad is the length of a malformed sequence at i, or 0.
		bad := 0
		switch {
		case b1 < 0x80:
			sb.WriteByte(b1)
			i++
			continue
		case 0xc2 <= b1 && b1 <= 0xdf:
			switch {
			case n-i < 2:
				bad = n - i // Truncated by the end of the input.
			case !isCont(b[i+1]):
				bad = 1
			}
			if bad == 0 {
				sb.Write(b[i : i+2])
				i += 2
				continue
			}
		case b1&0xf0 == 0xe0:
			if n-i < 3 {
				if n-i > 1 && (b1 == 0xe0 && b[i+1]&0xe0 == 0x80 || !isCont(b[i+1])) {
					bad = 1
				} else {
					bad = n - i
				}
				break
			}
			b2, b3 := b[i+1], b[i+2]
			switch {
			case b1 == 0xe0 && b2&0xe0 == 0x80 || !isCont(b2):
				bad = 1
			case !isCont(b3):
				bad = 2
			case b1 == 0xed && b2 >= 0xa0:
				bad = 3 // A surrogate code unit.
			default:
				sb.Write(b[i : i+3])
				i += 3
				continue
			}
		case b1&0xf8 == 0xf0:
			b2Bad := func(b2 byte) bool {
				return b1 > 0xf4 ||
					b1 == 0xf0 && (b2 < 0x90 || b2 > 0xbf) ||
					b1 == 0xf4 && b2&0xf0 != 0x80 ||
					!isCont(b2)
			}
			switch {
			case n-i > 1 && b2Bad(b[i+1]) || n-i == 1 && b1 > 0xf4:
				bad = 1
			case n-i > 2 && !isCont(b[i+2]):
				bad = 2
			case n-i < 4:
				bad = n - i
			case !isCont(b[i+3]):
				bad = 3
			default:
				sb.Write(b[i : i+4])
				i += 4
				continue
			}
		default:
			bad = 1
		}
		sb.WriteRune(utf8.RuneError)
		i += bad
	}
	return sb.String()
}
