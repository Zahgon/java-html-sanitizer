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
// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/StylingPolicyTest.java.

package sanitizer

import (
	"strings"
	"testing"
	"time"
)

// stylingPolicyTestLayout is a schema that opts into the layout families the
// way callers would.
var stylingPolicyTestLayout = func() *CSSSchema {
	schema, err := CSSSchemaUnion(
		DefaultCSSSchema,
		cssSchemaMustWithProperties([]string{
			"display", "grid-template-columns", "grid-template-rows",
			"grid-auto-flow", "grid-column", "grid-row", "gap", "row-gap",
			"column-gap", "flex", "flex-direction", "flex-wrap", "flex-grow",
			"flex-basis", "order", "justify-content", "align-items",
			"align-self", "transform", "transform-origin",
			"repeat()", "minmax()", "fit-content()", "transform-function()",
			"calc()"}))
	if err != nil {
		panic(err)
	}
	return schema
}()

// stylingPolicyTestSanitizeCSS sanitizes css against cssSchema, vetting URLs
// with the standard URL policy and marking the ones that survive.
func stylingPolicyTestSanitizeCSS(cssSchema *CSSSchema, css string) (string, bool) {
	policy := newStylingPolicy(
		cssSchema,
		stylingPolicyURLRewriterFunc(func(url string) string {
			safeURL, ok := standardURLAttributePolicyInstance.Apply("img", "src", url)
			if !ok {
				return ""
			}
			return safeURL + "#sanitized"
		}))
	return policy.sanitizeCSSProperties(css)
}

// stylingPolicyAssertSanitizedCSS checks the result of sanitizing css; a nil
// want means that nothing should be left.
func stylingPolicyAssertSanitizedCSS(t *testing.T, cssSchema *CSSSchema, want any, css string) {
	t.Helper()
	got, ok := stylingPolicyTestSanitizeCSS(cssSchema, css)
	if want == nil {
		if ok {
			t.Errorf("%q: got %q, want nothing", css, got)
		}
		return
	}
	if !ok || got != want.(string) {
		t.Errorf("%q: got %q (%v), want %q", css, got, ok, want)
	}
}

// stylingPolicyAssertSanitizedCSSInTime is stylingPolicyAssertSanitizedCSS
// for the default schema, failing if sanitizing takes over 20 seconds.
func stylingPolicyAssertSanitizedCSSInTime(t *testing.T, want, css string) {
	t.Helper()
	start := time.Now()
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, want, css)
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Errorf("took %v", elapsed)
	}
}

func TestStylingPolicyNothingToOutput(t *testing.T) {
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "/** no CSS here */")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "/* props: disabled; font-weight: bold */")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "position: fixed")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		nil, "background: url('javascript:alert%281337%29')")
}

func TestStylingPolicyColors(t *testing.T) {
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "color:red", "color: red")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "background-color:#f00", "background-color: #f00")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "background:#f00", "background: #f00")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "color:#f00", "color: #F00")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "color: #F000")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "color:#ff0000", "color: #ff0000")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "color:rgb( 255 , 0 , 0 )", "color: rgb(255, 0, 0)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "background:rgb( 100% , 0 , 0 )",
		"background: rgb(100%, 0, 0)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"color:rgba( 100% , 0 , 0 , 100% )", "color: RGBA(100%, 0, 0, 100%)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "color: transparent")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "color: bogus")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "color: expression(alert(1337))")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "color: 000")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "background-color: 000")
	// Not colors.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"background:url('pic.jpg#sanitized')", "background: \"pic.jpg\"")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"background:url('pic.jpg#sanitized')", "background: url(pic.jpg)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "color:#urlabc")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "color:#urlabcd")
}

func TestStylingPolicyFontWeight(t *testing.T) {
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font-weight:bold", "font-weight: bold")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font:bold", "font: bold")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font:bolder", "font: Bolder")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font-weight:800", "font-weight: 800")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		nil, "font-weight: expression(alert(1337))")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font:'evil'",
		"font: 3execute evil")
}

func TestStylingPolicyFontStyle(t *testing.T) {
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font-style:italic", "font-style: Italic")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font:italic", "font: italic")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font:oblique", "font: Oblique")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		nil, "font-style: expression(alert(1337))")
}

func TestStylingPolicyFontFace(t *testing.T) {
	// A font name is a name, not a keyword: it is emitted as the author wrote
	// it, even though the schema matches it case-insensitively.  See #289.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font:'Arial' , 'Helvetica'", "font: Arial, Helvetica")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font-family:'Arial' , 'Helvetica' , sans-serif",
		"Font-family: Arial, Helvetica, sans-serif")
	// A quoted "Monospace" is a font name, not the generic family keyword, so
	// it stays quoted; the bare keyword below does not.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font-family:'Monospace' , sans-serif",
		"Font-family: \"Monospace\", Sans-serif")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font:'Arial Bold' , 'Helvetica' , monospace",
		"FONT: \"Arial Bold\", Helvetica, monospace")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font-family:'Arial Bold' , 'Helvetica'",
		"font-family: \"Arial Bold\", Helvetica")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font-family:'Arial Bold' , 'Helvetica'",
		"font-family: 'Arial Bold', Helvetica")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font-family:'evil'",
		"font-family: 3execute evil")
	// An empty name really is empty, so it drops and leaves the separators.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font-family:'Arial Bold' , , , 'Helvetica' , sans-serif",
		"font-family: 'Arial Bold',,\"\",Helvetica,sans-serif")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font:'ChalkboardSE-Light' , 'Helvetica' , monospace",
		"FONT: \"ChalkboardSE-Light\", Helvetica, monospace")
}

// Issue #232.  Sanitizing twice must not change the result.  A font name
// containing an underscore -- which is what Word emits -- was accepted
// unquoted but rejected once quoted, so the first pass produced a name the
// second pass dropped, leaving a stray comma and invalid CSS.
func TestStylingPolicyFontFamilyIsIdempotent(t *testing.T) {
	once := "font-family:'WordVisi_MSFontService' , 'Algerian' ," +
		" 'Algerian_EmbeddedFont' , sans-serif"
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		once,
		"font-family: WordVisi_MSFontService, Algerian,"+
			" Algerian_EmbeddedFont, sans-serif")
	// The output of the first pass survives a second unchanged.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, once, once)
	// Periods and non-ASCII names round-trip too.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "font-family:'Foo.Bar_1'", "font-family: 'Foo.Bar_1'")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "font-family:'\u4e2d\u6587\u5b57\u4f53'",
		"font-family: '\u4e2d\u6587\u5b57\u4f53'")
}

// Issue #229.  A generic family is a keyword and must not be quoted, or the
// declaration stops meaning what it said.
func TestStylingPolicyGenericFontFamiliesAreNotQuoted(t *testing.T) {
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font-family:sans-serif , system-ui , -apple-system",
		"font-family: sans-serif, system-ui, -apple-system")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font-family:ui-serif , ui-sans-serif , ui-monospace , ui-rounded",
		"font-family: ui-serif, ui-sans-serif, ui-monospace, ui-rounded")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font-family:math , emoji , fangsong , cursive , fantasy",
		"font-family: math, emoji, fangsong, cursive, fantasy")
	// A real font name is still quoted.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font-family:'BlinkMacSystemFont' , sans-serif",
		"font-family: BlinkMacSystemFont, sans-serif")
}

// Both paths that emit a font name apply the same test, so a name cannot
// survive one sanitization pass and vanish on the next, and a format
// character cannot ride into the output on the unquoted path.
func TestStylingPolicyFontNamePathsAgree(t *testing.T) {
	// U+202E RIGHT-TO-LEFT OVERRIDE reorders the text around it, so it has no
	// business in a font name.  It used to be accepted unquoted and rejected
	// quoted, which also made sanitization non-idempotent.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "font-family: a\u202eb")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "font-family: 'a\u202eb'")
	// U+FEFF ZERO WIDTH NO-BREAK SPACE never reaches the output either, but
	// by a different route: quoted it is rejected here, and unquoted the
	// lexer has already split it into two identifiers.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "font-family:'a b'", "font-family: a\ufeffb")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "font-family: 'a\ufeffb'")
	// Ordinary names go through either way, and agree.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "font-family:'Foo_Bar'", "font-family: Foo_Bar")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "font-family:'Foo_Bar'", "font-family: 'Foo_Bar'")
}

// Which non-ASCII font names survive, pinned so the claim in
// stylingPolicyIsSafeQuotedIdentifier's doc comment stays honest.
// The limitation on combining marks and supplementary code points is not
// imposed here -- the CSS lexer drops them from a token before the policy
// runs, and did so before the widening in #232 as well.
func TestStylingPolicyNonAsciiFontNames(t *testing.T) {
	// Letters and digits from the basic multilingual plane go through, quoted
	// or not.
	for _, name := range []string{
		"\u0422\u0430\u0439\u043c\u0441",                   // Cyrillic
		"\u0395\u03bb\u03bb\u03b7\u03bd\u03b9\u03ba\u03ac", // Greek, precomposed accent
		"\u4e2d\u6587\u5b57\u4f53",                         // Han
		"\ub9d1\uc740\uace0\ub515",                         // Hangul
		"\u30d2\u30e9\u30ae\u30ce",                         // Katakana
		"\u0646\u0633\u062e",                               // Arabic base letters
		"\u05d0\u05dc\u05e3",                               // Hebrew base letters
	} {
		stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "font-family:'"+name+"'", "font-family: "+name)
		stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
			"font-family:'"+name+"'", "font-family: '"+name+"'")
	}

	// A combining mark does not, on either path.  This is the lexer's doing,
	// not this policy's.
	for _, name := range []string{
		"\u0646\u064e\u0633", // Arabic with fatha
		"\u0926\u0947\u0935", // Devanagari with matra
		"\u05d0\u05b8\u05dc", // Hebrew with qamats
		"\u0e1a\u0e31\u0e0d", // Thai with vowel sign
	} {
		stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "font-family: "+name)
		stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "font-family: '"+name+"'")
	}

	// Nor does a supplementary code point: U+20000, a CJK extension B
	// ideograph.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "font-family: \U00020000")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "font-family: '\U00020000'")
}

// Widening what a quoted name may contain must not let a name break out of
// the quotes it is emitted in.  The lexer hands us quotes and backslashes
// already escaped, and an escape is exactly what is rejected.
func TestStylingPolicyQuotedFontNamesCannotBreakOut(t *testing.T) {
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "font-family: 'it\\27s'")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "font-family: 'a\\5c b'")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "font-family: 'a\\22 b'")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "font-family: '</style>'")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "font-family: 'a\\a b'")
}

func TestStylingPolicyFont(t *testing.T) {
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font:'Arial' 12pt bold oblique",
		"font: Arial 12pt bold oblique")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font:'Times New Roman' 24px bolder",
		"font: \"Times New Roman\" 24px bolder")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "font:24px", "font: 24px")
	// Non-ascii characters discarded.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "font: 24ex\\pression")
	// Harmless garbage.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"font:24ex 'pression'", "font: 24ex\x00pression")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		nil, "font: expression(arial)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		nil, "font: rgb(\"expression(alert(1337))//\")")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "font-size:smaller", "font-size: smaller")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "font:smaller", "font: smaller")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "font:'ChalkboardSE-Light'", "font: 'ChalkboardSE-Light'")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "font: '---")
}

func TestStylingPolicyBidiAndAlignmentAttributes(t *testing.T) {
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"text-align:left;unicode-bidi:embed;direction:ltr",
		"Text-align: left; Unicode-bidi: Embed; Direction: LTR;")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		nil, "text-align:expression(left())")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "text-align: bogus")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "unicode-bidi:embed", "unicode-bidi:embed")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "unicode-bidi:expression(embed)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "unicode-bidi:bogus")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "direction:expression(ltr())")
}

func TestStylingPolicyTextDecoration(t *testing.T) {
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"text-decoration:underline",
		"Text-Decoration: Underline")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"text-decoration:overline",
		"text-decoration: overline")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"text-decoration:line-through",
		"text-decoration: line-through")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		nil,
		"text-decoration: expression(document.location=42)")
}

func TestStylingPolicyBoxProperties(t *testing.T) {
	// http://www.w3.org/TR/CSS2/box.html
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "height:0", "height:0")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "width:0", "width:0")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "width:20px", "width:20px")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "width:20", "width:20")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "width:100%", "width:100%")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "height:6in", "height:6in")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "width:-20")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "width:url('foo')")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "height:6fixed")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "margin:2 2 2 2", "margin:2 2 2 2")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "margin:2 2 2", "margin:2 2 2")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "padding:2 2", "padding:2 2")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "margin:2", "margin:2")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "margin:2px 4px 6px 8px", "margin:2px 4px 6px 8px")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "padding:0 4px 6px", "padding:0 4px 6px")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "margin:2px 4px 6px 4px", "margin:2px 4px 6px 4px")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "margin:0 4px", "margin:0 4px")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "margin:0 4px", "margin:0 4 px")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "padding-left:4px", "padding-left:4px")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "padding-left:0.4em;padding-top:2px;margin-bottom:3px",
		"padding-left:0.4em;padding-top:2px;margin-bottom:3px")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "padding:0 1em 0.5in 1.5cm",
		"padding:00. 1EM +00.5 In 1.50cm")
	// Mixed.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "margin:1em;margin-top:0.25em",
		"margin:1em; margin-top:.25em")
}

func TestStylingPolicyCalc(t *testing.T) {
	// https://drafts.csswg.org/css-values-4/#calc-func
	// calc() is allowed in the six sizing properties (issue #361).
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"width:calc( 100% - 20px )", "width: calc(100% - 20px)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"min-width:calc( 100% - 20px )", "min-width: calc(100% - 20px)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"max-width:calc( 100% - 20px )", "max-width: calc(100% - 20px)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"height:calc( 100% - 20px )", "height: calc(100% - 20px)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"min-height:calc( 100% - 20px )", "min-height: calc(100% - 20px)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"max-height:calc( 100% - 20px )", "max-height: calc(100% - 20px)")
	// All four operators, grouping, negative operands, and the function
	// name is case-insensitive.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"width:calc( 2 * 1em + 10px )", "width: calc(2 * 1em + 10px)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"width:calc( ( 100% - 20px ) / 2 )",
		"width: calc((100% - 20px) / 2)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"width:calc( -1 * 20px + 100% )", "width: CALC(-1 * 20px + 100%)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"width:calc( 100% - 20px ) !important",
		"width: calc(100% - 20px) !important")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"width:calc( 100% - 20px );color:red",
		"width: calc(100% - 20px); color: red")
	// Comments are dropped and unbalanced parentheses are repaired.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"width:calc( 100% - 20px )", "width: calc(100%/*a*/-/*b*/20px")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"width:calc( 100% - 20px )", "width: calc(100% - 20px))")
	// Only quantities and arithmetic survive inside calc().  Anything else
	// is stripped, leaving an invalid expression that browsers ignore.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"width:calc( )", "width: calc(expression(alert(1337)))")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"width:calc( )", "width: calc(url('//evil.org/x'))")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"width:calc( )", "width: calc(\"//evil.org/x\")")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"width:calc( 100% - )", "width: calc(100% - var(--x))")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"width:calc( 100% - )", "width: calc(100% - attr(data-x px))")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"width:calc( 100% - )",
		"width: calc(100% - env(safe-area-inset-left))")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"width:calc( 100% - )", "width: calc(100% - rgb(0, 0, 0))")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"width:calc( 100% - )", "width: calc(100% - #fff)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"width:calc( 100% - )", "width: calc(100% - auto)")
	// calc() is not allowed in properties outside the sizing set, ...
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "margin: calc(100% - 20px)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "padding-left: calc(100% - 20px)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "font-size: calc(1em + 2px)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "border-width: calc(1px + 1px)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "margin:20px", "margin: calc(100% - 20px) 20px")
	// ... and its operators are not allowed outside calc().
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "width:100% 20px", "width: 100% - 20px")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "width:20px", "width: (20px)")
}

func TestStylingPolicyCalcRequiresOptIn(t *testing.T) {
	// As with rgb() and color, a custom schema has to list calc() next to
	// the sizing property for the function to be accepted.
	widthOnly := cssSchemaMustWithProperties([]string{"width"})
	stylingPolicyAssertSanitizedCSS(t, widthOnly, "width:20px", "width: 20px")
	stylingPolicyAssertSanitizedCSS(t, widthOnly, nil, "width: calc(100% - 20px)")
	widthAndCalc := cssSchemaMustWithProperties([]string{"width", "calc()"})
	stylingPolicyAssertSanitizedCSS(t, widthAndCalc, "width:calc( 100% - 20px )", "width: calc(100% - 20px)")
}

func TestStylingPolicyLongUrls(t *testing.T) {
	// Test that a long URL does not blow out the stack or consume quadratic
	// amounts of processor as when the CSS lexer was implemented as a bunch of
	// regular expressions.
	longUrl := "" +
		"background-image:url(data:image/gif;base64," +
		"R0lGODlhMgCaAPf/AO5ZOuRpTfXSyvro5Pz08uCEb+ShkeummPOMdPOqmdZdQvbEud1" +
		"UNuqmlvqbhchNMfnTyvXPxu6pmtFkTeJ6Y9JxXPR8YNRSNvyunP3Mwd1zW+iCau9dPt" +
		"BOMe69sutwVPGGbuFcPvmRefqAZuhiQ/rJv9pFJf3h2up0WttCItmBbv3r5/26q/bc1" +
		"v3XzvHOx8tML/nf2cpAI+hfQf3GufVbOvyrmvCkk/7r5vnm4t+BbPism/apmN9DI+hN" +
		"LrkrD/x4V98+HeFBIPt0U/x2VflaOfdwT/lzUvhYN/p2VfhWNd47Gvx5WPtyUflcO+J" +
		"EI/VsS/FjQvRpSPtwT/tuTebm5vpmRfppSPlePeRIJ8XFxdRQNPpsS8I9IYyMjOhQL+" +
		"xYN+ZMK/liQflgP+1dO+pUM//188RBJZGRkff39/718vFZOcA/JtVXO8VEKPvVzeuhk" +
		"Pynk/ermsdHK/7Yz/ehjvi2p9Z4ZPre2NRDJPVkRPzz8d9NLdR1YNM2F/SkksBBKOdX" +
		"OfaHbdhsVPFbO81cQs1UOO2HcPNTM/708dd7Zt1GJuFRMd1JKfBiQvyNcuF1XfqOd+6" +
		"gj+SDbPuJb/re1/TUzeReP+mHce1zWeOdjthYPOaSgO2LdOyllPFzWPezpPe7rfVzVO" +
		"6Hb/vz8f7f2eGJdOKMee54XeBiR/Z5XeNlSfyVfPJtT++ikf7i3POrnPGun9+VhOVSM" +
		"vzo499/as1EJup5YPvUy+abi+tjRPNrS91aPfCCafyxn/SCaNVZPeu7r+B+ad1WOOuy" +
		"pOm3rPt6W/OikPvq5vCmlt6Qf/ygivp2V/OTfPrb1eKfkP7Z0OyBaeibiuieju+ciu2" +
		"ejeKCbOatn+2YhOFVN+eRfedWNvWplvLRyuF4Xs5kTdlOL+3Eu+1mR/zp5fzq5dVMLt" +
		"JTOPvDtvKgjvy1pe9yVchFKeafj+WYh/nBs/HIvv3Ctd9YONdVOM5BI8pXP/jUzOqKd" +
		"OiMd9toUN1iSONuU8HBwYmJifX19f///////yH/C1hNUCBEYXRhWE1QPD94cGFja2V0" +
		"IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1" +
		"wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIE" +
		"NvcmUgNS4wLWMwNjEgNjQuMTQwOTQ5LCAyMDEwLzEyLzA3LTEwOjU3OjAxICAgICAgI" +
		"CAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIv" +
		"MjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB" +
		"4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbn" +
		"M6c3RSZWY9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZ" +
		"VJlZiMiIHhtbG5zOnhtcD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wLyIgeG1w" +
		"TU06T3JpZ2luYWxEb2N1bWVudElEPSJ4bXAuZGlkOkEyRDgxODE2MkMyMDY4MTE4NzF" +
		"GRDNDMzU5QkE3OTE3IiB4bXBNTTpEb2N1bWVudElEPSJ4bXAuZGlkOkMzMjA1M0I4Qk" +
		"M4RjExRTBCRDBEQkE0MTlGMTc4MDZGIiB4bXBNTTpJbnN0YW5jZUlEPSJ4bXAuaWlkO" +
		"jlFQzFFMTZFQkM4RDExRTBCRDBEQkE0MTlGMTc4MDZGIiB4bXA6Q3JlYXRvclRvb2w9" +
		"IkFkb2JlIFBob3Rvc2hvcCBDUzUuMSBNYWNpbnRvc2giPiA8eG1wTU06RGVyaXZlZEZ" +
		"yb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDpDMjFGMUIwQjMyMjA2ODExODcxRk" +
		"QzQzM1OUJBNzkxNyIgc3RSZWY6ZG9jdW1lbnRJRD0ieG1wLmRpZDpBMkQ4MTgxNjJDM" +
		"jA2ODExODcxRkQzQzM1OUJBNzkxNyIvPiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6" +
		"UkRGPiA8L3g6eG1wbWV0YT4gPD94cGFja2V0IGVuZD0iciI/PgH//v38+/r5+Pf29fT" +
		"z8vHw7+7t7Ovq6ejn5uXk4+Lh4N/e3dzb2tnY19bV1NPS0dDPzs3My8rJyMfGxcTDws" +
		"HAv769vLu6ubi3trW0s7KxsK+urayrqqmop6alpKOioaCfnp2cm5qZmJeWlZSTkpGQj" +
		"46NjIuKiYiHhoWEg4KBgH9+fXx7enl4d3Z1dHNycXBvbm1sa2ppaGdmZWRjYmFgX15d" +
		"XFtaWVhXVlVUU1JRUE9OTUxLSklIR0ZFRENCQUA/Pj08Ozo5ODc2NTQzMjEwLy4tLCs" +
		"qKSgnJiUkIyIhIB8eHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgEAACH5BAEAAP" +
		"8ALAAAAAAyAJoAAAj/AP+h8EGwoMGDCBMqXOgDxb8ZUphInEixosWLGDMykTLDB5CPI" +
		"EOKHEmypEmQBImoXMmypcuXMGOuJDikps2bOHPq3MnTJsEmQJv4G0rUX9CjSJMqXXqU" +
		"4JSnRaM+nWKMxtBXy6Y8gvZoqtevYL8SpEK2KJWiCsjSMIPNlCUC6lj5u7eLrN27ePO" +
		"SJcilb1EuaPvSQaZBnAUJGkT487DCTBwulOj4M8OCSxw6vvwxYzH5cV8uBK+IHiq69F" +
		"Bgoh0MPcHCAgnF7+zFIKArw4kAufxFw+AvBixiODo18IeqNEEryItaKdoGuRUEHgj4I" +
		"6Aqkr8CIeT422QF0wEX13f4/xvEi1y9A9ob6EF+PDnR5USbW8EQydElaf4aWC/giHcb" +
		"eGbYkcB12rWhhxkCSJBAAgXMwJ4PYkQYVVEXRIgDHp+IMYI/7Rzijw4c2ODPBf4kIw8" +
		"1H/IwohgZCJDKBxAcwkGEBI1h4xgTjniBjSMMQBQuF4DwYYgjpuMPBKX4c4qKO44wzl" +
		"AlDMOBjQRhYaWVW2Sp5RZXYkEIJLUosAUDWACwBQBYBMLlLfgwwMCZalr5pQZbZHMlQ" +
		"U7kqeeefOq5BgA19LnnGoEK6sQaa+xJUBGMNuroo5BGKumkjRKExKWYZqrpppx26imm" +
		"PsyAiBKklmrqqaimquqqSiAyw0MMxf8q66yv/lPID7jmquuuvPbq668/FPIPGyGcZOy" +
		"xyIbAxg9JNOvss9BGK+201DqL6xHYZqvtttx26+232eJqxLjklmvuueimqy65uELhLh" +
		"Q5vivvvPTWa6+8uEqhb45D6SuFKOes5oAUgrggiL8IJ6xwwrhG4bBZRRnisDtqaKNCN" +
		"wQEgMB1Mzjs8ccgh+xwww8TBRhREkfxxgCDXIJCA4NsHAw5atQRxS9v+KOGHVHU8YZ4" +
		"rdihs80e40rG0aSVdsVQDxzdzFB4gPLBMKP4E441LewRTwmVKCCLP95w408LnlwzziQ" +
		"G+KPP0WTgCsbbyhUFw9tgbFAMKf7s8YGQimz/cYM/cwtjAAT+KPL3BB0MIIABfz+zzd" +
		"u4liF53ETNIfkfvTBSjjL+aBKNP3cw8oc/c4SSSCxwgO4K6bMk8gI7cMBxBziS4/rF7" +
		"fz648bttLSwyheZ+KMMBf70wccxuvszzTqcFC+J7l8s8II5+URAAR+34xrG9mHkeMYZ" +
		"23+QA1ERnEF8H42g488ZsPgTgTP+qFDN+mGIP9QCtjSyPa5Z9N9/FwAMYBf8l4VFTKA" +
		"CD+iCDLJggi6YIAt5GCA+6CEDGTgwgv0z4De6MA//4eoJIAyhCEcYwhSkoAckFOEJUw" +
		"hCE4oQV0KIoQxnSMMa2vCGOJQhroLAwx768IdADKIQ/4fYwx8Awg9LSKISl8jEJjrxi" +
		"VBcgh8AMSxgWfGKWGTDP/6hhX148YtgDKMYx0jGMu5DC1zsR+7WyMY2FqUfXXSjHOc4" +
		"IS/S8Y5ztCMe97hGPfLxj1HxIyAHKchB/rGQhtwjIhN5x0UyMo/7eOQhIylJRVKyko2" +
		"8JCYhuclMdpKOjvxkjkIpykBqspS5IyUqh6LKVbYSla8sZSxFOctP1rKTt9xkLjG5y0" +
		"r2UpJnTMMqc5cGNHbRjGVU4xuRSUY0bvGZ0IymNLe4D2X6ox/7mKY2t8lNblbzmtnsp" +
		"jjHuc1IhpOc6EznP86pzmiigR/wjKc850nPetrznvxAwz+8UP+FfvjznwANqEAHStCC" +
		"9qMKXuCHQRfK0Ib6E54OjahE/wnRiVqUoRW9qEYHmtGNevShCv2oSDsqUo2StKQWPSl" +
		"KJarSlTq0pS7FaEhjOlGY0rSgNr0pR2eq04bmtKcA/SlQQTpUn/K0qAQV6lCVClSm9t" +
		"SpOoXqTaVKU6rG1KouxepKtYpSfvATqQVF6D7xic9+ArQKZLWnF9oZTX6Y9aD8YKtc2" +
		"9pPtM71rs90a1zxyte98vWZx2SmYL/oTHRqwZqPhGM6T/lIdoqTsYx0bDchm0jJehOX" +
		"i8UsOb+py80i1pfj5KxmvflZXoa2tMD0rC3RKVrQsna0oYXtY2U7WdplclMLwqxkMdU" +
		"Z2MEKtrDofGdahytPfabzqzEVKzqPutV0Mrerzo1qdKc63aou961XJadbnzrO7XK3m9" +
		"79Lnixa93ukjer15XuctWrXfZ2173ifG5J/TpO5LpUuehMKHH3u1ZxBgQAOw==);"
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, longUrl)
}

func TestStylingPolicyUrls(t *testing.T) {
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"background-image:url('foo.gif#sanitized')",
		"background-image: \"foo.gif\"")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"background-image:url('foo.gif#sanitized')",
		"background-image: 'foo.gif'")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"background-image:url('foo.gif#sanitized')",
		"background-image:url(foo.gif)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"background-image:url('foo.gif#sanitized')",
		"background-image : url( foo.gif )")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"background-image:url('foo.gif#sanitized')",
		"background-image: url('foo.gif')")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"background-image:url('foo.gif#sanitized')",
		"background-image: URL( \"foo.gif\" )")
}

func TestStylingPolicyImportant(t *testing.T) {
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"color:blue !important",
		"color:blue !important")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"color:red !important",
		"color:red ! IMPORTANT")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"color:purple",
		"color:purple !foo(bar) important")
}

func TestStylingPolicyCdoCdc(t *testing.T) {
	// No <!-- or --> in output.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "font-family:'a--' 'b'", "font-family: a--\\>b")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "font-family:'a' '--b'", "font-family: a<\\!--b")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "font-family:'a--' 'b'", "font-family: a-->b")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "font-family:'a b'", "font-family: a<!--b")
}

// Issue #228: the text-decoration longhands and a richer shorthand.
func TestStylingPolicyTextDecorationLonghands(t *testing.T) {
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"text-decoration-line:line-through", "text-decoration-line: line-through")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "text-decoration-style:wavy", "text-decoration-style: wavy")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "text-decoration-color:red", "text-decoration-color: red")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"text-decoration-thickness:2px", "text-decoration-thickness: 2px")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"text-decoration:underline dotted red",
		"text-decoration: underline dotted red")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "text-decoration-line: url(javascript:alert(1))")
}

// Issue #265: SVG stroke paint, but never a paint-server URL.
func TestStylingPolicyStroke(t *testing.T) {
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"stroke-width:4;stroke:rgb( 138 , 232 , 242 )",
		"stroke-width: 4; stroke: rgb(138,232,242)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, "stroke:none", "stroke: none")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "stroke: url(#paintserver)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "stroke: url('javascript:alert%281337%29')")
}

// Issue #380 item 6: conic gradients alongside linear and radial.
func TestStylingPolicyConicGradient(t *testing.T) {
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"background:conic-gradient( red , blue )",
		"background: conic-gradient(red, blue)")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"background-image:repeating-conic-gradient( red , blue )",
		"background-image: repeating-conic-gradient(red, blue)")
}

// DEFAULT withholds layout control, so none of the modern layout families
// are reachable without opting in.  This is the security-relevant half of
// the change and it must keep failing closed.
func TestStylingPolicyLayoutRequiresOptIn(t *testing.T) {
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "display: block")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "display: none")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "display: flex")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "display: grid")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "grid-template-columns: 1fr 280px")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "gap: 10px")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "flex: 1 1 auto")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "order: -5")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "justify-content: center")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "transform: translate(-9999px, 0)")
}

// Issues #242 and #234: flex and grid for a policy that opts in.
func TestStylingPolicyFlexAndGridWhenOptedIn(t *testing.T) {
	stylingPolicyAssertSanitizedCSS(t, stylingPolicyTestLayout, "display:flex", "display: flex")
	stylingPolicyAssertSanitizedCSS(t, stylingPolicyTestLayout, "display:flex;flex-direction:column",
		"display: flex; flex-direction: column")
	stylingPolicyAssertSanitizedCSS(t, stylingPolicyTestLayout, "flex:1 1 auto", "flex: 1 1 auto")
	stylingPolicyAssertSanitizedCSS(t, stylingPolicyTestLayout, "order:-1", "order: -1")
	stylingPolicyAssertSanitizedCSS(t, stylingPolicyTestLayout, "justify-content:space-between", "justify-content: space-between")
	stylingPolicyAssertSanitizedCSS(t, stylingPolicyTestLayout, "display:grid", "display: grid")
	// The exact value from issue #234.
	stylingPolicyAssertSanitizedCSS(t, stylingPolicyTestLayout,
		"display:grid;grid-template-columns:repeat( auto-fit , minmax( 160px , 1fr ) )",
		"display: grid; grid-template-columns: repeat( auto-fit, minmax(160px, 1fr) )")
	// The exact value from issue #380 item 1.
	stylingPolicyAssertSanitizedCSS(t, stylingPolicyTestLayout, "grid-template-columns:1fr 280px",
		"grid-template-columns: 1fr 280px")
	stylingPolicyAssertSanitizedCSS(t, stylingPolicyTestLayout, "gap:10px 20px", "gap: 10px 20px")
	stylingPolicyAssertSanitizedCSS(t, stylingPolicyTestLayout, "grid-column:1 / 3", "grid-column: 1 / 3")
}

// Issue #71: transform functions for a policy that opts in.
func TestStylingPolicyTransformWhenOptedIn(t *testing.T) {
	stylingPolicyAssertSanitizedCSS(t, stylingPolicyTestLayout, "transform:rotate( 30deg ) translate( 10px , 20px )",
		"transform: rotate(30deg) translate(10px, 20px)")
	stylingPolicyAssertSanitizedCSS(t, stylingPolicyTestLayout, "transform:matrix( 1 , 0 , 0 , 1 , 10 , 20 )",
		"transform: matrix(1, 0, 0, 1, 10, 20)")
	stylingPolicyAssertSanitizedCSS(t, stylingPolicyTestLayout, "transform:none", "transform: none")
	stylingPolicyAssertSanitizedCSS(t, stylingPolicyTestLayout, "transform-origin:top left", "transform-origin: top left")
	// A transform function is not a way to smuggle a URL or a script.  The
	// payload is dropped and an empty function shell is left behind, which is
	// how rgb(), linear-gradient() and calc() have always behaved.
	stylingPolicyAssertSanitizedCSS(t, stylingPolicyTestLayout, "transform:translate( )",
		"transform: translate(url(javascript:alert(1)))")
	stylingPolicyAssertSanitizedCSS(t, stylingPolicyTestLayout, nil, "transform: expression(alert(1))")
	stylingPolicyAssertSanitizedCSS(t, stylingPolicyTestLayout, "transform:translate( )",
		"transform: translate(expression(alert(1)))")
}

// position:fixed escapes a scrolling container, so opting into layout must
// not bring it along.
func TestStylingPolicyFixedPositioningStaysBlockedWhenOptedIn(t *testing.T) {
	withPosition, err := CSSSchemaUnion(
		DefaultCSSSchema, cssSchemaMustWithProperties([]string{"position"}))
	if err != nil {
		t.Fatal(err)
	}
	stylingPolicyAssertSanitizedCSS(t, withPosition, "position:absolute", "position: absolute")
	stylingPolicyAssertSanitizedCSS(t, withPosition, nil, "position: fixed")
	stylingPolicyAssertSanitizedCSS(t, withPosition, nil, "position: sticky")
}

// The cap sits between these two lengths, so one URL survives and the other
// takes its whole property with it.  1024 used to sit between them, which is
// what #187 was about.
func TestStylingPolicyLongCssUrlsAreKeptUpToTheLengthCap(t *testing.T) {
	under := "http://example.com/" + strings.Repeat("a", 1500)
	over := "http://example.com/" + strings.Repeat("a", 2100)
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"background-image:url('"+under+"#sanitized')",
		"background-image: url("+under+")")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "background-image: url("+over+")")
}

// The grammar recurses once per function, so a declaration may nest
// functions only so deep; one at the limit still parses as it always has.
func TestStylingPolicyNestingAtTheLimitIsKept(t *testing.T) {
	depth := cssGrammarMaxFunctionDepth
	// As before: the schema lets no colour function nest, so the inner
	// ones go and the outer one stays.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"color:rgb( )",
		"color: "+strings.Repeat("rgb(", depth)+"1"+strings.Repeat(")", depth))
	// Bare brackets are punctuation, not recursion, and do not count.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"width:calc("+strings.Repeat(" (", 2*depth)+" 1px"+
			strings.Repeat(" )", 2*depth+1),
		"width: calc("+strings.Repeat("(", 2*depth)+"1px"+
			strings.Repeat(")", 2*depth+1))
}

// One level past the limit drops the declaration whole, and only that
// declaration: the ones before and after it are untouched.
func TestStylingPolicyNestingBeyondTheLimitDropsTheDeclaration(t *testing.T) {
	depth := cssGrammarMaxFunctionDepth + 1
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		nil,
		"color: "+strings.Repeat("rgb(", depth)+"1"+strings.Repeat(")", depth))
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"color:red;background:blue",
		"color: red; width: "+strings.Repeat("rgb(", depth)+"1"+
			strings.Repeat(")", depth)+"; background: blue")
	// A semicolon inside a function ends only that function's arguments,
	// so the declaration runs on to the one after the closes, and nothing
	// inside the dropped value comes back as a declaration of its own.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"color:red;background:blue",
		"color: red; width: "+strings.Repeat("rgb(", depth)+"; color: blue"+
			strings.Repeat(")", depth)+"; background: blue")
	// A semicolon inside a bare bracket ends the declaration, as it always
	// has, so what follows is parsed on its own and is not too deep.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"color:red;background:rgb( )",
		"width: (; color: red; background: "+strings.Repeat("rgb(", depth-1)+
			"1"+strings.Repeat(")", depth-1))
}

// A value that nests functions without bound would recurse without bound.
// It is dropped, in linear time, with or without its closes.
func TestStylingPolicyUnboundedNestingDoesNotOverflowTheStack(t *testing.T) {
	depth := 200000
	opens := strings.Repeat("rgb(", depth)
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "color: "+opens+"1"+strings.Repeat(")", depth))
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema, nil, "color: "+opens+"1")
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"color:red;background:blue",
		"color: red; width: "+opens+"1"+strings.Repeat(")", depth)+
			"; background: blue")
	// Bare brackets are punctuation, and the semicolon inside them ends the
	// declaration, as it always has.
	stylingPolicyAssertSanitizedCSS(t, DefaultCSSSchema,
		"color:red;background:blue",
		"color: red; width: "+strings.Repeat("(", depth)+"; background: blue")
}

// Shapes that made the CSS path quadratic.  A semicolon inside a bare
// bracket ends a declaration, so a scan for the end of the declaration
// that ran on to the matching close read the rest of the input once per
// declaration.  And the lexer walked the whole stack of open brackets
// for every close bracket that had no partner.  Each takes seconds when
// quadratic and well under a second here.
func TestStylingPolicyHostileBracketShapesAreLinear(t *testing.T) {
	rescan := strings.Repeat("a:(;a:)", 200000)
	stylingPolicyAssertSanitizedCSSInTime(t, "color:red", "color: red;"+rescan)
	orphans :=
		"color: " + strings.Repeat("(", 400000) + strings.Repeat("]", 400000)
	stylingPolicyAssertSanitizedCSSInTime(t, "color:red", "color: red;"+orphans)
	// Opens deep, then sets and clears the depth scan's top mark over and
	// over.  This size catches bookkeeping whose work on each close grows
	// with the depth.  The doc comment on cssGrammarSkipIfNestedTooDeeply
	// says why the marks are kept as they are.
	churn :=
		"color: red; width: " + strings.Repeat("(", 500000) +
			strings.Repeat("rgb()()", 500000)
	stylingPolicyAssertSanitizedCSSInTime(t, "color:red", churn)
}
