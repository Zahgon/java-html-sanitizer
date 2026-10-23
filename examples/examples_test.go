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

// Ported from examples/src/test/java/org/owasp/html/examples/ExamplesTest.java.

package examples

import (
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
)

// TestRunOnEmptyInput checks that each example runs to completion, and emits
// nothing, on empty input.
func TestRunOnEmptyInput(t *testing.T) {
	var ebay strings.Builder
	if err := RunEbayPolicy(strings.NewReader(""), &ebay); err != nil {
		t.Fatal(err)
	}
	if got := ebay.String(); got != "" {
		t.Errorf("ebay: got %q, want empty", got)
	}

	var slashdot strings.Builder
	if err := RunSlashdotPolicy(strings.NewReader(""), &slashdot); err != nil {
		t.Fatal(err)
	}
	if got := slashdot.String(); got != "" {
		t.Errorf("slashdot: got %q, want empty", got)
	}

	var urlText strings.Builder
	if err := RunURLTextExample(&urlText); err != nil {
		t.Fatal(err)
	}
	if got := urlText.String(); got != "" {
		t.Errorf("url text: got %q, want empty", got)
	}
}

// TestSlashdotRun exercises the Slashdot policy: allowed elements (p, b, tt,
// blockquote, a, and the custom quote and ecode) survive; align is kept but
// lower-cased; href is kept and gains rel="nofollow"; style, onclick, script
// (with its body) and a javascript: link are dropped, the latter leaving only
// its text.
func TestSlashdotRun(t *testing.T) {
	input := "<p align=\"Right\" style=\"color:red\">Hello <b>bold</b>" +
		" <tt>mono</tt> <script>alert(1)</script></p>\n" +
		"<blockquote>quoted <a href=\"http://example.com/\"" +
		" onclick=\"evil()\">link</a>" +
		" <a href=\"javascript:alert(1)\">bad</a></blockquote>\n" +
		"<quote>custom</quote><ecode>x &lt; y</ecode>"
	var out strings.Builder
	if err := RunSlashdotPolicy(strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	want := "<p align=\"right\">Hello <b>bold</b> <tt>mono</tt> </p>\n" +
		"<blockquote>quoted <a href=\"http://example.com/\"" +
		" rel=\"nofollow\">link</a> bad</blockquote>\n" +
		"<quote>custom</quote><ecode>x &lt; y</ecode>"
	if got := out.String(); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

// TestEbayRun exercises the eBay policy through RunEbayPolicy: ids,
// classes, styling, titles, fonts, on-site image URLs and sized images
// survive; event handlers, script and iframe are dropped; links gain
// rel="nofollow" and have = encoded in the URL.
func TestEbayRun(t *testing.T) {
	input := "<div id=\"listing\" class=\"item\" style=\"color: red\">\n" +
		"<h1 title=\"Sale!\">Big <font color=\"#ff0000\" size=\"3\">Sale" +
		"</font></h1>\n" +
		"<p align=\"center\" onclick=\"alert(1)\">Buy " +
		"<a href=\"http://example.com/item?id=1\">now</a>\n" +
		"<img src=\"/images/item.png\" alt=\"Item\" width=\"100\"" +
		" onerror=\"alert(1)\"></p>" +
		"<script>alert(\"bad\")</script>" +
		"<iframe src=\"http://evil.example.com/\"></iframe>\n" +
		"</div>"
	var out strings.Builder
	if err := RunEbayPolicy(strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	want := "<div id=\"listing\" class=\"item\" style=\"color:red\">\n" +
		"<h1 title=\"Sale!\">Big <font color=\"#ff0000\" size=\"3\">Sale" +
		"</font></h1>\n" +
		"<p align=\"center\">Buy " +
		"<a href=\"http://example.com/item?id&#61;1\" rel=\"nofollow\">" +
		"now</a>\n" +
		"<img src=\"/images/item.png\" alt=\"Item\" width=\"100\" /></p>\n" +
		"</div>"
	if got := out.String(); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestSanitizeRemovesScripts(t *testing.T) {
	input := "<p>Hello World</p>" +
		"<script language=\"text/javascript\">alert(\"bad\");</script>"
	sanitized := EbayPolicy.Sanitize(input)
	if want := "<p>Hello World</p>"; sanitized != want {
		t.Errorf("got %q, want %q", sanitized, want)
	}
}

func TestSanitizeRemovesOnclick(t *testing.T) {
	input := "<p onclick=\"alert(\"bad\");\">Hello World</p>"
	sanitized := EbayPolicy.Sanitize(input)
	if want := "<p>Hello World</p>"; sanitized != want {
		t.Errorf("got %q, want %q", sanitized, want)
	}
}

func TestTextAllowedInLinks(t *testing.T) {
	input := "<a href=\"../good.html\">click here</a>"
	sanitized := EbayPolicy.Sanitize(input)
	if want := "<a href=\"../good.html\" rel=\"nofollow\">click here</a>"; sanitized != want {
		t.Errorf("got %q, want %q", sanitized, want)
	}
}

// TestEbayPolicyExamplePatternsMatchExactly checks the patterns where a
// naive Go spelling would accept the wrong strings: vertical tab as
// whitespace, ASCII-only case folding and whole-value matching.
func TestEbayPolicyExamplePatternsMatchExactly(t *testing.T) {
	matcher := func(p *regexp.Regexp) func(string) bool { return p.MatchString }
	scope := matcher(examplesWholeMatch(ebayPolicyExampleIgnoreCase("(?:row|col)(?:group)?")))
	noresize := matcher(examplesWholeMatch(ebayPolicyExampleIgnoreCase("noresize")))
	tests := []struct {
		name    string
		matches func(string) bool
		value   string
		want    bool
	}{
		{"ALIGN", matcher(ebayPolicyExampleAlign), "JUSTIFY", true},
		{"ALIGN", matcher(ebayPolicyExampleAlign), "juſtify", false},
		{"ALIGN", matcher(ebayPolicyExampleAlign), "Char", true},
		{"VALIGN", matcher(ebayPolicyExampleValign), "BaseLine", true},
		{"VALIGN", matcher(ebayPolicyExampleValign), "baſeline", false},
		{"HTML_CLASS", matcher(ebayPolicyExampleHTMLClass), "a\vb", true},
		{"HTML_CLASS", matcher(ebayPolicyExampleHTMLClass), "a b", false},
		{"HTML_TITLE", matcher(ebayPolicyExampleHTMLTitle), "a\vb", true},
		{"PARAGRAPH", matcher(ebayPolicyExampleParagraph), "x\v", true},
		{"OFFSITE_URL", matcher(ebayPolicyExampleOffsiteURL), "http://a  \t", true},
		{"OFFSITE_URL", matcher(ebayPolicyExampleOffsiteURL), "http://a b", true},
		{"OFFSITE_URL", matcher(ebayPolicyExampleOffsiteURL), "\vmailto:x\v", true},
		{"OFFSITE_URL", matcher(ebayPolicyExampleOffsiteURL), " http://a", false},
		{"OFFSITE_URL", matcher(ebayPolicyExampleOffsiteURL), "http://K", true},
		{"ONSITE_URL", matcher(ebayPolicyExampleOnsiteURL), "#a_1", true},
		{"ONSITE_URL", matcher(ebayPolicyExampleOnsiteURL), "café/٠", true},
		{"ONE_CHAR", ebayPolicyExampleOneChar, "", true},
		{"ONE_CHAR", ebayPolicyExampleOneChar, "\U0001f600", true},
		{"ONE_CHAR", ebayPolicyExampleOneChar, "\xed\xa0\x80", true}, // A lone surrogate.
		{"ONE_CHAR", ebayPolicyExampleOneChar, "\n", true},
		{"ONE_CHAR", ebayPolicyExampleOneChar, "ab", false},
		{"HISTORY_BACK", matcher(ebayPolicyExampleHistoryBack), "history.go(-1)", true},
		{"HISTORY_BACK", matcher(ebayPolicyExampleHistoryBack), "JavaScript:history.go(-1)", false},
		{"scope", scope, "ROWGROUP", true},
		{"scope", scope, "rowGroup", true},
		{"scope", scope, "grouprow", false},
		{"noresize", noresize, "NoReSiZe", true},
		{"noresize", noresize, "NOREſIZE", false},
	}
	for _, tc := range tests {
		if got := tc.matches(tc.value); got != tc.want {
			t.Errorf("%s(%q) = %v, want %v", tc.name, tc.value, got, tc.want)
		}
	}
}

// TestRunDecodesAndJoinsLines checks how the test-beds decode their input
// and join its lines.
func TestRunDecodesAndJoinsLines(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"", ""},
		{"\n", ""},
		{"a\r\nb\rc\n", "a\nb\nc"},
		{"a\n\n", "a\n"},
		{"\r\r\n", "\n"},
		// Each malformed sequence becomes one U+FFFD.
		{"\xe2\x82A", "�A"},
		{"\x80\x80", "��"},
		{"\xed\xa0\x80", "�"},
		{"\xf0\x90\x80", "�"},
		{"\xf0\x90\x80A", "�A"},
		{"\xc0\xaf", "��"},
		{"\xf4\x90\x80\x80", "����"},
		{"\xe0\x80\x80", "���"},
		{"\xf8\x88\x80\x80\x80", "�����"},
		{"\xc2", "�"},
		{"\xff\x41", "�A"},
		{"\xf0\x41", "�A"},
		{"\xef\xbf\xbd\xf0\x9f\x98\x80", "�\U0001f600"},
	}
	for _, tc := range tests {
		got, err := examplesReadLines(strings.NewReader(tc.input))
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("examplesReadLines(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// examplesFailingWriter fails every write with its error.
type examplesFailingWriter struct{ err error }

func (w examplesFailingWriter) Write([]byte) (int, error) { return 0, w.err }

// TestRunStopsAtWriteError checks that a test-bed reports the first error
// writing its output.
func TestRunStopsAtWriteError(t *testing.T) {
	want := errors.New("disk full")
	for name, run := range map[string]func(io.Reader, io.Writer) error{
		"ebay":     RunEbayPolicy,
		"slashdot": RunSlashdotPolicy,
	} {
		err := run(strings.NewReader("<p>Hello</p>"), examplesFailingWriter{want})
		if err != want {
			t.Errorf("%s: got error %v, want %v", name, err, want)
		}
	}
	if err := RunURLTextExample(examplesFailingWriter{want}, "<p>Hello</p>"); err != want {
		t.Errorf("url text: got error %v, want %v", err, want)
	}
}
