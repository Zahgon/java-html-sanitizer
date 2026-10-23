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

// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/HtmlSanitizerTest.java.

package sanitizer

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// These tests compare the DOM trees that a browser-conformant HTML parser
// (validator.nu) builds from their inputs and outputs.  Go's standard
// library has no such parser, so the tests were run once against the
// reference implementation with every tree they built recorded, keyed by the parsed HTML, in
// testdata/html_sanitizer_test_browser_trees.json.gz.  A tree the Go tests
// ask for is looked up there; one that is missing means the Go code produced
// HTML that the reference implementation never did, which is itself a
// failure.
const (
	hstBrowserTreesFile = "html_sanitizer_test_browser_trees.json.gz"
	// hstNamespacedTreeKeyPrefix marks the keys of the trees that name SVG
	// and MathML elements with their namespace.
	hstNamespacedTreeKeyPrefix = "ns:"
)

var (
	hstBrowserTreesOnce sync.Once
	hstBrowserTrees     map[string]string
	hstBrowserTreesErr  error
)

// hstLoadGzippedJSON decodes a gzipped JSON file in testdata into v.
func hstLoadGzippedJSON(name string, v any) error {
	compressed, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		return err
	}
	r, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return err
	}
	defer r.Close()
	return json.NewDecoder(r).Decode(v)
}

// hstRecordedTree returns the recorded browser tree for key.
func hstRecordedTree(t testing.TB, key, html string) string {
	t.Helper()
	hstBrowserTreesOnce.Do(func() {
		hstBrowserTreesErr = hstLoadGzippedJSON(hstBrowserTreesFile, &hstBrowserTrees)
	})
	if hstBrowserTreesErr != nil {
		t.Fatalf("loading recorded browser trees: %v", hstBrowserTreesErr)
	}
	tree, ok := hstBrowserTrees[key]
	if !ok {
		t.Fatalf("no browser tree recorded for %q: the reference run never parsed it", html)
	}
	return tree
}

// hstParseAsBrowser returns the tree a browser builds from html, one node per
// line.
func hstParseAsBrowser(t testing.TB, html string) string {
	t.Helper()
	return hstRecordedTree(t, html, html)
}

// hstParseAsBrowserWithNamespaces is as hstParseAsBrowser, but naming an SVG
// or MathML element with its namespace, svg:a or math:mi, so that a tree
// comparison checks the namespace a browser gives each element and not just
// its name.
func hstParseAsBrowserWithNamespaces(t testing.TB, html string) string {
	t.Helper()
	return hstRecordedTree(t, hstNamespacedTreeKeyPrefix+html, html)
}

// hstTextOf returns the text of a browser tree from hstParseAsBrowser, in
// document order with the markup removed: what a reader sees, whatever the
// elements around it became.
func hstTextOf(browserTree string) string {
	var sb strings.Builder
	for _, line := range strings.Split(browserTree, "\n") {
		node := strings.TrimFunc(line, func(r rune) bool { return r <= ' ' })
		if len(node) >= 2 && strings.HasPrefix(node, `"`) && strings.HasSuffix(node, `"`) {
			sb.WriteString(node[1 : len(node)-1])
		}
	}
	return sb.String()
}

// hstAssertForeignInOutput asserts that every element named in foreignNames
// is an SVG or MathML element, and never an HTML one, in the browser tree of
// the sanitized input.
func hstAssertForeignInOutput(
	t testing.TB, p *PolicyFactory, input string, foreignNames []string) {
	t.Helper()
	tree := hstParseAsBrowserWithNamespaces(t, p.Sanitize(input))
	for _, name := range foreignNames {
		if !(strings.Contains(tree, "<svg:"+name+">") ||
			strings.Contains(tree, "<math:"+name+">") ||
			strings.Contains(tree, "<svg:"+name+" ") ||
			strings.Contains(tree, "<math:"+name+" ")) {
			t.Errorf("%s not foreign in\n%s", name, tree)
		}
		if strings.Contains(tree, "<"+name+">") || strings.Contains(tree, "<"+name+" ") {
			t.Errorf("%s HTML in\n%s", name, tree)
		}
	}
}

// hstLeadingSpaces counts the spaces that start line.
func hstLeadingSpaces(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

// hstElementNamePattern extracts the name from a tree line for an element.
var hstElementNamePattern = regexp.MustCompile(`^<([a-zA-Z0-9:-]+).*$`)

// hstBrowserParentOf returns the name of the parent of the first name
// element in the browser tree of html, or "" when it is a child of the
// fragment, and false if there is no such element.
func hstBrowserParentOf(t testing.TB, html, name string) (string, bool) {
	t.Helper()
	lines := strings.Split(hstParseAsBrowser(t, html), "\n")
	for i, line := range lines {
		indent := hstLeadingSpaces(line)
		if strings.TrimSpace(line) != "<"+name+">" {
			continue
		}
		for j := i - 1; j >= 0; j-- {
			above := lines[j]
			if hstLeadingSpaces(above) == indent-2 &&
				strings.HasPrefix(strings.TrimSpace(above), "<") {
				return hstElementNamePattern.ReplaceAllString(strings.TrimSpace(above), "$1"), true
			}
		}
		return "", true
	}
	return "", false
}

// hstStartTagNamePattern finds the names of the start tags in HTML.
var hstStartTagNamePattern = regexp.MustCompile(`<([a-zA-Z]+)`)

// hstForeignNamesIn returns the element names in html, except the list and
// root names.
func hstForeignNamesIn(html string) []string {
	var names []string
	for _, m := range hstStartTagNamePattern.FindAllStringSubmatch(html, -1) {
		name := strings.ToLower(m[1])
		if name != "ul" && name != "li" && name != "svg" && name != "math" &&
			!slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return names
}

// hstNest wraps inner in depth div elements.
func hstNest(inner string, depth int) string {
	return strings.Repeat("<div>", depth) + inner + strings.Repeat("</div>", depth)
}

// hstFactory builds b, failing the test if the builder reports an error.
func hstFactory(t testing.TB, b *HTMLPolicyBuilder) *PolicyFactory {
	t.Helper()
	f, err := b.ToFactory()
	if err != nil {
		t.Fatalf("ToFactory: %v", err)
	}
	return f
}

// hstIgnoringListener is a change listener that ignores every report.
type hstIgnoringListener struct{ NopHTMLChangeListener }

// DiscardedTag ignores the report.
func (hstIgnoringListener) DiscardedTag(any, string) {}

// DiscardedAttributes ignores the report.
func (hstIgnoringListener) DiscardedAttributes(any, string, ...string) {}

// hstReceiverFuncs is an HTMLStreamEventReceiver, and so an
// HTMLSanitizerPolicy, made of optional functions, for the tests' anonymous
// receivers.  A nil function ignores its event.
type hstReceiverFuncs struct {
	openDocument  func()
	closeDocument func()
	openTag       func(elementName string, attrs []string)
	closeTag      func(elementName string)
	text          func(text string)
}

func (r *hstReceiverFuncs) OpenDocument() {
	if r.openDocument != nil {
		r.openDocument()
	}
}

func (r *hstReceiverFuncs) CloseDocument() {
	if r.closeDocument != nil {
		r.closeDocument()
	}
}

func (r *hstReceiverFuncs) OpenTag(elementName string, attrs []string) {
	if r.openTag != nil {
		r.openTag(elementName, attrs)
	}
}

func (r *hstReceiverFuncs) CloseTag(elementName string) {
	if r.closeTag != nil {
		r.closeTag(elementName)
	}
}

func (r *hstReceiverFuncs) Text(text string) {
	if r.text != nil {
		r.text(text)
	}
}

// hstCollectText returns a receiver that records the text events it is
// given.
func hstCollectText(text *[]string) HTMLStreamEventReceiver {
	return &hstReceiverFuncs{text: func(s string) { *text = append(*text, s) }}
}

// hstCompletesWithin runs f, failing the test if it takes longer than limit,
// as JUnit's assertTimeoutPreemptively does.
func hstCompletesWithin[T any](t testing.TB, limit time.Duration, f func() T) T {
	t.Helper()
	done := make(chan T, 1)
	go func() { done <- f() }()
	select {
	case result := <-done:
		return result
	case <-time.After(limit):
		t.Fatalf("execution exceeded timeout of %v", limit)
		var zero T
		return zero
	}
}

// hstAssertRoundTripAndBalanced asserts that input sanitizes to expected,
// that the output is a fixed point that a browser parses the same, and that
// the events the policy emits balance.
func hstAssertRoundTripAndBalanced(t testing.TB, p *PolicyFactory, input, expected string) {
	t.Helper()
	out := p.Sanitize(input)
	if out != expected {
		t.Errorf("%s:\nwant %q\ngot  %q", input, expected, out)
	}
	again := p.Sanitize(out)
	if again != out {
		t.Errorf("%s: not a fixed point:\nwant %q\ngot  %q", input, out, again)
	}
	if a, b := hstParseAsBrowser(t, out), hstParseAsBrowser(t, again); a != b {
		t.Errorf("%s: browser trees differ:\n%s\n%s", input, a, b)
	}
	if got := p.SanitizeWithListener(input, hstIgnoringListener{}, nil); got != out {
		t.Errorf("%s: with a listener:\nwant %q\ngot  %q", input, out, got)
	}
	hstAssertBalancedPolicyEvents(t, p, input)
	hstAssertBalancedPolicyEvents(t, p, out)
}

// hstAssertBalancedPolicyEvents asserts that the policy emits balanced open
// and close events for input.
func hstAssertBalancedPolicyEvents(t testing.TB, p *PolicyFactory, input string) {
	t.Helper()
	var open []string
	var opened, closed int
	checked := &hstReceiverFuncs{
		openDocument: func() {
			if len(open) != 0 {
				t.Errorf("document opened with %v open", open)
			}
		},
		closeDocument: func() {
			if len(open) != 0 {
				t.Errorf("unclosed elements %v", open)
			}
			if opened != closed {
				t.Errorf("%d opened, %d closed", opened, closed)
			}
		},
		openTag: func(elementName string, attrs []string) {
			canonName := htmlLexerCanonicalElementName(elementName)
			if !IsVoidElement(canonName) {
				open = append(open, canonName)
				opened++
			}
		},
		closeTag: func(elementName string) {
			canonName := htmlLexerCanonicalElementName(elementName)
			if len(open) == 0 {
				t.Fatalf("unmatched close %s", canonName)
			}
			if last := open[len(open)-1]; last != canonName {
				t.Errorf("close order: want %s, got %s", last, canonName)
			}
			open = open[:len(open)-1]
			closed++
		},
	}
	Sanitize(input, p.Apply(checked), nil)
}

// hstRenamingPolicy returns an element policy that renames every element to
// output, or rejects it when output is empty.
func hstRenamingPolicy(output string) ElementPolicy {
	return ElementPolicyFunc(func(string, *[]string) (string, bool) {
		return output, output != ""
	})
}

// hstTableMutationPolicy allows a set of table, form, foreign and literal
// elements, mapping firstInput to firstOutput and secondInput to
// secondOutput.  An empty output rejects the element.
func hstTableMutationPolicy(
	t testing.TB, firstInput, firstOutput, secondInput, secondOutput string) *PolicyFactory {
	t.Helper()
	all := []string{
		"table", "caption", "colgroup", "col", "thead", "tbody", "tfoot",
		"tr", "td", "th", "form", "template", "div", "p", "span", "b",
		"strong", "i", "select", "option", "svg", "g", "foreignObject",
		"textArea", "math", "mrow", "mtext", "style", "script",
		"textarea", "noscript", "title", "xmp", "iframe", "foo", "bar",
	}
	unchanged := slices.Clone(all)
	unchanged = hstRemoveFirst(unchanged, firstInput)
	if secondInput != firstInput {
		unchanged = hstRemoveFirst(unchanged, secondInput)
	}
	b := NewHTMLPolicyBuilder().
		AllowElements(unchanged...).
		AllowElementsWithPolicy(hstRenamingPolicy(firstOutput), firstInput)
	if secondInput != firstInput {
		b.AllowElementsWithPolicy(hstRenamingPolicy(secondOutput), secondInput)
	}
	return hstFactory(t, b.AllowTextIn(
		"form", "td", "th", "div", "p", "span", "b", "strong", "i",
		"style", "script", "textarea", "noscript", "title", "xmp",
		"iframe").
		AllowWithoutAttributes(all...))
}

// hstRemoveFirst removes the first element equal to s, if any.
func hstRemoveFirst(list []string, s string) []string {
	if i := slices.Index(list, s); i >= 0 {
		return slices.Delete(list, i, i+1)
	}
	return list
}

// hstFormTablePolicy allows table parts, forms with ids, literal elements
// and foreign content.
func hstFormTablePolicy(t testing.TB) *PolicyFactory {
	t.Helper()
	return hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(
			"table", "caption", "thead", "tbody", "tfoot", "tr", "td", "th",
			"form", "div", "template", "style", "script", "textarea",
			"noscript", "b", "strong", "a", "svg", "g", "foreignObject",
			"math", "mrow", "mtext").
		AllowAttributes("id").OnElements("form").
		AllowTextIn("style", "script", "noscript"))
}

// hstHasID reports whether attrs has an id attribute with this value.
func hstHasID(attrs []string, value string) bool {
	for i := 0; i+1 < len(attrs); i += 2 {
		if attrs[i] == "id" && attrs[i+1] == value {
			return true
		}
	}
	return false
}

// hstTableFormReplacementPolicy maps form to replacement, or rejects it when
// replacement is empty, and allows table parts and literal elements.
func hstTableFormReplacementPolicy(t testing.TB, replacement string) *PolicyFactory {
	t.Helper()
	return hstFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(hstRenamingPolicy(replacement), "form").
		AllowElements(
			"table", "caption", "thead", "tbody", "tfoot", "tr", "td", "th",
			"div", "template", "style", "script", "textarea", "noscript",
			"svg", "math").
		AllowTextIn("form", "style", "script", "noscript"))
}

// hstTablePolicy allows table parts, div, p and span.
func hstTablePolicy(t testing.TB) *PolicyFactory {
	t.Helper()
	return hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(
			"table", "caption", "thead", "tbody", "tfoot", "tr", "td", "th",
			"div", "p", "span").
		AllowAttributes("class").OnElements("table", "div").
		AllowWithoutAttributes("span"))
}

// hstNoscriptStyleImg allows noscript, style with its text, and img with
// src.
func hstNoscriptStyleImg(t testing.TB) *PolicyFactory {
	t.Helper()
	return hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("noscript", "style", "img").
		AllowTextIn("style").
		AllowAttributes("src").OnElements("img").
		AllowURLProtocols("https"))
}

// hstForeignContentPolicy allows SVG and MathML elements and the HTML
// elements that interact with them.
func hstForeignContentPolicy(t testing.TB) *PolicyFactory {
	t.Helper()
	return hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(
			"svg", "math", "path", "g", "rect", "clipPath", "foreignObject",
			"desc", "annotation-xml", "textArea", "textarea", "mi", "mrow",
			"mglyph", "a", "div", "p", "font", "br", "style", "title",
			"cite", "kbd", "b", "h2", "form").
		AllowAttributes("width", "height", "viewBox").OnElements("svg").
		AllowAttributes("id", "opacity", "d").OnElements("path").
		AllowAttributes("href").OnElements("a").
		AllowAttributes("color").OnElements("font").
		AllowAttributes("encoding").OnElements("annotation-xml").
		AllowWithoutAttributes("font").
		AllowStandardURLProtocols())
}

var (
	// hstWordStart matches an ASCII letter at the start of the input or
	// after whitespace, counting the vertical tab, which Go's \s omits.
	hstWordStart = regexp.MustCompile(`(?:^|[ \t\n\x0B\f\r])([a-zA-Z])`)
	// hstSpaces matches a run of whitespace, vertical tab included.
	hstSpaces = regexp.MustCompile(`[ \t\n\x0B\f\r]+`)
)

// hstTrim trims characters at or below U+0020 from both ends of s.
func hstTrim(s string) string {
	return strings.TrimFunc(s, func(r rune) bool { return r <= ' ' })
}

// hstSanitize sanitizes html with the policy most of the older tests share,
// failing the test if the renderer reports bad HTML.
func hstSanitize(t testing.TB, html string) string {
	t.Helper()
	var sb strings.Builder
	renderer := NewHTMLStreamRendererToBuilder(&sb, func(errorMessage string) {
		t.Error(errorMessage)
	})

	policy, err := NewHTMLPolicyBuilder().
		// Allow these tags.
		AllowElements(
			"a", "b", "br", "div", "i", "iframe", "img", "input", "li",
			"ol", "p", "span", "ul", "noscript", "noframes", "noembed", "noxss").
		// And these attributes.
		AllowAttributes(
			"dir", "checked", "class", "href", "id", "target", "title", "type",
			"__foo", "__bar", "foo-bar").
		Globally().
		// Cleanup IDs and CLASSes and prefix them with p- to move to a
		// separate name-space.
		AllowAttributes("id", "class").
		Matching(AttributePolicyFunc(func(elementName, attributeName, value string) (string, bool) {
			value = hstWordStart.ReplaceAllString(value, " p-$1")
			return hstTrim(hstSpaces.ReplaceAllString(value, " ")), true
		})).
		Globally().
		AllowStyling().
		// Don't throw out useless <img> and <input> elements to ease
		// debugging.
		AllowWithoutAttributes("img", "input").
		Build(renderer)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	Sanitize(html, policy, nil)

	return sb.String()
}

// hstAssertEqual fails the test if got is not want.
func hstAssertEqual[T comparable](t testing.TB, want, got T, msgAndArgs ...any) {
	t.Helper()
	if want != got {
		t.Errorf("%swant %#v\ngot  %#v", hstMessage(msgAndArgs), want, got)
	}
}

// hstAssertTrue fails the test if cond is false.
func hstAssertTrue(t testing.TB, cond bool, msgAndArgs ...any) {
	t.Helper()
	if !cond {
		t.Errorf("%sexpected true", hstMessage(msgAndArgs))
	}
}

// hstAssertFalse fails the test if cond is true.
func hstAssertFalse(t testing.TB, cond bool, msgAndArgs ...any) {
	t.Helper()
	if cond {
		t.Errorf("%sexpected false", hstMessage(msgAndArgs))
	}
}

// hstMessage formats an optional assertion message, as the trailing message
// argument of a JUnit assertion: a format string and its arguments.
func hstMessage(msgAndArgs []any) string {
	if len(msgAndArgs) == 0 {
		return ""
	}
	format, ok := msgAndArgs[0].(string)
	if !ok {
		return fmt.Sprint(msgAndArgs...) + ":\n"
	}
	if len(msgAndArgs) == 1 {
		return format + ":\n"
	}
	return fmt.Sprintf(format, msgAndArgs[1:]...) + ":\n"
}

// hstP1TagRecorder is a change listener that records the names of the tags
// it hears were discarded and ignores the other reports.
type hstP1TagRecorder struct {
	NopHTMLChangeListener
	discarded *[]string
}

// DiscardedTag records elementName.
func (l hstP1TagRecorder) DiscardedTag(context any, elementName string) {
	*l.discarded = append(*l.discarded, elementName)
}

// DiscardedAttributes ignores the report.
func (hstP1TagRecorder) DiscardedAttributes(any, string, ...string) {}

// hstP1Rechunker is a preprocessor's receiver that hands text on in chunks
// of size UTF-16 code units, as a preprocessor may.
type hstP1Rechunker struct {
	HTMLStreamEventReceiverWrapper
	size int
}

// Text forwards text in chunks.
func (w hstP1Rechunker) Text(text string) {
	n := utf16Length(text)
	for i := 0; i < n; i += w.size {
		w.Underlying.Text(utf16Substring(text, i, min(n, i+w.size)))
	}
}

// hstP1Rechunking returns a preprocessor that re-chunks text into blocks of
// size code units.
func hstP1Rechunking(size int) HTMLStreamEventProcessor {
	return HTMLStreamEventProcessorFunc(func(r HTMLStreamEventReceiver) HTMLStreamEventReceiver {
		return hstP1Rechunker{HTMLStreamEventReceiverWrapper{Underlying: r}, size}
	})
}

// hstP1Recaser is a preprocessor's receiver that hands on the tags of the
// custom element under the name CusTom.
type hstP1Recaser struct{ HTMLStreamEventReceiverWrapper }

// OpenTag forwards the tag under its new name.
func (w hstP1Recaser) OpenTag(elementName string, attrs []string) {
	w.Underlying.OpenTag(w.recase(elementName), attrs)
}

// CloseTag forwards the tag under its new name.
func (w hstP1Recaser) CloseTag(elementName string) {
	w.Underlying.CloseTag(w.recase(elementName))
}

func (hstP1Recaser) recase(elementName string) string {
	if elementName == "custom" {
		return "CusTom"
	}
	return elementName
}

// TestTextSurvivesPastTheNestingLimit covers issue #205.  The nesting limit
// bounds how deep the output nests; it is not a licence to delete content.
// Markup nested past the limit used to come out as a well-formed stack of
// empty elements with the author's text removed from the middle, silently.
// It should flatten instead.
func TestTextSurvivesPastTheNestingLimit(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().AllowElements("div"))
	for _, depth := range []int{100, 255, 256, 257, 300, 1000} {
		hstAssertTrue(t, strings.Contains(p.Sanitize(hstNest("MARKER", depth)), "MARKER"),
			fmt.Sprintf("text should survive at depth %d", depth))
	}
	// The output itself stays bounded; it is the text that is kept.
	deep := p.Sanitize(hstNest("MARKER", 1000))
	hstAssertEqual(t, 256, strings.Count(deep, "<div>"))
	hstAssertEqual(t, 256, strings.Count(deep, "</div>"))
}

// TestElementAtDefaultNestingLimitRoundTrips: the element at the 256th level
// is emitted and must also be closed.
func TestElementAtDefaultNestingLimitRoundTrips(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("div", "span", "p").
		AllowWithoutAttributes("span"))
	input := hstNest("<span>x</span><p>y</p>", 255)
	out := p.Sanitize(input)

	hstAssertEqual(t, input, out)
	hstAssertEqual(t, out, p.Sanitize(out))
	hstAssertEqual(t, hstParseAsBrowser(t, input), hstParseAsBrowser(t, out))
}

// TestTextKeptPastTheNestingLimitIsEscaped covers issue #205.  Text kept past
// the limit is still text: it is escaped on the way out and cannot
// reintroduce markup.
func TestTextKeptPastTheNestingLimitIsEscaped(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().AllowElements("div"))
	out := p.Sanitize(hstNest("1<2 & <img src=x onerror=alert(1)>", 300))
	hstAssertTrue(t, strings.Contains(out, "1&lt;2"), out)
	hstAssertFalse(t, strings.Contains(out, "<img"), out)
	hstAssertFalse(t, strings.Contains(out, "onerror"), out)
}

// TestSuppressedContentDoesNotResurfacePastTheNestingLimit: keeping text past
// the limit must not resurface content the policy would have suppressed.  The
// policy decides to skip a script or style body when it sees the start tag; a
// tag the balancer drops never reaches it, so the balancer has to keep that
// content suppressed itself.
func TestSuppressedContentDoesNotResurfacePastTheNestingLimit(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().AllowElements("div"))
	for _, elementName := range []string{
		"script", "style", "noscript", "nostyle", "noembed", "noframes",
		"iframe", "object", "title",
	} {
		out := p.Sanitize(
			hstNest("<"+elementName+">SECRET</"+elementName+">", 300))
		hstAssertFalse(t, strings.Contains(out, "SECRET"),
			elementName+" content should stay suppressed: "+out)
	}
	// Unbalanced input fails closed rather than open.
	hstAssertFalse(t, strings.Contains(p.Sanitize(hstNest("<script>SECRET", 300)), "SECRET"))
	hstAssertFalse(t, strings.Contains(
		p.Sanitize(hstNest("<script><script>SECRET</script></script>", 300)), "SECRET"))
	// But ordinary text outside the suppressed element still comes through.
	hstAssertTrue(t, strings.Contains(
		p.Sanitize(hstNest("<script>S</script>VISIBLE", 300)), "VISIBLE"))

	// The same holds for an element the policy, rather than the fixed list,
	// says to suppress text in: the balancer has to ask the policy.
	q := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("div").DisallowTextIn("template"))
	deep := hstNest("<template>SECRET</template>", 300)
	hstAssertFalse(t, strings.Contains(q.Sanitize(deep), "SECRET"))
	// Also with an HtmlChangeReporter between the balancer and the policy.
	hstAssertFalse(t, strings.Contains(
		q.SanitizeWithListener(deep, hstIgnoringListener{}, nil), "SECRET"))
	// And the template's text still shows where nothing disallows it.
	hstAssertTrue(t, strings.Contains(p.Sanitize(deep), "SECRET"))
}

// TestLongRunOfUnknownTagsIsLinear: the balancer forwards tags it does not
// recognize without counting them toward the nesting limit, so a run of them
// is the one way to grow the policy's open-element stack without bound.
// Nothing on the per-tag or per-text path may walk that stack, or a few
// hundred kilobytes of unknown tags cost seconds of CPU.  Quadratic behaviour
// takes minutes here; linear takes a fraction of a second.
func TestLongRunOfUnknownTagsIsLinear(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().AllowElements("div"))
	const n = 200_000
	input := "<div>" + strings.Repeat("<zz>a", n) + strings.Repeat("</zz>", n) + "</div>"
	expected := "<div>" + strings.Repeat("a", n) + "</div>"
	out := hstCompletesWithin(t, 20*time.Second, func() string { return p.Sanitize(input) })
	hstAssertEqual(t, expected, out)
}

// TestNestingLimitReportsDiscardedTags covers issue #205.  A tag dropped for
// exceeding the nesting limit is discarded from the input, so a listener
// should hear about it.  The tag balancer runs upstream of the policy, and so
// upstream of HtmlChangeReporter, so this previously went unreported and the
// loss was undetectable.
func TestNestingLimitReportsDiscardedTags(t *testing.T) {
	var discarded []string
	listener := hstP1TagRecorder{discarded: &discarded}
	p := hstFactory(t, NewHTMLPolicyBuilder().AllowElements("div"))

	out := p.SanitizeWithListener(hstNest("MARKER", 300), listener, nil)
	hstAssertTrue(t, strings.Contains(out, "MARKER"))
	// 300 requested, 256 emitted, so 44 were dropped by the limit.
	hstAssertEqual(t, 44, len(discarded), fmt.Sprint(discarded))
	for _, name := range discarded {
		hstAssertEqual(t, "div", name)
	}

	// Nothing to report when the input stays within the limit.
	discarded = discarded[:0]
	p.SanitizeWithListener(hstNest("MARKER", 10), listener, nil)
	hstAssertEqual(t, 0, len(discarded), fmt.Sprint(discarded))
}

// TestEmpty covers the empty input.
func TestEmpty(t *testing.T) {
	hstAssertEqual(t, "", hstSanitize(t, ""))
}

func TestSimpleText(t *testing.T) {
	hstAssertEqual(t, "hello world", hstSanitize(t, "hello world"))
}

func TestEntities1(t *testing.T) {
	hstAssertEqual(t, "&lt;hello world&gt;", hstSanitize(t, "&lt;hello world&gt;"))
}

func TestEntities2(t *testing.T) {
	hstAssertEqual(t, "<b>hello <i>world</i></b>",
		hstSanitize(t, "<b>hello <i>world</i></b>"))
}

func TestC1NumericReferencesAreWindows1252(t *testing.T) {
	// "&#x85;" is an ellipsis in a browser, not the NEL control.  The
	// ellipsis is written back as a reference since its compatibility
	// decomposition is three full stops.
	hstAssertEqual(t,
		"<b>a&#x2026;b</b>",
		Formatting.Sanitize("<b>a&#x85;b</b>"))
	hstAssertEqual(t,
		"<b>a€b</b>",
		Formatting.Sanitize("<b>a&#128;b</b>"))
	// An undefined Windows-1252 byte stays a control and is removed.
	hstAssertEqual(t,
		"<b>ab</b>",
		Formatting.Sanitize("<b>a&#x81;b</b>"))
}

func TestUnknownTagsRemoved(t *testing.T) {
	hstAssertEqual(t, "<b>hello <i>world</i></b>",
		hstSanitize(t, "<b>hello <bogus></bogus><i>world</i></b>"))
}

func TestUnsafeTagsRemoved(t *testing.T) {
	hstAssertEqual(t, "<b>hello <i>world</i></b>",
		hstSanitize(t, "<b>hello <i>world</i>"+
			"<script src=foo.js></script></b>"))
}

func TestUnsafeAttributesRemoved(t *testing.T) {
	hstAssertEqual(t,
		"<b>hello <i>world</i></b>",
		hstSanitize(t, "<b>hello <i onclick=\"takeOverWorld(this)\">world</i></b>"))
}

func TestCruftEscaped(t *testing.T) {
	hstAssertEqual(t, "<b>hello <i>world&lt;</i></b> &amp; tomorrow the universe",
		hstSanitize(t,
			"<b>hello <i>world<</i></b> & tomorrow the universe"))
}

func TestTagCruftRemoved(t *testing.T) {
	hstAssertEqual(t, "<b id=\"p-foo\">hello <i>world&lt;</i></b>",
		hstSanitize(t, "<b id=\"foo\" / -->hello <i>world<</i></b>"))
}

func TestIdsAndClassesPrefixed(t *testing.T) {
	hstAssertEqual(t,
		"<b id=\"p-foo\" class=\"p-boo p-bar p-baz\">"+
			"hello <i>world&lt;</i></b>",
		hstSanitize(t,
			"<b id=\"foo\" class=\"boo bar baz\">hello <i>world<</i></b>"))
}

func TestSpecialCharsInAttributes(t *testing.T) {
	hstAssertEqual(t,
		"<b title=\"a&lt;b &amp;&amp; c&gt;b\">bar</b>",
		hstSanitize(t, "<b title=\"a<b && c>b\">bar</b>"))
}

func TestUnclosedTags(t *testing.T) {
	hstAssertEqual(t, "<div id=\"p-foo\">Bar<br />Baz</div>",
		hstSanitize(t, "<div id=\"foo\">Bar<br>Baz"))
}

func TestUnopenedTags(t *testing.T) {
	hstAssertEqual(t, "Foo<b>Bar</b>Baz",
		hstSanitize(t, "Foo<b></select>Bar</b></b>Baz</select>"))
}

func TestUnsafeEndTags(t *testing.T) {
	hstAssertEqual(t,
		"",
		hstSanitize(t,
			"</meta http-equiv=\"refesh\""+
				" content=\"1;URL=http://evilgadget.com\">"))
}

func TestEmptyEndTags(t *testing.T) {
	hstAssertEqual(t, "<input />", hstSanitize(t, "<input></input>"))
}

func TestOnLoadStripped(t *testing.T) {
	hstAssertEqual(t,
		"<img />",
		hstSanitize(t, "<img src=http://foo.com/bar ONLOAD=alert(1)>"))
}

func TestClosingTagParameters(t *testing.T) {
	hstAssertEqual(t,
		"<p>Hello world</p>",
		hstSanitize(t, "<p>Hello world</b style=\"width:expression(alert(1))\">"))
}

func TestOptionalEndTags(t *testing.T) {
	// Should not be
	//     "<ol> <li>A</li> <li>B<li>C </li></li></ol>"
	// The difference is significant because in the first, the item contains no
	// space after 'A", but in the third, the item contains 'C' and a space.
	hstAssertEqual(t,
		"<ol><li>A</li><li>B</li><li>C </li></ol>",
		hstSanitize(t, "<ol> <li>A</li> <li>B<li>C </ol>"))
}

func TestFoldingOfHtmlAndBodyTags(t *testing.T) {
	hstAssertEqual(t,
		"<p>P 1</p>",
		hstSanitize(t, "<html><head><title>Foo</title></head>"+
			"<body><p>P 1</p></body></html>"))
	hstAssertEqual(t,
		"Hello",
		hstSanitize(t, "<body bgcolor=\"blue\">Hello</body>"))
	hstAssertEqual(t,
		"<p>Foo</p><p>One</p><p>Two</p>Three<p>Four</p>",
		hstSanitize(t,
			"<html>"+
				"<head>"+
				"<title>Blah</title>"+
				"<p>Foo</p>"+
				"</head>"+
				"<body>"+
				"<p>One"+
				"<p>Two</p>"+
				"Three"+
				"<p>Four</p>"+
				"</body>"+
				"</html>"))
}

func TestEmptyAndValuelessAttributes(t *testing.T) {
	hstAssertEqual(t,
		"<input checked=\"checked\" type=\"checkbox\" id=\"\" class=\"\" />",
		hstSanitize(t, "<input checked type=checkbox id=\"\" class=>"))
}

func TestAllowedAttributes(t *testing.T) {
	hstAssertEqual(t,
		"<div __foo=\"__foo\" __bar=\"foo\" foo-bar=\"foo-bar\"></div>",
		hstSanitize(t, "<div __foo __bar=\"foo\" foo-bar></div>"))
}

func TestSgmlShortTags(t *testing.T) {
	// We make no attempt to correctly handle SGML short tags since they are
	// not implemented consistently across browsers, and have been removed from
	// HTML 5.
	//
	// According to http://www.w3.org/QA/2007/10/shorttags.html
	//      Shorttags - the odd side of HTML 4.01
	//      ...
	//      It uses an ill-known feature of SGML called shorthand markup, which
	//      was authorized in HTML up to HTML 4.01. But what used to be a "cool"
	//      feature for SGML experts becomes a liability in HTML, where the
	//      construct is more likely to appear as a typo than as a conscious
	//      choice.
	//
	//      All could be fine if this form typo-that-happens-to-be-legal was
	//      properly implemented in contemporary HTML user-agents. It is not.
	// Short-tag discarded, and since the input ends inside the tag, the tag
	// goes with it, as in a browser (#410).
	hstAssertEqual(t, "", hstSanitize(t, "<p/b/"))
	hstAssertEqual(t, "<p></p>", hstSanitize(t, "<p<b>")) // Discard <b attribute
	hstAssertEqual(t,
		// This behavior for short tags is not ideal, but it is safe.  The
		// "</>" is nothing to a browser, and nothing here (#410).
		"<p href=\"/\">first part of the text second part</p>",
		hstSanitize(t, "<p<a href=\"/\">first part of the text</> second part"))
}

func TestNul(t *testing.T) {
	hstAssertEqual(t,
		"<a title="+
			"\"harmless  SCRIPT&#61;javascript:alert(1) ignored&#61;ignored\">"+
			"</a>",
		hstSanitize(t,
			"<A TITLE="+
				"\"harmless\x00  SCRIPT=javascript:alert(1) ignored=ignored\">"))
}

func TestDigitsInAttrNames(t *testing.T) {
	// See bug 614 for details.
	hstAssertEqual(t,
		"<div>Hello</div>",
		hstSanitize(t,
			"<div style1=\"expression('alert(1)\")\">Hello</div>"))
}

func TestSupplementaryCodepointEncoding(t *testing.T) {
	// &#xd87e;&#xdc1a; is not appropriate.
	// &#x2f81a; is appropriate as is the unencoded form.
	hstAssertEqual(t,
		"&#x2f81a; | &#x2f81a; | &#x2f81a;",
		hstSanitize(t, "&#x2F81A; | \U0002F81A | &#xd87e;&#xdc1a;"))
}

func TestDeeplyNestedTagsDoS(t *testing.T) {
	sanitized := hstSanitize(t, strings.Repeat("<div>", 20000))
	n := len(sanitized) / len("<div></div>")
	hstAssertTrue(t, 50 <= n && n <= 1000, fmt.Sprint(n))
	middle := n * len("<div>")
	hstAssertEqual(t, sanitized[:middle], strings.Repeat("<div>", n))
	hstAssertEqual(t, sanitized[middle:], strings.Repeat("</div>", n))
}

func TestInnerHTMLIE8(t *testing.T) {
	// Apparently, in quirks mode, IE8 does a poor job producing innerHTML
	// values.  Given
	//     <div attr="``foo=bar">
	// we encode &#96; but if JavaScript does:
	//    nodeA.innerHTML = nodeB.innerHTML;
	// and nodeB contains the DIV above, then IE8 will produce
	//     <div attr=``foo=bar>
	// as the value of nodeB.innerHTML and assign it to nodeA.
	// IE8's HTML parser treats `` as a blank attribute value and foo=bar
	// becomes a separate attribute.
	// Adding a space at the end of the attribute prevents this by forcing
	// IE8 to put double quotes around the attribute when computing
	// nodeB.innerHTML.
	hstAssertEqual(t,
		"<div title=\"&#96;&#96;onmouseover&#61;alert(1337) \"></div>",
		hstSanitize(t, "<div title=\"``onmouseover=alert(1337)\">"))
}

func TestNabobsOfNegativism(t *testing.T) {
	// Treating <noscript> as raw-text gains us nothing security-wise
	// and we don't want to push tag content outside.
	cases := []struct{ want, input string }{
		{"<noscript></noscript>",
			"<noscript><evil></noscript>"},
		{"<noscript>I <b>&lt;3</b> Ponies</noscript>",
			"<noscript>I <b><3</b> Ponies</noscript>"},
		{"<noscript>I <b>&lt;3</b> Ponies</noscript>",
			"<NOSCRIPT>I <b><3</b> Ponies</noscript><evil>"},
		{"<noframes>I <b>&lt;3</b> Ponies</noframes>",
			"<noframes>I <b><3</b> Ponies</noframes><evil>"},
		{"<noembed>I <b>&lt;3</b> Ponies</noembed>",
			"<noembed>I <b><3</b> Ponies</noembed><evil>"},
		{"<noxss>I <b>&lt;3</b> Ponies</noxss>",
			"<noxss>I <b><3</b> Ponies</noxss><evil>"},
		{"&lt;noscript&gt;I &lt;b&gt;&lt;3&lt;/b&gt; Ponies&lt;/noscript&gt;",
			"<xmp><noscript>I <b><3</b> Ponies</noscript></xmp>"},
	}
	for _, c := range cases {
		hstAssertEqual(t, c.want, hstSanitize(t, c.input))
	}
}

func TestNULs(t *testing.T) {
	cases := []struct{ want, input string }{
		{"<b>Hello, </b>", "<b>Hello, \x00</b>"},
		{"<b>Hello, </b>", "<b>Hello, \x00"},
		{"", "\x00"},
		{"<b>Hello, </b>", "<b>Hello, &#0;</b>"},
		{"", "&#0;"},
	}
	for _, c := range cases {
		hstAssertEqual(t, c.want, hstSanitize(t, c.input))
	}
}

func TestDegenerateComments(t *testing.T) {
	cases := []struct{ want, input string }{
		// Issue #258: a comment opened by <!-- and closed by --!> after nothing
		// but dashes must not swallow the rest of the document.
		{"<b>after</b>", "<!----!><b>after</b>"},
		{"<b>after</b>", "<!-----!><b>after</b>"},
		// <!-> is an empty bogus comment, not a directive that runs to the
		// next '>' and eats the following tag.
		{"c<b>after</b>", "<!->c<b>after</b>"},
		// Other complete empty comments.
		{"x", "<!>x"},
		{"x", "<!-->x"},
		{"x", "<!--->x"},
		// Fewer than two dashes after <!-- leave !> as comment content, so the
		// comment runs to the end of input, as it does in a browser.
		{"", "<!--!><b>after</b>"},
		{"", "<!---!><b>after</b>"},
		// Only a contiguous --> or --!> closes a comment; a lone dash followed
		// later by -> does not, so these comments also run to end of input.
		{"", "<!-- a -x-><b>after</b>"},
		{"", "<!-- a --b-><b>after</b>"},
		{"<b>after</b>", "<!-- a -x--><b>after</b>"},
	}
	for _, c := range cases {
		hstAssertEqual(t, c.want, hstSanitize(t, c.input), c.input)
	}
}

func TestQMarkMeta(t *testing.T) {
	hstAssertEqual(t,
		"Hello, <b>World</b>!",
		hstSanitize(t,
			""+
				// An XML Prologue.
				// HTML5 treats it as ignorable content via the bogus comment state.
				"<?xml version=\"1\" ?>"+
				"Hello, "+
				// An XML Processing instruction.
				// HTML5 treats it as ignorable content via the bogus comment state.
				"<?processing instruction?>"+
				"<b>World"+
				// Appears in HTML copied from outlook.
				"<?xml:namespace prefix = o ns = "+
				"\"urn:schemas-microsoft-com:office:office\" />"+
				"</b>!"))
}

func TestScriptInIframe(t *testing.T) {
	hstAssertEqual(t,
		"<iframe></iframe>",
		hstSanitize(t,
			"<iframe>\n"+
				"  <script>alert(Hi)</script>\n"+
				"</iframe>"))
}

func TestBalancingOfEmptyTags(t *testing.T) {
	hstAssertEqual(t,
		"<span style=\"color:rgb( 72 , 72 , 72 );font-family:&#39;helveticaneue&#39;\">"+
			" "+
			"my \u00a0"+
			" list of style names or a "+
			"</span>",
		hstSanitize(t,
			"<span style=\"color:rgb(72, 72, 72); font-family:helveticaneue\">"+
				" "+
				"<span>my &nbsp;</span>"+
				" list of style names or a "+
				"</span>"))
}

func TestDuplicateAttributes(t *testing.T) {
	hstAssertEqual(t,
		hstSanitize(t, "<br id=\"foo\">"),
		hstSanitize(t, "<br id=foo id=bar>"))
}

func TestNbsps(t *testing.T) {
	input := "test&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;bob"

	policy := hstFactory(t, NewHTMLPolicyBuilder())

	got := policy.Sanitize(input)
	codeUnits := utf16Units(got)

	want := []uint16{
		116, 101, 115, 116,
		160, 160, 160, 160, 160, 160, 160, 160,
		98, 111, 98,
	}
	hstAssertTrue(t, slices.Equal(want, codeUnits), fmt.Sprint(codeUnits))
}

func TestIssue254SemicolonlessNamedCharactersInUrls(t *testing.T) {
	input := "<a href=\"/test/?param1=valueOne&param2=valueTwo\">click me</a>"
	want := "<a href=\"/test/?param1&#61;valueOne&amp;param2&#61;valueTwo\">click me</a>"
	hstAssertEqual(t, want, hstSanitize(t, input))
}

func TestStylingCornerCase(t *testing.T) {
	input := "<a style=\\006-\\000038"
	want := ""
	hstAssertEqual(t, want, hstSanitize(t, input))
}

// These tests cover regression scenarios for CVE-2025-66021, which relates
// to improper sanitization of HTML content involving <style> and <noscript>
// tags.  The tests ensure that HTMLSanitizer:
//   - properly closes any opened elements,
//   - only allows allowed elements inside <style> blocks,
//   - prevents injection of forbidden HTML or scripts within style or
//     noscript,
//   - does not allow unexpected element escape or context breaking.

// hstP1StyleNoscriptPolicy allows style, with its text, noscript and the
// extra elements.
func hstP1StyleNoscriptPolicy(t *testing.T, extra ...string) *PolicyFactory {
	t.Helper()
	return hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(append([]string{"style", "noscript"}, extra...)...).
		AllowTextIn("style"))
}

// TestCVE202566021_1 verifies that unallowed elements (<div>) injected inside
// <style> are removed, and only allowed content (CSS and allowed elements)
// remain.
func TestCVE202566021_1(t *testing.T) {
	// Arrange: Attempt to inject a <div> inside <style>. Only 'style' and
	// 'noscript' are allowed.
	actualPayload := "<noscript><style>/* user content */.x { font-size: 12px; }<div id=\"evil\">XSS?</div></style></noscript>"
	expectedPayload := "<noscript><style>/* user content */.x { font-size: 12px; }</style></noscript>"

	policy := hstP1StyleNoscriptPolicy(t)

	// Act
	sanitized := policy.Sanitize(actualPayload)

	// Assert
	hstAssertEqual(t, expectedPayload, sanitized)
}

// TestCVE202566021_2 ensures that <script> tags (attempting script injection)
// are stripped out even when they appear inside allowed <style> tags.
func TestCVE202566021_2(t *testing.T) {
	// Arrange: Attempt to inject a <script> inside <style>. Only 'style' and
	// 'noscript' are allowed.
	actualPayload := "<noscript><style>/* user content */.x { font-size: 12px; }<script>alert('XSS Attack!')</script></style></noscript>"
	expectedPayload := "<noscript><style>/* user content */.x { font-size: 12px; }</style></noscript>"

	policy := hstP1StyleNoscriptPolicy(t)

	// Act
	sanitized := policy.Sanitize(actualPayload)

	// Assert
	hstAssertEqual(t, expectedPayload, sanitized)
}

// TestCVE202566021_3: a tag inside style text is text to a browser, never
// markup, so even an allowed element's tag goes, content and all.  It used to
// be copied through with its attributes unvetted, which is how an event
// handler could follow the breakout in test #7.
func TestCVE202566021_3(t *testing.T) {
	// Arrange: <div> is allowed as an element, which buys it nothing as style
	// text.
	actualPayload := "<noscript><style>/* user content */.x { font-size: 12px; }<div id=\"good\">ALLOWED?</div></style></noscript>"
	expectedPayload := "<noscript><style>/* user content */.x { font-size: 12px; }</style></noscript>"

	policy := hstP1StyleNoscriptPolicy(t, "div")

	// Act
	sanitized := policy.Sanitize(actualPayload)

	// Assert
	hstAssertEqual(t, expectedPayload, sanitized)
}

// TestCVE202566021_4 confirms that an attempt to prematurely close <style>
// with </noscript>, then inject a script, does not allow the injected script.
// The </noscript> goes too: a browser with scripting on reads noscript as raw
// text up to the first </noscript> and parses whatever follows as markup, so
// no end tag may survive in style text, whatever element it names.
func TestCVE202566021_4(t *testing.T) {
	// Arrange: Try to break out of <style> and <noscript>, then add a script.
	// Only style/noscript/p allowed.
	actualPayload := "<noscript><style></noscript><script>alert(1)</script>"
	expectedPayload := "<noscript><style></style></noscript>"

	policy := hstP1StyleNoscriptPolicy(t, "p")

	// Act
	sanitized := policy.Sanitize(actualPayload)

	// Assert
	hstAssertEqual(t, expectedPayload, sanitized)
}

// TestCVE202566021_5 is like test #4, but with <p> instead of <noscript>.
// Ensures sanitizer emits correctly closed tags and strips the injected
// script tag completely.  The </p> in the style text goes like every other
// end tag there, allowed element or not.
func TestCVE202566021_5(t *testing.T) {
	// Arrange: Try to break out of <style> through <p>, then add a script.
	// Only style/noscript/p allowed.
	actualPayload := "<p><style></p><script>alert(1)</script>"
	expectedPayload := "<p><style></style></p>"

	policy := hstP1StyleNoscriptPolicy(t, "p")

	// Act
	sanitized := policy.Sanitize(actualPayload)

	// Assert
	hstAssertEqual(t, expectedPayload, sanitized)
}

// TestCVE202566021_6 tests that <script> tags with space < script> are
// sanitized correctly.
func TestCVE202566021_6(t *testing.T) {
	// Arrange: Attempt to inject a <script> inside <style>. Only 'style' and
	// 'noscript' elements are allowed.
	actualPayload := "<noscript><style>/* user content */.x { font-size: 12px; }< script>alert('XSS Attack!')</script></style></noscript>"
	expectedPayload := "<noscript><style>/* user content */.x { font-size: 12px; }</style></noscript>"

	policy := hstP1StyleNoscriptPolicy(t)

	// Act
	sanitized := policy.Sanitize(actualPayload)

	// Assert
	hstAssertEqual(t, expectedPayload, sanitized)
}

// TestCVE202566021_7AllowedElementInStyleTextKeepsNoAttributes: an allowed
// element's start tag inside style text used to be copied through with its
// attributes unvetted, and an end tag was kept when its element was allowed.
// Together they let an event handler follow a </noscript> that a browser with
// scripting on honours as the end of the raw-text noscript.  Neither
// survives.
func TestCVE202566021_7AllowedElementInStyleTextKeepsNoAttributes(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("noscript", "style", "img", "b").
		AllowTextIn("style").
		AllowAttributes("src").OnElements("img").
		AllowURLProtocols("https"))

	hstAssertEqual(t,
		"<noscript><style></style></noscript>",
		policy.Sanitize(
			"<noscript><style></noscript>"+
				"<img src=x onerror=alert(1)></style></noscript>"))
	hstAssertEqual(t,
		"<noscript><style></style></noscript>",
		policy.Sanitize(
			"<noscript><style></noscript>"+
				"<b onmouseover=alert(1)>x</b></style></noscript>"))
	// Outside any noscript the same tag is harmless, and treated the same.
	hstAssertEqual(t,
		"<style></style>",
		policy.Sanitize("<style><img src=x onerror=alert(1)></style>"))
}

// TestCVE202566021_8EveryEndTagLeavesStyleText: noframes and noembed are raw
// text to a browser whether or not scripting is on, so they break out the
// same way, and every spelling of an end tag a browser accepts has to go: any
// case, trailing whitespace, or a slash before the >.
func TestCVE202566021_8EveryEndTagLeavesStyleText(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("noframes", "noembed", "style", "b").
		AllowTextIn("style"))

	hstAssertEqual(t,
		"<noframes><style></style></noframes>",
		policy.Sanitize(
			"<noframes><style></noframes>"+
				"<b onmouseover=alert(1)>x</b></style></noframes>"))
	hstAssertEqual(t,
		"<noembed><style></style></noembed>",
		policy.Sanitize(
			"<noembed><style></NOEMBED ><b onclick=alert(1)>x</b>"+
				"</style></noembed>"))
	hstAssertEqual(t,
		"<style>a{} b{}</style>",
		policy.Sanitize("<style>a{} </noembed/></div></ b>b{}</style>"))
}

// TestCVE202566021_9IframeContent: iframe content is literal to the renderer
// too, and used to escape the filter, which looked only for style and script.
func TestCVE202566021_9IframeContent(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("noscript", "iframe", "img").
		AllowTextIn("iframe").
		AllowAttributes("src").OnElements("img").
		AllowURLProtocols("https"))

	hstAssertEqual(t,
		"<noscript><iframe></iframe></noscript>",
		policy.Sanitize(
			"<noscript><iframe></noscript>"+
				"<img src=x onerror=alert(1)></iframe></noscript>"))
}

// TestCVE202566021_10CommentElementIsNotLiteralContent: the IE-only comment
// element was read as raw text, but no current browser reads it so: its
// content is markup to all of them.  It used to be emitted unescaped, so a tag
// inside it reached the browser unvetted, and a start tag with no > of its
// own was completed by the > of the sanitizer's own end tag.  Its content is
// now parsed, vetted and escaped like any other element's.
func TestCVE202566021_10CommentElementIsNotLiteralContent(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("comment", "img").
		AllowTextIn("comment").
		AllowAttributes("src").OnElements("img").
		AllowURLProtocols("https"))

	hstAssertEqual(t,
		"<comment><img src=\"x\" /></comment>",
		policy.Sanitize("<comment><img src=x onerror=alert(1)></comment>"))
	hstAssertEqual(t,
		"<comment>x<img src=\"x\" /></comment>",
		policy.Sanitize(
			"<comment>x<img src=x onerror=alert(1)//</comment>"))
	hstAssertEqual(t,
		"<comment>a &lt;b&gt; c</comment>",
		policy.Sanitize("<comment>a &lt;b&gt; c</comment>"))
}

// TestCVE202566021_11ChunkBoundariesCannotAssembleAnEndTag: text reaches the
// policy in chunks whose boundaries fall anywhere, so a chunk that ends in <,
// or holds </ with no >, must not combine with the next chunk into an end
// tag.  A preprocessor that delivers one character at a time is the extreme
// case.
func TestCVE202566021_11ChunkBoundariesCannotAssembleAnEndTag(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("noscript", "style", "img").
		AllowTextIn("style").
		AllowAttributes("src").OnElements("img").
		WithPreprocessor(hstP1Rechunking(1)))

	hstAssertEqual(t,
		"<noscript><style>/noscript>img src=x onerror=alert(1)>"+
			"</style></noscript>",
		policy.Sanitize(
			"<noscript><style></noscript>"+
				"<img src=x onerror=alert(1)></style></noscript>"))
}

// TestCVE202566021_12EndTagBehindAStrayBracket: a < that opens no tag used to
// carry everything up to the next > through as text, and that > could belong
// to an end tag inside the span, so <</noscript> and < </noscript> kept the
// breakout that a bare </noscript> lost.  The original fix had the same hole.
// The scan now resumes right after such a <.
func TestCVE202566021_12EndTagBehindAStrayBracket(t *testing.T) {
	policy := hstNoscriptStyleImg(t)

	cases := []struct{ want, input string }{
		{"<noscript><style></style></noscript>",
			"<noscript><style><</noscript>" +
				"<<img src=x onerror=alert(1)></style></noscript>"},
		{"<noscript><style>< </style></noscript>",
			"<noscript><style>< </noscript>" +
				"<img src=x onerror=alert(1)></style></noscript>"},
		{"<noscript><style><3</style></noscript>",
			"<noscript><style><3</noscript>" +
				"<img src=x onerror=alert(1)></style></noscript>"},
		{"<noscript><style><??></style></noscript>",
			"<noscript><style><?</noscript>" +
				"<img src=x onerror=alert(1)>?></style></noscript>"},
		{"<noscript><style><!----></style></noscript>",
			"<noscript><style><!--</noscript>" +
				"<img src=x onerror=alert(1)>--></style></noscript>"},
		// The dropped tag takes a '<' just before it along: "<" + "/noscript>"
		// would otherwise be an end tag again.
		{"<noscript><style>/noscript></style></noscript>",
			"<noscript><style><<b>/noscript></style></noscript>"},
	}
	for _, c := range cases {
		hstAssertEqual(t, c.want, policy.Sanitize(c.input))
	}
}

// TestCVE202566021_13DanglingBracketBeforeTheEndTag: once a breakout has put
// a browser in a markup state, a start tag left without its > inside the
// literal text is completed by the > of the sanitizer's own end tag.  A
// dangling < goes unless HTML whitespace follows it, which starts no tag in
// any browser state.
func TestCVE202566021_13DanglingBracketBeforeTheEndTag(t *testing.T) {
	policy := hstNoscriptStyleImg(t)

	hstAssertEqual(t,
		"<noscript><style>< img src=y onerror=alert(1)</style></noscript>",
		policy.Sanitize(
			"<noscript><style>< </noscript>"+
				"<img src=y onerror=alert(1)</style></noscript>"))
	hstAssertEqual(t,
		"<style>a { } b < c</style>",
		policy.Sanitize("<style>a { } b < c</style>"))
}

// TestCVE202566021_14ChunksSplitByServerCode: the lexer hands the content of
// a literal element over in more than one chunk when a server-side script tag
// <%...%> sits in it, so the pieces of an end tag or a start tag can arrive
// in different chunks, and each chunk has to drop its own dangling <.
func TestCVE202566021_14ChunksSplitByServerCode(t *testing.T) {
	hstAssertEqual(t,
		"<noscript><style>/noscript>img src=x onerror=alert(1)>"+
			"</style></noscript>",
		hstNoscriptStyleImg(t).Sanitize(
			"<noscript><style><<<%%>/noscript><<<%%>"+
				"img src=x onerror=alert(1)></style></noscript>"))
}

// hstP1StartTagPattern finds a start tag's opening.
var hstP1StartTagPattern = regexp.MustCompile(`<[a-zA-Z]`)

// TestCVE202566021_15FixedSizeRechunking: text re-chunked by a preprocessor
// into fixed-size blocks, which can split a tag anywhere, still leaves
// nothing in the literal text that a browser could read as an end tag or as a
// start tag.
func TestCVE202566021_15FixedSizeRechunking(t *testing.T) {
	for _, size := range []int{1, 2, 3, 5, 7, 16} {
		policy := hstFactory(t, NewHTMLPolicyBuilder().
			AllowElements("noscript", "style", "img").
			AllowTextIn("style").
			AllowAttributes("src").OnElements("img").
			WithPreprocessor(hstP1Rechunking(size)))
		for _, html := range []string{
			"<noscript><style><</noscript>" +
				"<<img src=x onerror=alert(1)></style></noscript>",
			"<noscript><style>< </noscript>" +
				"<img src=y onerror=alert(1)</style></noscript>",
		} {
			out := policy.Sanitize(html)
			styleText := out[strings.Index(out, "<style>")+7 : strings.Index(out, "</style>")]
			hstAssertFalse(t, strings.Contains(styleText, "</"), fmt.Sprintf("%d: %s", size, out))
			hstAssertFalse(t, hstP1StartTagPattern.MatchString(styleText),
				fmt.Sprintf("%d: %s", size, out))
		}
	}
}

// TestPreprocessorMayRecaseAnUnrecognizedTag: a preprocessor can hand the
// balancer a name in a case the lexer would not, such as CusTom.  The policy
// prepares its result under the canonical name, so the start has to be
// forwarded under it too.  Forwarded as written, the prepared result was
// never consumed, the policy was applied to the tag a second time, and the
// next start tag threw IllegalStateException out of sanitize.
func TestPreprocessorMayRecaseAnUnrecognizedTag(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("custom", "p").
		WithPreprocessor(HTMLStreamEventProcessorFunc(
			func(r HTMLStreamEventReceiver) HTMLStreamEventReceiver {
				return hstP1Recaser{HTMLStreamEventReceiverWrapper{Underlying: r}}
			})))
	out := p.Sanitize("<custom><p>x</p></custom><custom>y</custom>")
	hstAssertEqual(t, "<custom><p>x</p></custom><custom>y</custom>", out)
	hstAssertEqual(t, out, p.Sanitize(out))
	hstAssertEqual(t, hstParseAsBrowser(t, out), hstParseAsBrowser(t, p.Sanitize(out)))
}

// TestCVE202566021_16RendererRefusesContainerEndTags: the renderer itself
// refuses literal content holding the end tag of an element that a browser
// reads as raw text, so a policy that never runs the filter, such as one
// built by hand on PolicyFactory.Apply, is covered too.
func TestCVE202566021_16RendererRefusesContainerEndTags(t *testing.T) {
	for _, name := range []string{"noscript", "NOSCRIPT", "noframes", "noembed"} {
		var sb strings.Builder
		r := NewHTMLStreamRendererToBuilder(&sb, DoNothing[string])
		r.OpenDocument()
		r.OpenTag("style", []string{})
		r.Text("a{} </" + name + "><img src=x onerror=alert(1)> b{}")
		r.CloseTag("style")
		r.CloseDocument()
		hstAssertEqual(t, "<style></style>", sb.String(), name)
	}
	// Names that only start alike are left alone.
	var sb strings.Builder
	r := NewHTMLStreamRendererToBuilder(&sb, DoNothing[string])
	r.OpenDocument()
	r.OpenTag("style", []string{})
	r.Text("a{} </noscripts> </no b{}")
	r.CloseTag("style")
	r.CloseDocument()
	hstAssertEqual(t, "<style>a{} </noscripts> </no b{}</style>", sb.String())
}

// TestCVE202566021_17AllowedElementInStyleTextBypassesNoPolicy:
// GHSA-vqwm-jvq2-mfwc reported the first fix incomplete.  Under the reporter's
// policy an allowed element's tag inside style text came through verbatim, so
// neither its attribute policy nor its URL policy ran, and a > inside a quoted
// attribute value ended the scan for the tag early.  Every tag goes now; what
// is left of the quoted one is text with no < to start a tag.
func TestCVE202566021_17AllowedElementInStyleTextBypassesNoPolicy(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("style", "img").
		AllowAttributes("src").OnElements("img").
		AllowTextIn("style"))

	hstAssertEqual(t,
		"<style>x{}</style>",
		policy.Sanitize("<style>x{}<img src=x onerror=alert(1)>"))
	hstAssertEqual(t,
		"<style>x{}</style>",
		policy.Sanitize("<style>x{}<img src=javascript:alert(1)>"))
	hstAssertEqual(t,
		"<style>x{}\" onerror=alert(1)></style>",
		policy.Sanitize("<style>x{}<img src=\"x>\" onerror=alert(1)>"))
}

// TestCVE202566021_18AllowedElementInScriptTextIsRemoved is the same report's
// script case: text kept inside a script element loses an allowed element's
// tag too.
func TestCVE202566021_18AllowedElementInScriptTextIsRemoved(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("script", "img").
		AllowAttributes("src").OnElements("img").
		AllowTextIn("script"))

	hstAssertEqual(t,
		"<script>1</script>",
		policy.Sanitize("<script>1<img src=x onerror=alert(1)></script>"))
}

// TestLongRunOfUnmatchedTagsInLiteralTextIsLinear: a chunk of literal text
// full of start tags with no end tags is the worst case for pairing tags,
// since every one is searched for a match.  Pairing is done in one pass, so
// this takes a fraction of a second; a search restarted from each tag takes
// minutes.
func TestLongRunOfUnmatchedTagsInLiteralTextIsLinear(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("style").AllowTextIn("style"))
	const n = 200_000
	html := "<style>" + strings.Repeat("<b>x", n) + "</style>"
	expected := "<style>" + strings.Repeat("x", n) + "</style>"

	out := hstCompletesWithin(t, 20*time.Second, func() string { return p.Sanitize(html) })
	hstAssertEqual(t, expected, out)
}

// TestLongRunOfStrayBracketsInLiteralTextIsLinear: invalid tag openings must
// not repeatedly rescan the same long suffix.
func TestLongRunOfStrayBracketsInLiteralTextIsLinear(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("style").AllowTextIn("style"))
	const n = 1_000_000
	brackets := strings.Repeat("<", n)
	html := "<style>" + brackets + "></style>"

	out := hstCompletesWithin(t, 20*time.Second, func() string { return p.Sanitize(html) })
	hstAssertEqual(t, html, out)
}

// TestTagRemovalTakesAllAdjacentOpeningBrackets: removing a tag must not turn
// preceding brackets into a new start tag.
func TestTagRemovalTakesAllAdjacentOpeningBrackets(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("style").AllowTextIn("style"))

	hstAssertEqual(t,
		"<style>img src=x onerror=alert(1)></style>",
		p.Sanitize("<style><<<b>img src=x onerror=alert(1)></style>"))
}

// TestLongRunOfUnfinishedTagsInLiteralTextIsLinear: the worst case for the
// sweep that keeps a removal from leaving a tag behind: a long run of what
// could be the start of one, ended by a tag that goes.  Every < of the run
// goes with it, and the run is rewritten once rather than closed up around
// each, which would be quadratic: this text takes well under a second, where
// closing up each takes half a minute.
func TestLongRunOfUnfinishedTagsInLiteralTextIsLinear(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("style", "svg").AllowTextIn("style"))
	const n = 1_500_000
	html := "<style>" + strings.Repeat("<b", n) + "<svg></style>"

	out := hstCompletesWithin(t, 20*time.Second, func() string { return p.Sanitize(html) })
	hstAssertEqual(t, "<style>"+strings.Repeat("b", n)+"</style>", out)
}

// TestLiteralTextFullOfBracketsThatOpenNoTagIsLinear: the other worst case
// for the scan: literal text where no < opens a tag and the only > is at the
// end, so that every < is looked at and none of them resolves until the last
// character.  The scan remembers the > it found rather than looking for the
// same one again from each <, which would be quadratic: this text takes under
// a second, where looking again takes minutes.
func TestLiteralTextFullOfBracketsThatOpenNoTagIsLinear(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("style").AllowTextIn("style"))
	html := "<style>" + strings.Repeat("a<b'", 1_000_000) + ">" + "</style>"

	out := hstCompletesWithin(t, 20*time.Second, func() string { return p.Sanitize(html) })
	// None of it is a tag, so none of it goes.
	hstAssertEqual(t, html, out)
}

// TestLiteralTextKeepsWhatIsNotATag: the filter no longer discards the rest
// of a chunk after a start tag with no matching end tag, and keeps a < that
// opens no tag, so script and style text with a bare comparison survives.
func TestLiteralTextKeepsWhatIsNotATag(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("script", "style").
		AllowTextIn("script", "style"))

	hstAssertEqual(t,
		"<script>if (a < b) x();</script>",
		policy.Sanitize("<script>if (a < b) x();</script>"))
	// A '<' dangling before a letter at the end of a chunk goes: a later
	// chunk could complete it into a tag.
	hstAssertEqual(t,
		"<script>if (ab) x();</script>",
		policy.Sanitize("<script>if (a<b) x();</script>"))
	// "<b'; var t = 'c>" is a tag only where a browser would read "b';" as a
	// tag name, which is nowhere this text can reach one, so it stays (#470).
	hstAssertEqual(t,
		"<script>var s = 'a<b'; var t = 'c>d';</script>",
		policy.Sanitize("<script>var s = 'a<b'; var t = 'c>d';</script>"))
	hstAssertEqual(t,
		"<style>a{}c{}</style>",
		policy.Sanitize("<style>a{}<b>c{}</style>"))
	// With one, it goes with its content, as a script in a style block does.
	hstAssertEqual(t,
		"<style>a{}c{}</style>",
		policy.Sanitize("<style>a{}<b>x<b>y</b>z</b>c{}</style>"))
	// Not tags: a comment and an empty end tag stay; a bare bracket with no
	// '>' after it in the chunk is dangling and goes.
	hstAssertEqual(t,
		"<style>a{}<!-- x --></>c3{}</style>",
		policy.Sanitize("<style>a{}<!-- x --></>c<3{}</style>"))
	hstAssertEqual(t,
		"<style>a{}<3>{}</style>",
		policy.Sanitize("<style>a{}<3>{}</style>"))
}

// TestIssue470ComparisonOperatorsInScriptTextSurvive: ordinary script and
// style text tripped the filter, which took < plus anything up to the next >
// for a tag, so a comparison or a loop condition lost the text between.  A
// tag now needs a well-formed name.
func TestIssue470ComparisonOperatorsInScriptTextSurvive(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("script", "style").
		AllowTextIn("script", "style"))

	for _, js := range []string{
		"if (a < b) { x(); } if (c > d) { y(); }",
		"for(i=0;i<n;i++){a[i]=b>c;}",
		"a = b << 2 >> 1;",
		"if (x<y) { g(); } // z>w",
		"if (a<b){c();}else{d>e;}",
	} {
		hstAssertEqual(t, "<script>"+js+"</script>",
			policy.Sanitize("<script>"+js+"</script>"), js)
	}
	// CSS keeps its own comparisons, and a media query's parentheses.
	hstAssertEqual(t,
		"<style>@media (max-width:10px){a{}}</style>",
		policy.Sanitize("<style>@media (max-width:10px){a{}}</style>"))
	// What is left: a name followed by whitespace is a tag wherever a browser
	// reads markup, so "<b ||" goes with everything up to the next '>', as
	// the "< script>" that test #6 pins does.  The filter cannot tell them
	// apart, and an end tag hiding there would break out.
	hstAssertEqual(t,
		"<script>if (ad) f();</script>",
		policy.Sanitize("<script>if (a<b || c>d) f();</script>"))
}

// TestIssue470OnlyAWellFormedNameMakesATag: relaxing what counts as a tag
// gives up nothing: a browser reads a weird name as a tag only in a markup
// context, and the text of a kept literal-content element never reaches one.
// Anything that could end such an element for a browser has a well-formed
// name and still goes, including a name that only becomes one once the
// renderer elides a character it cannot emit.
func TestIssue470OnlyAWellFormedNameMakesATag(t *testing.T) {
	policy := hstNoscriptStyleImg(t)

	// Names a browser could act on, in every shape an element name takes.
	for _, tag := range []string{
		"<img src=x onerror=alert(1)>", "<my-widget onmouseover=alert(1)>",
		"<svg:a onmouseover=alert(1)>", "<b2 onmouseover=alert(1)>",
		"<b_c onmouseover=alert(1)>", "<b.c onmouseover=alert(1)>",
		"< img src=x onerror=alert(1)>", "<img/src=x onerror=alert(1)>",
	} {
		hstAssertEqual(t,
			"<style>a{}b{}</style>",
			policy.Sanitize("<style>a{}"+tag+"b{}</style>"), tag)
	}
	// A name that is not one stays, and is inert: a browser reads the text of
	// a style element literally, and an end tag whose name is not an
	// element's own name does not end it.
	for _, notATag := range []string{
		"<b) onmouseover=alert(1)>", "<n;i++){a[i]=b>", "<b'x'>",
		"</b) onmouseover=alert(1)>", "</3>",
	} {
		hstAssertEqual(t,
			"<style>a{}"+notATag+"b{}</style>",
			policy.Sanitize("<style>a{}"+notATag+"b{}</style>"), notATag)
	}
	// The renderer elides a NUL, a DEL and a C1 control, which would
	// otherwise join a name to what follows it, so they end a name instead.
	for _, elided := range []string{"\u0000", "\u007f", "\u0085"} {
		r, _ := wtf8DecodeRune(elided)
		hstAssertEqual(t,
			"<noscript><style></style></noscript>",
			policy.Sanitize(
				"<noscript><style></noscript"+elided+">"+
					"<img src=x onerror=alert(1)></style></noscript>"),
			fmt.Sprintf("U+%x", r))
		hstAssertEqual(t,
			"<style>a{}b{}</style>",
			policy.Sanitize(
				"<style>a{}<img"+elided+" src=x onerror=alert(1)>b{}"+
					"</style>"))
	}
}

// TestIssue473LiteralTextFilterKeepsNoRecordPerTag: the filter kept a record
// per tag, so a chunk of literal text full of tags cost a multiple of its own
// size in heap, and text that used to sanitize in 160 MB needed 256 MB.  It
// now keeps only its output and a bounded note of the start tags it has not
// matched, so the cost per tag is what the lexer already spends on the same
// text.
func TestIssue473LiteralTextFilterKeepsNoRecordPerTag(t *testing.T) {
	n := 200_000
	html := "<style>" + strings.Repeat("<b>x", n) + "</style>"
	// The same text, filtered and not: one policy keeps the text of a style
	// element and filters it, the other drops it, so the difference in what
	// they allocate is the filter's own, without the lexer's share of it.
	filtering := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("style").AllowTextIn("style"))
	notFiltering := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("style"))
	filtering.Sanitize(html)
	notFiltering.Sanitize(html) // Warm up what both use.

	allocated := func() uint64 {
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		return stats.TotalAlloc
	}
	before := allocated()
	filtering.Sanitize(html)
	between := allocated()
	notFiltering.Sanitize(html)
	after := allocated()

	perTag := (int64(between-before) - int64(after-between)) / int64(n)
	// Around 5 bytes a tag, for the output and the string it becomes; a
	// record per tag cost more than 700.
	hstAssertTrue(t, perTag < 64, fmt.Sprintf("%d bytes allocated per tag", perTag))
}

// TestIssue473LiteralTextNestedPastThePairingBoundIsStillTagFree: pairing a
// start tag with its end tag keeps a dropped element's content with it, which
// is fidelity rather than safety, so the filter bounds what it remembers.
// Literal text nested deeper than that loses each tag on its own, and still
// no tag survives.
func TestIssue473LiteralTextNestedPastThePairingBoundIsStillTagFree(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("style").AllowTextIn("style"))
	for _, depth := range []int{8, 64, 65, 100, 1000} {
		html := "<style>" + strings.Repeat("<b>x", depth) +
			strings.Repeat("</b>", depth) + "</style>"
		out := policy.Sanitize(html)
		body := out[strings.Index(out, "<style>")+7 : strings.LastIndex(out, "</style>")]
		hstAssertFalse(t, strings.Contains(body, "<"), fmt.Sprintf("%d: %s", depth, out))
		hstAssertFalse(t, strings.Contains(body, ">"), fmt.Sprintf("%d: %s", depth, out))
	}
}

// TestIssue475RemovingATagDoesNotSpliceACommentDelimiter: removing a tag
// joins the text on either side of it, which could make a <!-- or a --> that
// the input did not have.  The renderer refuses the whole content of a
// literal element whose comment delimiters do not balance, so the element
// came out empty.  A space goes in where the join would make one.
func TestIssue475RemovingATagDoesNotSpliceACommentDelimiter(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("style", "script", "b").
		AllowTextIn("style", "script"))

	hstAssertEqual(t,
		"<style>a{}- ->b{}</style>",
		policy.Sanitize("<style>a{}-<b>->b{}</style>"))
	hstAssertEqual(t,
		"<style>a{}-- >b{}</style>",
		policy.Sanitize("<style>a{}--<b>>b{}</style>"))
	hstAssertEqual(t,
		"<style>a<! --x</style>",
		policy.Sanitize("<style>a<!<b>--x</style>"))
	hstAssertEqual(t,
		"<style>a<!- -x</style>",
		policy.Sanitize("<style>a<!-<b>-x</style>"))
	// The text on either side of the join can be in different chunks, which
	// the lexer splits at server-side script tags, so the last of a chunk is
	// remembered, and a join at the end of one assumes the worst.
	hstAssertEqual(t,
		"<style>a{}- ->b{}</style>",
		policy.Sanitize("<style>a{}-<%%><b>->b{}</style>"))
	hstAssertEqual(t,
		"<style>a{}- ->b{}</style>",
		policy.Sanitize("<style>a{}-<b><%%>->b{}</style>"))
	// A delimiter the input itself holds is not the filter's to fix: the
	// renderer still refuses the content, and says so.
	hstAssertEqual(t,
		"<style></style>",
		policy.Sanitize("<style>a{}--><b>b{}</style>"))
}

// TestIssue475ADroppedPairDoesNotTakeACommentDelimiter is issue #475 the
// other way round: a start tag dropped together with its content can take a
// --> with it and leave an earlier <!-- unclosed, which costs the whole
// content again.  Such a pair is dropped tag by tag instead, so what the
// comment holds stays.
func TestIssue475ADroppedPairDoesNotTakeACommentDelimiter(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("style", "script", "b").
		AllowTextIn("style", "script"))

	hstAssertEqual(t,
		"<script><!-- if (a > 0) {  } -->  f();</script>",
		policy.Sanitize(
			"<script><!-- if (a > 0) { <b> } --> </b> f();</script>"))
	hstAssertEqual(t,
		"<style><!-- a --> b </style>",
		policy.Sanitize("<style><!-- a<b> --> b </b></style>"))
	// A pair whose content holds no delimiter still goes whole.
	hstAssertEqual(t,
		"<style>a{}c{}</style>",
		policy.Sanitize("<style>a{}<b>x - y</b>c{}</style>"))
}

// TestRemovingATagDoesNotSpliceAnotherTag: removing a tag must not splice
// what is on either side of it into another tag, nor leave the element's own
// end tag to finish one.  A browser reads the text of a kept literal-content
// element literally, so none of this is reachable, but the filter must not
// hand one a tag the text did not hold: <b<svg> is a tag a browser acts on
// and the text after it is text, while <b followed by that text is a tag
// with a live handler.
func TestRemovingATagDoesNotSpliceAnotherTag(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("noscript", "style", "script", "svg", "b", "img", "p").
		AllowTextIn("style", "script").
		AllowAttributes("src").OnElements("img").
		AllowURLProtocols("https"))

	// The "<b" the removed tag followed goes, so the text after it cannot
	// become its attributes.
	hstAssertEqual(t,
		"<style>b onmouseover=alert(1)>x</style>",
		policy.Sanitize("<style><b<svg> onmouseover=alert(1)>x</style>"))
	// Every '<' of the run goes: dropping one leaves the next before a name.
	hstAssertEqual(t,
		"<style>bb onmouseover=alert(1)>x</style>",
		policy.Sanitize("<style><b<b<svg> onmouseover=alert(1)>x</style>"))
	// A "</" before the removed tag would have met the name after it, which
	// is the breakout the filter exists to stop.
	hstAssertEqual(t,
		"<style>/noscript></style>",
		policy.Sanitize("<style></<b>noscript></style>"))
	hstAssertEqual(t,
		"<noscript><style>/noscript></style></noscript>",
		policy.Sanitize(
			"<noscript><style></<b>noscript>"+
				"<img src=x onerror=alert(1)></style></noscript>"))
	// At the end of the text it is the element's own end tag that would
	// finish the tag, whether or not a '>' came earlier.
	hstAssertEqual(t,
		"<style>a{}b</style>",
		policy.Sanitize("<style>a{}<b<svg></style>"))
	hstAssertEqual(t,
		"<script>x> x<3/style</script>",
		policy.Sanitize("<script>x><p> x<3</style<B></script>"))
	// A start tag the text kept has a place to come back to that the sweep
	// has already been over, so its end tag cannot cut the text short.
	hstAssertEqual(t,
		"<noscript><style>--bnoscript></style></noscript>",
		policy.Sanitize(
			"<noscript><style>--<b<b/></><style></ b>noscript></noscript>"))
	// What opens no tag stays: "3" is no name, and no browser state starts a
	// tag at '<' and whitespace.
	hstAssertEqual(t,
		"<style>a{}<3{}</style>",
		policy.Sanitize("<style>a{}<3<svg>{}</style>"))
	hstAssertEqual(t,
		"<style>a{}< b{}</style>",
		policy.Sanitize("<style>a{}< b<svg>{}</style>"))
	// And ordinary text is untouched.
	hstAssertEqual(t,
		"<style>a{}c{}</style>",
		policy.Sanitize("<style>a{}<b>c{}</style>"))
	hstAssertEqual(t,
		"<script>var s = 'a<b'; var t = 'c>d';</script>",
		policy.Sanitize("<script>var s = 'a<b'; var t = 'c>d';</script>"))
}

// TestIssue474LiteralTextInForeignContentIsEscapedNotStripped: inside svg or
// math a browser parses the content of every element as markup, so the
// renderer escapes the text of a style or script element there instead of
// emitting it as written.  The filter used to strip the tags from that text
// as well, which was safe but lost them for no reason.
func TestIssue474LiteralTextInForeignContentIsEscapedNotStripped(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("svg", "math", "style", "script", "b").
		AllowTextIn("style", "script", "svg", "math"))

	hstAssertEqual(t,
		"<svg><style>a{}&lt;b&gt;x&lt;/b&gt;c{}</style></svg>",
		policy.Sanitize("<svg><style>a{}<b>x</b>c{}</style></svg>"))
	hstAssertEqual(t,
		"<math><script>a&lt;b&gt;c</script></math>",
		policy.Sanitize("<math><script>a<b>c</script></math>"))
	// Escaped, so a breakout cannot ride along on it either.
	hstAssertEqual(t,
		"<svg><style>&lt;/noscript&gt;&lt;img src&#61;x onerror&#61;alert(1)&gt;"+
			"</style></svg>",
		policy.Sanitize(
			"<svg><style></noscript><img src=x onerror=alert(1)></style>"+
				"</svg>"))
	// Outside the svg the same element's text is emitted as written, so the
	// filter runs over it: the tags go and the end tag with them.
	hstAssertEqual(t,
		"<svg></svg><style>a{}c{}</style>",
		policy.Sanitize("<svg></svg><style>a{}<b>x</b>c{}</style>"))
	hstAssertEqual(t,
		"<svg><b></b></svg><style>a{}c{}</style>",
		policy.Sanitize("<svg><b></b></svg><style>a{}<b>x</b>c{}</style>"))
}

// TestIssue474ACustomReceiverGetsRawTextWithoutTags: the filter judged the
// element by the name the library's own renderer emits, which renames xmp,
// listing and plaintext to pre and escapes their text.  A receiver handed to
// PolicyFactory.Apply does not rename, so it used to receive the text of
// those elements with its tags intact, a </noscript> among them, and the
// renderer-side check cannot run for it either.  With any other receiver
// every element whose content the lexer read as raw text is filtered.
func TestIssue474ACustomReceiverGetsRawTextWithoutTags(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("noscript", "xmp", "listing", "plaintext", "style",
			"img").
		AllowTextIn("xmp", "listing", "plaintext", "style").
		AllowAttributes("src").OnElements("img"))

	for _, rawText := range []string{"xmp", "listing", "plaintext"} {
		html := "<noscript><" + rawText + "></noscript>" +
			"<img src=x onerror=alert(1)></" + rawText + "></noscript>"
		var text []string
		Sanitize(html, policy.Apply(hstCollectText(&text)), nil)
		hstP2AssertStrings(t, []string{""}, text, rawText)

		// Through the library's renderer, which renames the element and
		// escapes its text, the tags are still there to see.  A plaintext
		// element runs to the end of the input, so its own end tag is part of
		// its text.
		plaintextTail := ""
		if rawText == "plaintext" {
			plaintextTail = "&lt;/plaintext&gt;&lt;/noscript&gt;"
		}
		hstAssertEqual(t,
			"<noscript><pre>&lt;/noscript&gt;&lt;img src&#61;x"+
				" onerror&#61;alert(1)&gt;"+
				plaintextTail+
				"</pre></noscript>",
			policy.Sanitize(html), rawText)
	}
	// A receiver the library cannot see through gets no tags in the text of
	// a style element inside an svg either, where the renderer would escape
	// them, since it may write what it is given as it stands.
	svgPolicy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("svg", "style", "b").AllowTextIn("style", "svg"))
	var text []string
	Sanitize(
		"<svg><style>a{}<b>x</b>c{}</style></svg>",
		svgPolicy.Apply(hstCollectText(&text)), nil)
	hstP2AssertStrings(t, []string{"a{}c{}"}, text)
}

// hstP2AssertStrings fails the test if got is not the list want.
func hstP2AssertStrings(t testing.TB, want, got []string, msgAndArgs ...any) {
	t.Helper()
	if !slices.Equal(want, got) {
		t.Errorf("%swant %q\ngot  %q", hstMessage(msgAndArgs), want, got)
	}
}

// TestTheLiteralTextFilterDoesNotDependOnAListener: listening for what a
// policy drops must not change what it keeps.  The filter follows what the
// receiver escapes, and a reporter sits between the policy and the renderer,
// so the renderer has to stay visible behind it.
func TestTheLiteralTextFilterDoesNotDependOnAListener(t *testing.T) {
	policy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("svg", "style", "xmp", "b").
		AllowTextIn("style", "xmp", "svg"))

	for _, html := range []string{
		"<svg><style>a{}<b>x</b>c{}</style></svg>",
		"<style>a{}<b>x</b>c{}</style>",
		"<xmp>a<b>x</b>c</xmp>",
	} {
		hstAssertEqual(t,
			policy.Sanitize(html),
			policy.SanitizeWithListener(html, hstIgnoringListener{}, nil), html)
	}
}

// TestIssue410EofInTagAndBogusEndTags covers two tokenizer differences left
// over from #189 (#410).  A tag that the input ends inside is dropped whole,
// as a browser drops it, rather than opened with whatever attributes had been
// read; and </ followed by anything but a letter is a bogus comment running
// to the next >, or text at the end of input, rather than text up to the
// next tag.
func TestIssue410EofInTagAndBogusEndTags(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("p", "b").
		AllowAttributes("class", "x").OnElements("p"))

	// End of input inside a tag: the tag goes, the text before it stays.
	hstAssertEqual(t, "x", p.Sanitize("x<p "))
	hstAssertEqual(t, "", p.Sanitize("<p class=\">y</p>"))
	hstAssertEqual(t,
		"<p>foo</p> ",
		p.Sanitize("<p>foo</p> <p class=\"test\" \"=\">bar</p> <p>baz</p>"))
	// An end tag the input ends inside goes too; the balancer closes the
	// element at the end as it would have anyway.
	hstAssertEqual(t, "<b>x</b>", p.Sanitize("<b>x</b"))
	hstAssertEqual(t, "<b>x</b>", p.Sanitize("<b>x</b class"))

	// "</" and a non-letter.
	hstAssertEqual(t, "<p>z</p>", p.Sanitize("<p></>z"))
	hstAssertEqual(t, "<p x=\"x\">y</p>", p.Sanitize("<p x></\"<p>y</p>"))
	hstAssertEqual(t, "<b>xy</b>", p.Sanitize("<b>x</ b>y"))
	hstAssertEqual(t, "a&lt;/", p.Sanitize("a</"))
}

// TestLinkInsideCellInsideLinkKeepsTheTableTogether: a link inside a table
// cell inside a link stays where it is: a browser clears its active
// formatting elements to a marker on entering the cell, so the inner a does
// not end the outer one.  The balancer used to close back to the outer a,
// taking the inner table's cell, row and table with it, so that table's
// second row landed in the outer table (#333).  The parser check reads both
// the input and the output the way a browser does and compares the trees.
func TestLinkInsideCellInsideLinkKeepsTheTableTogether(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a", "table", "tbody", "tr", "td", "th", "caption").
		AllowAttributes("href").OnElements("a").
		AllowURLProtocols("http"))
	input := "<table><tr><td><a href=\"http://b.example\">" +
		"<table><tbody>" +
		"<tr><td><a href=\"http://b.example\">11111</a></td></tr>" +
		"<tr><td><a href=\"http://b.example\">22222</a></td></tr>" +
		"</tbody></table></a></td></tr></table>"
	out := p.Sanitize(input)

	hstAssertEqual(t,
		"<table><tbody><tr><td><a href=\"http://b.example\">"+
			"<table><tbody>"+
			"<tr><td><a href=\"http://b.example\">11111</a></td></tr>"+
			"<tr><td><a href=\"http://b.example\">22222</a></td></tr>"+
			"</tbody></table></a></td></tr></tbody></table>",
		out)
	hstAssertEqual(t, hstParseAsBrowser(t, input), hstParseAsBrowser(t, out))

	// caption and th are markers too; a link straight inside a link is not,
	// and the second still ends the first, as in a browser.
	for _, html := range []string{
		"<a href=\"http://u\"><table><caption><a href=\"http://v\">c" +
			"</a></caption></table></a>",
		"<a href=\"http://u\"><table><tr><th><a href=\"http://v\">h" +
			"</a></th></tr></table></a>",
		"<a href=\"http://u\">x<a href=\"http://v\">y</a>z</a>",
	} {
		hstAssertEqual(t,
			hstParseAsBrowser(t, html), hstParseAsBrowser(t, p.Sanitize(html)), html)
	}
}

// TestDroppedFormattingMarkersDoNotProtectNestedLinks: a formatting marker
// matters only when the policy keeps it in output.
func TestDroppedFormattingMarkersDoNotProtectNestedLinks(t *testing.T) {
	expected := "<a href=\"u\" rel=\"nofollow\"></a>" +
		"<a href=\"v\" rel=\"nofollow\">x</a>y"
	for _, marker := range []string{
		"applet", "caption", "marquee", "object", "td", "template", "th",
	} {
		input := "<a href=u><" + marker + "><a href=v>x</a></" +
			marker + ">y</a>"
		out := Links.Sanitize(input)

		hstAssertEqual(t, expected, out, marker)
		hstAssertEqual(t, out, Links.Sanitize(out), marker)
		hstAssertEqual(t, hstParseAsBrowser(t, expected), hstParseAsBrowser(t, out), marker)
	}
}

// TestKeptFormattingMarkerStillProtectsNestedLinks: a marker that survives
// policy still permits the browser's nested links.
func TestKeptFormattingMarkerStillProtectsNestedLinks(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a", "marquee").
		AllowAttributes("href").OnElements("a"))
	input := "<a href=u><marquee><a href=v>x</a></marquee>y</a>"
	out := p.Sanitize(input)

	hstAssertEqual(t,
		"<a href=\"u\"><marquee><a href=\"v\">x</a></marquee>y</a>",
		out)
	hstAssertEqual(t, hstParseAsBrowser(t, input), hstParseAsBrowser(t, out))
	hstAssertEqual(t, out, p.Sanitize(out))
}

// TestRenamedElementsDetermineFormattingMarkerScope: marker scope follows an
// element policy's output name, not its input.
func TestRenamedElementsDetermineFormattingMarkerScope(t *testing.T) {
	awayFromMarker := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a", "div").
		AllowElementsWithPolicy(hstRenamingPolicy("div"), "marquee").
		AllowAttributes("href").OnElements("a"))
	renamedAway := awayFromMarker.Sanitize(
		"<a href=u><marquee><a href=v>x</a></marquee>y</a>")
	hstAssertEqual(t,
		"<a href=\"u\"><div></div></a><a href=\"v\">x</a>y",
		renamedAway)
	hstAssertEqual(t, renamedAway, awayFromMarker.Sanitize(renamedAway))

	intoMarker := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a", "marquee").
		AllowElementsWithPolicy(hstRenamingPolicy("marquee"), "div").
		AllowAttributes("href").OnElements("a"))
	renamedInto := intoMarker.Sanitize(
		"<a href=u><div><a href=v>x</a></div>y</a>")
	hstAssertEqual(t,
		"<a href=\"u\"><marquee><a href=\"v\">x</a></marquee>y</a>",
		renamedInto)
	hstAssertEqual(t, renamedInto, intoMarker.Sanitize(renamedInto))
}

// TestContentPushedOutOfATableIsClosedWhenTheTableResumes: a browser puts
// content that cannot go inside a table in front of the table and keeps the
// table open, so that the next row pops the content and carries on in the
// same table (#342).  The output cannot put anything in front of a tag
// already written, so the table is closed there, the content written after
// it, and the table written again for its rows.  The content used to stay
// open until the end of the document, taking the rows and everything after
// the table with it.  A browser now reads the output as it reads the input,
// but for the empty table in front.
func TestContentPushedOutOfATableIsClosedWhenTheTableResumes(t *testing.T) {
	p := hstTablePolicy(t)
	input := "<table><div>x<tr><td>y</td></tr></div></table>tail"
	out := p.Sanitize(input)

	hstAssertEqual(t,
		"<table></table><div>x</div>"+
			"<table><tbody><tr><td>y</td></tr></tbody></table>tail",
		out)
	hstAssertEqual(t, out, p.Sanitize(out))
	hstAssertEqual(t, hstParseAsBrowser(t, "<table></table>"+input), hstParseAsBrowser(t, out))
}

// TestRowsAfterPushedOutContentContinueInANewTable is the shape reported in
// #342: the table had rows before the content and attributes of its own.
// The rows before stay in the first table, and the table written again for
// the rows after has no attributes, as a formatting element written again
// after being closed has none.
func TestRowsAfterPushedOutContentContinueInANewTable(t *testing.T) {
	p := hstTablePolicy(t)
	input := "<table class=t><tbody><tr><td>a</td></tr>" +
		"<div class=d>x<tr><td>y</td></tr></div></table>tail"
	out := p.Sanitize(input)

	hstAssertEqual(t,
		"<table class=\"t\"><tbody><tr><td>a</td></tr></tbody></table>"+
			"<div class=\"d\">x</div>"+
			"<table><tbody><tr><td>y</td></tr></tbody></table>tail",
		out)
	hstAssertEqual(t, out, p.Sanitize(out))
}

// TestPushedOutContentNestsUntilATablePartArrives: content pushed out of a
// table nests as usual until a part of the table arrives, which closes all
// of it.  End tags for that content arriving later find nothing to close, as
// in a browser, and the text after them is pushed out as well.  A browser
// puts that text in front of the table; the output, written in order, can
// only put it after.
func TestPushedOutContentNestsUntilATablePartArrives(t *testing.T) {
	p := hstTablePolicy(t)
	input := "<table><div><p>x<span>s<tr><td>y</td></tr></span>t</div>u" +
		"</table>v"
	out := p.Sanitize(input)

	hstAssertEqual(t,
		"<table></table><div><p>x<span>s</span></p></div>"+
			"<table><tbody><tr><td>y</td></tr></tbody></table>tuv",
		out)
	hstAssertEqual(t, out, p.Sanitize(out))
}

// TestEndTagBelowAPushedOutTableIsIgnoredWhileItIsOpen: a browser keeps the
// table open below the content it pushed out, so an end tag for an element
// enclosing the table is ignored meanwhile, and the text after it lands in
// the pushed-out content.  The balancer used to close the table and let the
// end tag through.
func TestEndTagBelowAPushedOutTableIsIgnoredWhileItIsOpen(t *testing.T) {
	p := hstTablePolicy(t)
	input := "<div><table><span>x</div>y</table>z"
	out := p.Sanitize(input)

	hstAssertEqual(t, "<div><table></table><span>xy</span>z</div>", out)
	hstAssertEqual(t, out, p.Sanitize(out))
	hstAssertEqual(t,
		hstParseAsBrowser(t, "<div><table></table><span>xy</span>z</div>"),
		hstParseAsBrowser(t, out))
}

// TestTableEndTagEndsPushedOutContent: the table's own end tag ends the
// content pushed out of it.  A browser has the content in front of the table
// and the text after both; the output has the same nodes with the table
// first.
func TestTableEndTagEndsPushedOutContent(t *testing.T) {
	p := hstTablePolicy(t)
	out := p.Sanitize("<table><div>x</table>tail")

	hstAssertEqual(t, "<table></table><div>x</div>tail", out)
	hstAssertEqual(t, out, p.Sanitize(out))
}

// TestTableInsidePushedOutContentReplacesTheOpenTable: a table arriving
// inside pushed-out content pops the open table in a browser and takes its
// place, rather than nesting in the content; and with tables pushed out at
// two levels, a row returns to the nearest.
func TestTableInsidePushedOutContentReplacesTheOpenTable(t *testing.T) {
	p := hstTablePolicy(t)
	input := "<table><div>x<table><tr><td>y</td></tr></table>tail"
	out := p.Sanitize(input)
	hstAssertEqual(t,
		"<table></table><div>x</div>"+
			"<table><tbody><tr><td>y</td></tr></tbody></table>tail",
		out)
	hstAssertEqual(t, out, p.Sanitize(out))

	nested := "<table><div>x<table><span>y<tr><td>z</td></tr></table>" +
		"</div>w</table>v"
	out = p.Sanitize(nested)
	hstAssertEqual(t,
		"<table></table><div>x</div><table></table><span>y</span>"+
			"<table><tbody><tr><td>z</td></tr></tbody></table>wv",
		out)
	hstAssertEqual(t, out, p.Sanitize(out))
	hstAssertEqual(t, hstParseAsBrowser(t, "<table></table>"+nested), hstParseAsBrowser(t, out))
}

// TestEveryTablePartReturnsToThePushedOutTable: every part of a table brings
// the pushed-out table back.
func TestEveryTablePartReturnsToThePushedOutTable(t *testing.T) {
	p := hstTablePolicy(t)
	cases := [][2]string{
		{"<caption>c</caption>", "<caption>c</caption>"},
		{"<thead><tr><th>h</th></tr></thead>", "<thead><tr><th>h</th></tr></thead>"},
		{"<tbody><tr><td>y</td></tr></tbody>", "<tbody><tr><td>y</td></tr></tbody>"},
		{"<tr><td>y</td></tr>", "<tbody><tr><td>y</td></tr></tbody>"},
		{"<td>y</td>", "<tbody><tr><td>y</td></tr></tbody>"},
		{"<th>h</th>", "<tbody><tr><th>h</th></tr></tbody>"},
	}
	for _, c := range cases {
		input := "<table><div>x" + c[0] + "</table>"
		out := p.Sanitize(input)
		hstAssertEqual(t,
			"<table></table><div>x</div><table>"+c[1]+"</table>", out, c[0])
		hstAssertEqual(t, out, p.Sanitize(out), c[0])
		hstAssertEqual(t,
			hstParseAsBrowser(t, "<table></table>"+input), hstParseAsBrowser(t, out), c[0])
	}
}

// TestForeignTablePartsDoNotReturnToAPushedOutTable: table-part names in SVG
// and MathML stay in foreign content.  Treating them as HTML used to close
// the foreign ancestors and move the elements into the pushed-out table.  At
// an HTML integration point the same names do use HTML rules and still
// return to the table.
func TestForeignTablePartsDoNotReturnToAPushedOutTable(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(
			"b", "caption", "colgroup", "table", "thead", "tbody",
			"tr", "td", "div", "svg", "g", "textArea", "foreignObject",
			"math", "mrow", "mtext"))
	input := "<table><svg><g><tr><td>s</td></tr>" +
		"<textArea><tr><td>t</td></tr></textArea></g></svg>" +
		"<math><mrow><tr><td>m</td></tr></mrow></math>" +
		"<tr><td>h</td></tr></table>tail"
	out := p.Sanitize(input)

	hstAssertEqual(t,
		"<table></table><svg><g><tr><td>s</td></tr>"+
			"<textArea><tr><td>t</td></tr></textArea></g></svg>"+
			"<math><mrow><tr><td>m</td></tr></mrow></math>"+
			"<table><tbody><tr><td>h</td></tr></tbody></table>tail",
		out)
	hstAssertEqual(t, out, p.Sanitize(out))
	hstAssertEqual(t, hstParseAsBrowser(t, "<table></table>"+input), hstParseAsBrowser(t, out))

	for _, integrationPoint := range [][2]string{
		{"<svg><foreignObject>", "</foreignObject></svg>"},
		{"<math><mtext>", "</mtext></math>"},
	} {
		input = "<table><div>" + integrationPoint[0] +
			"<tr><td>i</td></tr>" + integrationPoint[1] +
			"<tr><td>h</td></tr></table>tail"
		out = p.Sanitize(input)
		hstAssertEqual(t, out, p.Sanitize(out), integrationPoint[0])
		hstAssertEqual(t,
			hstParseAsBrowser(t, "<table></table>"+input), hstParseAsBrowser(t, out),
			integrationPoint[0])
	}

	// An emitted HTML breakout leaves the rendered foreign root before the
	// table is written again.  Its later end tag must not close that table in
	// the policy's stack and strand the following section outside it.
	input = "<table><svg><b><thead></svg>" +
		"<tbody><tr><td>y</td></tr></table>tail"
	out = p.Sanitize(input)
	hstAssertEqual(t,
		"<table></table><svg><b></b></svg>"+
			"<table><thead></thead><tbody><tr><td><b>y</b></td></tr>"+
			"</tbody></table><b>tail</b>",
		out)
	hstAssertEqual(t, out, p.Sanitize(out))

	// A stray table end tag cannot lose foreign context and send a later
	// table part back into the pushed-out table.
	foreign := "<table><svg><colgroup></thead>" +
		"<caption>c</caption></colgroup></svg>" +
		"<tr><td>y</td></tr></table>tail"
	out = p.Sanitize(foreign)
	hstAssertEqual(t, out, p.Sanitize(out))
	hstAssertEqual(t,
		hstParseAsBrowser(t, "<table></table>"+foreign), hstParseAsBrowser(t, out))
}

// TestLiteralContentInPushedOutTableContent: raw-text and RCDATA elements
// stay bounded by a pushed-out run.
func TestLiteralContentInPushedOutTableContent(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(
			"table", "tbody", "tr", "td", "div", "span", "style",
			"script", "textarea", "noscript").
		AllowTextIn("style", "script", "noscript"))
	input := "<table><textarea>&lt;tr&gt;</textarea><div>" +
		"<style>x{}</style><script>x()</script>" +
		"<noscript><span>n</span></noscript></div>" +
		"<tr><td>y</td></tr></table>tail"
	out := p.Sanitize(input)

	hstAssertEqual(t,
		"<table></table><textarea>&lt;tr&gt;</textarea><div>"+
			"<style>x{}</style><script>x()</script>"+
			"<noscript>n</noscript></div>"+
			"<table><tbody><tr><td>y</td></tr></tbody></table>tail",
		out)
	hstAssertEqual(t, out, p.Sanitize(out))
}

// TestTableStructureIsSuppressedUnderRenamedReopenedTable: a policy may drop
// or rename the attribute-free table written when table content resumes.  A
// renamed synthetic table and its row structure cannot safely be emitted,
// but allowed cell text still survives.  This includes replacements with
// table, void, select, raw-text and foreign parsing rules.
func TestTableStructureIsSuppressedUnderRenamedReopenedTable(t *testing.T) {
	input := "<table class=t><div>x<tr><td>" +
		"a&lt;/script&gt;&lt;svg onload=x&gt;b" +
		"</td></tr></table>tail"
	replacements := []string{
		"", "div", "tbody", "tr", "td", "caption", "colgroup", "col",
		"br", "select", "option", "script", "style", "textarea",
		"noscript", "xmp", "plaintext", "iframe", "svg", "math",
	}
	for _, c := range replacements {
		replacement := c // An empty replacement rejects the table.
		p := hstFactory(t, NewHTMLPolicyBuilder().
			AllowElementsWithPolicy(
				ElementPolicyFunc(func(elementName string, attrs *[]string) (string, bool) {
					if len(*attrs) == 0 {
						return replacement, replacement != ""
					}
					return elementName, true
				}),
				"table").
			AllowElements("tbody", "tr", "td", "div").
			AllowAttributes("class").OnElements("table").
			AllowTextIn("table"))
		out := p.Sanitize(input)

		hstAssertEqual(t,
			"<table class=\"t\"></table><div>x</div>"+
				"a&lt;/script&gt;&lt;svg onload&#61;x&gt;btail",
			out, c)
		hstAssertEqual(t, out, p.Sanitize(out), c)
		hstAssertEqual(t, out, p.SanitizeWithListener(input, hstIgnoringListener{}, nil), c)
	}
}

// TestPushedOutLinkIsNotResumedAroundAnotherLink: a link pushed out of a
// table is closed when the table resumes, and is not written again around
// another link or inside one: nested links do not survive a browser's parse.
// Nor is it written again after that link: a browser drops the earlier link
// from its list of active formatting elements when the next one starts, so
// the text after the second link is plain, as it is here.  Text is pushed
// out likewise, and needs nothing closed.
func TestPushedOutLinkIsNotResumedAroundAnotherLink(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tbody", "tr", "td", "a").
		AllowAttributes("href").OnElements("a").
		AllowWithoutAttributes("a"))
	input := "<table><a href=u>x<tr><td><a href=v>y</a>z</td></tr></table>w"
	out := p.Sanitize(input)

	hstAssertEqual(t,
		"<table></table><a href=\"u\">x</a>"+
			"<table><tbody><tr><td><a href=\"v\">y</a>z</td></tr></tbody>"+
			"</table>w",
		out)
	hstAssertEqual(t, out, p.Sanitize(out))
	hstAssertEqual(t,
		"<table></table>x<table><tbody><tr><td>y</td></tr></tbody></table>",
		p.Sanitize("<table>x<tr><td>y</td></tr></table>"))
}

// TestReturnToAPushedOutTableStopsAtATableScopeBoundary: a browser looks for
// the table to return to within table scope only, so a table or row inside a
// template in the pushed-out content stays in the template, and the
// pushed-out table waits for a part arriving outside it.
func TestReturnToAPushedOutTableStopsAtATableScopeBoundary(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tbody", "tr", "td", "div", "template"))
	out := p.Sanitize(
		"<table><div><template><table><tr><td>y</td></tr></table></template>" +
			"z</div>w<tr><td>v</td></tr></table>u")

	hstAssertEqual(t,
		"<table></table><div><template>"+
			"<table><tbody><tr><td>y</td></tr></tbody></table></template>z</div>w"+
			"<table><tbody><tr><td>v</td></tr></tbody></table>u",
		out)
	hstAssertEqual(t, out, p.Sanitize(out))
}

// TestPushedOutContentIsJudgedByWhatHoldsTheTable: content is judged by what
// holds the table it was pushed out of, since that is where a browser puts
// it.  An element that cannot hold the content closes instead of nesting it:
// a heading inside a heading does not survive a browser's parse, so the
// output would read back as a different tree.
func TestPushedOutContentIsJudgedByWhatHoldsTheTable(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tbody", "tr", "td", "h1", "button"))
	heading := p.Sanitize(
		"<h1><table><tr><td>a</td></tr><h1>b</h1></table>")
	hstAssertEqual(t,
		"<h1><table><tbody><tr><td>a</td></tr></tbody></table></h1>"+
			"<h1>b</h1>",
		heading)
	hstAssertEqual(t, heading, p.Sanitize(heading))

	button := p.Sanitize(
		"<button><table><tr><td>a</td></tr><button>b</button></table>")
	hstAssertEqual(t,
		"<button><table><tbody><tr><td>a</td></tr></tbody></table></button>"+
			"<button>b</button>",
		button)
	hstAssertEqual(t, button, p.Sanitize(button))
}

// TestContentBesideAPushedOutTableStillGetsItsImpliedWrapper: and it gets
// the elements a browser would imply around it there: an option needs its
// select whether or not a table was pushed out of the way, which the tables
// never leave to chance, since the sanitizer does not know what the output
// will be embedded in.
func TestContentBesideAPushedOutTableStillGetsItsImpliedWrapper(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tbody", "tr", "td", "select", "option"))
	out := p.Sanitize("<table>x<option>o</option></table>z")

	hstAssertEqual(t, "<table></table>x<select><option>o</option></select>z", out)
	hstAssertEqual(t, out, p.Sanitize(out))
}

// TestTextAfterAPushedOutTableSurvivesAContainerThatCannotHoldIt: text that
// follows a pushed-out table reaches the output even where the element
// holding the table cannot hold text: that element closes, as it would for
// text arriving anywhere else, rather than the text going into it and being
// dropped.  The row after a column closes the colgroup and continues in the
// existing table (#483), and tail survives.
func TestTextAfterAPushedOutTableSurvivesAContainerThatCannotHoldIt(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "colgroup", "col", "tbody", "tr", "td"))
	out := p.Sanitize("<table><col><tr><td>a</td></tr>tail</table>")

	hstAssertEqual(t,
		"<table><colgroup><col /></colgroup>"+
			"<tbody><tr><td>a</td></tr></tbody></table>tail",
		out)
	hstAssertEqual(t, out, p.Sanitize(out))
}

// TestACellReturningToAPushedOutSectionDoesNotOpenANewTable: a cell
// returning to a pushed-out table lands in the table, not in a fresh one:
// the row group it arrives in cannot hold a cell without a row between, and
// the path to that row runs through a table, so the row group goes and the
// table takes the cell.
func TestACellReturningToAPushedOutSectionDoesNotOpenANewTable(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "thead", "tfoot", "tbody", "tr", "td", "th"))
	head := p.Sanitize("<table><thead>x<td>y</td></table>tail")
	hstAssertEqual(t,
		"<table><thead></thead></table>x"+
			"<table><tbody><tr><td>y</td></tr></tbody></table>tail",
		head)
	hstAssertEqual(t, head, p.Sanitize(head))

	foot := p.Sanitize("<table><tfoot>x<th>h</th></table>tail")
	hstAssertEqual(t,
		"<table><tfoot></tfoot></table>x"+
			"<table><tbody><tr><th>h</th></tr></tbody></table>tail",
		foot)
	hstAssertEqual(t, foot, p.Sanitize(foot))
}

// TestLinkIsNotResumedAroundAnotherLinkWithoutATable: the rule that a link
// is not written again around or inside another link is not about tables:
// an end tag that closes the element a link was misnested in queues the link
// for resumption, and resuming it around the next link used to produce
// nested links, which a browser's parse unnests, so the output read back as
// a different tree.
func TestLinkIsNotResumedAroundAnotherLinkWithoutATable(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("div", "p", "a").
		AllowAttributes("href").OnElements("a").
		AllowURLProtocols("http").
		AllowWithoutAttributes("a"))
	out := p.Sanitize(
		"<div><a href=http://u>x</div><a href=http://v>y")
	hstAssertEqual(t,
		"<div><a href=\"http://u\">x</a></div><a href=\"http://v\">y</a>",
		out)
	hstAssertEqual(t, out, p.Sanitize(out))

	nested := p.Sanitize(
		"<div><a href=http://u>x<p><a href=http://v>y</a></p></a>")
	hstAssertEqual(t,
		"<div><a href=\"http://u\">x<p></p></a>"+
			"<a href=\"http://v\">y</a></div>",
		nested)
	hstAssertEqual(t, nested, p.Sanitize(nested))
}

// TestPushedOutContentRespectsTheNestingLimit: pushed-out content is bounded
// by the nesting limit like any other.
func TestPushedOutContentRespectsTheNestingLimit(t *testing.T) {
	p := hstTablePolicy(t)
	input := "<table>" + strings.Repeat("<div>", 300) +
		"<tr><td>y</td></tr></table>z"
	out := p.Sanitize(input)
	hstAssertTrue(t,
		strings.HasSuffix(out, "</div><table><tbody><tr><td>y</td></tr></tbody></table>z"),
		out[max(0, len(out)-80):])
	hstAssertEqual(t, out, p.Sanitize(out))
}

// TestRepeatedPushOutAndReturnDoesNotAccumulate: a table arriving beside a
// pushed-out table replaces it, so a long run of them leaves nothing behind:
// the stack stays flat however many there are, where the content used to
// nest one run inside the next.
func TestRepeatedPushOutAndReturnDoesNotAccumulate(t *testing.T) {
	p := hstTablePolicy(t)
	input := strings.Repeat("<table><div>", 300) + "<tr><td>y</td></tr></table>z"
	out := p.Sanitize(input)

	expected := strings.Repeat("<table></table><div></div>", 300) +
		"<table><tbody><tr><td>y</td></tr></tbody></table>z"
	hstAssertEqual(t, expected, out)
	hstAssertEqual(t, out, p.Sanitize(out))
}

// TestFormStartIsPoppedInTableModes is issue #484: a form inserted by the
// table modes is popped at once.
func TestFormStartIsPoppedInTableModes(t *testing.T) {
	p := hstFormTablePolicy(t)
	cases := [][2]string{
		{
			"<table><form><tr><td>y</td></tr></table>",
			"<table><form></form><tbody><tr><td>y</td></tr></tbody></table>",
		},
		{
			"<table><thead><form><tr><td>y</td></tr></thead></table>",
			"<table><thead><form></form><tr><td>y</td></tr></thead></table>",
		},
		{
			"<table><tbody><form><tr><td>y</td></tr></tbody></table>",
			"<table><tbody><form></form><tr><td>y</td></tr></tbody></table>",
		},
		{
			"<table><tfoot><form><tr><td>y</td></tr></tfoot></table>",
			"<table><tfoot><form></form><tr><td>y</td></tr></tfoot></table>",
		},
		{
			"<table><tr><form><td>y</td></tr></table>",
			"<table><tbody><tr><form></form><td>y</td></tr></tbody></table>",
		},
	}
	for _, c := range cases {
		out := p.Sanitize(c[0])
		hstAssertEqual(t, c[1], out, c[0])
		hstAssertEqual(t, out, p.Sanitize(out), c[0])
		hstAssertEqual(t, hstParseAsBrowser(t, c[0]), hstParseAsBrowser(t, out), c[0])
	}
}

// TestTableFormDoesNotContainFollowingContent: the reported text and row are
// not children of the table-mode form.
func TestTableFormDoesNotContainFollowingContent(t *testing.T) {
	p := hstFormTablePolicy(t)
	input := "<table><form id=f>x<tr><td>y</td></tr></table>tail"
	out := p.Sanitize(input)

	hstAssertEqual(t,
		"<table><form id=\"f\"></form></table>x"+
			"<table><tbody><tr><td>y</td></tr></tbody></table>tail",
		out)
	hstAssertEqual(t, out, p.Sanitize(out))
	// A browser foster-parents "x" in front of the table it arrives in.  The
	// sanitizer serializes content pushed out of a table after the table it
	// was pushed out of, as it has for text since #481, so the browser's tree
	// of the output is not the tree of the input: the table is split around
	// "x".  What must agree is that the form has no children and that
	// nothing is lost or reordered.
	hstAssertEqual(t,
		"<table>\n"+
			"  <form id=f>\n"+
			"\"x\"\n"+
			"<table>\n"+
			"  <tbody>\n"+
			"    <tr>\n"+
			"      <td>\n"+
			"        \"y\"\n"+
			"\"tail\"\n",
		hstParseAsBrowser(t, out))
	hstAssertEqual(t, hstTextOf(hstParseAsBrowser(t, input)), hstTextOf(hstParseAsBrowser(t, out)))

	hstAssertEqual(t, out, p.SanitizeWithListener(input, hstIgnoringListener{}, nil))
}

// TestFormsInCellsCaptionsAndTemplates: cells and captions use in-body form
// nesting; templates bound the scope.
func TestFormsInCellsCaptionsAndTemplates(t *testing.T) {
	p := hstFormTablePolicy(t)
	cases := [][2]string{
		{
			"<table><tr><td><form>x</form>y</td></tr></table>",
			"<table><tbody><tr><td><form>x</form>y</td></tr></tbody></table>",
		},
		{
			"<table><caption><form>x</form>y</caption></table>",
			"<table><caption><form>x</form>y</caption></table>",
		},
		{
			"<template><form>x</form></template>",
			"<template><form>x</form></template>",
		},
		{
			"<template><table><form><tr><td>y</td></tr></table></template>",
			"<template><table><form></form><tbody><tr><td>y</td></tr></tbody>" +
				"</table></template>",
		},
		{
			"<table><template><form>x</form></template>" +
				"<tr><td>y</td></tr></table>",
			"<table><template><form>x</form></template>" +
				"<tbody><tr><td>y</td></tr></tbody></table>",
		},
	}
	for _, c := range cases {
		out := p.Sanitize(c[0])
		hstAssertEqual(t, c[1], out, c[0])
		hstAssertEqual(t, out, p.Sanitize(out), c[0])
		hstAssertEqual(t, hstParseAsBrowser(t, c[0]), hstParseAsBrowser(t, out), c[0])
	}
}

// TestTableFormsKeepBrowserFormPointerSemantics: the input form pointer
// stays set until an input end tag clears it.
func TestTableFormsKeepBrowserFormPointerSemantics(t *testing.T) {
	p := hstFormTablePolicy(t)
	cases := [][2]string{
		{
			"<table><form id=a><form id=b><tr><td>y</td></tr></table>",
			"<table><form id=\"a\"></form><tbody><tr><td>y</td></tr></tbody>" +
				"</table>",
		},
		{
			"<table><form id=a></form><form id=b><tr><td>y</td></tr></table>",
			"<table><form id=\"a\"></form><form id=\"b\"></form>" +
				"<tbody><tr><td>y</td></tr></tbody></table>",
		},
		{
			"<table><form id=a></table><form id=b>x",
			"<table><form id=\"a\"></form></table>x",
		},
		{
			"<form id=a><table><form id=b><tr><td>y</td></tr></table>" +
				"<form id=c>x",
			"<form id=\"a\"><table><tbody><tr><td>y</td></tr></tbody></table>" +
				"x</form>",
		},
		{
			"<table><form id=a><template></template><form id=b>" +
				"<tr><td>y</td></tr></table>",
			"<table><form id=\"a\"></form><template></template>" +
				"<tbody><tr><td>y</td></tr></tbody></table>",
		},
		{
			"<table><form id=a><template></template></form><form id=b>" +
				"<tr><td>y</td></tr></table>",
			"<table><form id=\"a\"></form><template></template>" +
				"<form id=\"b\"></form>" +
				"<tbody><tr><td>y</td></tr></tbody></table>",
		},
		{
			"<form id=a><table></form><form id=b>" +
				"<tr><td>y</td></tr></table>",
			"<form id=\"a\"><table><form></form><form id=\"b\"></form>" +
				"<tbody><tr><td>y</td></tr></tbody></table></form>",
		},
		{
			"<form id=a><table></form></table><div><form id=b>x",
			"<form id=\"a\"><table><form></form></table><div>" +
				"<form id=\"b\">x</form></div></form>",
		},
	}
	for _, c := range cases {
		out := p.Sanitize(c[0])
		hstAssertEqual(t, c[1], out, c[0])
		hstAssertEqual(t, out, p.Sanitize(out), c[0])
		hstAssertEqual(t, hstParseAsBrowser(t, c[0]), hstParseAsBrowser(t, out), c[0])
	}
}

// hstP3Case is an input and the output it sanitizes to.
type hstP3Case struct{ input, want string }

// hstP3AssertCases asserts that each case sanitizes as expected and that its
// output is a fixed point.
func hstP3AssertCases(t *testing.T, p *PolicyFactory, cases []hstP3Case) {
	t.Helper()
	for _, c := range cases {
		out := p.Sanitize(c.input)
		hstAssertEqual(t, c.want, out, c.input)
		hstAssertEqual(t, out, p.Sanitize(out), c.input)
	}
}

// hstP3AssertCasesReparse is hstP3AssertCases, also comparing the browser
// tree of the output with that of its own sanitized form.
func hstP3AssertCasesReparse(t *testing.T, p *PolicyFactory, cases []hstP3Case) {
	t.Helper()
	for _, c := range cases {
		out := p.Sanitize(c.input)
		hstAssertEqual(t, c.want, out, c.input)
		hstAssertEqual(t, out, p.Sanitize(out), c.input)
		hstAssertEqual(t,
			hstParseAsBrowser(t, out), hstParseAsBrowser(t, p.Sanitize(out)), c.input)
	}
}

// TestFormDroppedAtNestingLimitDoesNotLatchThePointer checks that a form the
// nesting limit drops is not in the output, so it must not latch the form
// pointer: the output parser's pointer stays null, and a later form is
// inserted.  The pointer used to stay set, which silently discarded every
// form for the rest of the document.
func TestFormDroppedAtNestingLimitDoesNotLatchThePointer(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("form", "div").
		AllowWithoutAttributes("form", "div"))
	// At depth 255 the form fits, sets the pointer as a browser would, and
	// the later form is ignored for it.  From 256 on the form is dropped at
	// the limit, so the pointer stays clear and the later form is kept.
	fits := p.Sanitize(
		strings.Repeat("<div>", 255) + "<form>a" +
			strings.Repeat("</div>", 255) + "<form>b</form>")
	hstAssertEqual(t,
		strings.Repeat("<div>", 255)+"<form>a</form>"+
			strings.Repeat("</div>", 255)+"b",
		fits)
	hstAssertEqual(t, fits, p.Sanitize(fits))
	for _, depth := range []int{256, 300} {
		out := p.Sanitize(
			strings.Repeat("<div>", depth) + "<form>a" +
				strings.Repeat("</div>", depth) + "<form>b</form>")
		hstAssertEqual(t,
			strings.Repeat("<div>", 256)+"a"+
				strings.Repeat("</div>", 256)+"<form>b</form>",
			out, fmt.Sprintf("depth %d", depth))
		hstAssertEqual(t, out, p.Sanitize(out), fmt.Sprintf("depth %d", depth))
	}
}

// TestForeignFormsAfterUnknownContextAreNotDroppedByThePointer checks that a
// stray table end tag inside SVG makes the input tracker give up on the
// namespace.  The forms that follow are still SVG elements, which a browser
// inserts without consulting the form pointer, so they are all kept, as they
// are when the output is parsed.  Applying the HTML rule dropped the second
// form and merged its text into the first.
func TestForeignFormsAfterUnknownContextAreNotDroppedByThePointer(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("svg", "form", "b").
		AllowWithoutAttributes("svg", "form", "b"))
	hstP3AssertCasesReparse(t, p, []hstP3Case{
		{
			"<svg></tr><form><form>",
			"<svg><form></form><form></form></svg>",
		},
		{
			"<svg></tr><form><b></b><form>x</form></form>",
			"<svg><form><b></b></form><form>x</form></svg>",
		},
		// Once the foreign root is closed the output is HTML again, and the
		// pointer rule applies: the second form is ignored.
		{
			"<svg></tr></svg><form><form>x",
			"<svg></svg><form>x</form>",
		},
	})
}

// TestFormEndInIntegrationPointClearsThePointerWhenTrackerIsUnknown checks
// that a form in an HTML integration point sets the pointer under HTML rules.
// If the tracker then gives up, its end tag arrives while the output is still
// inside the foreign root, and judging the end tag by the output alone called
// it foreign, left the pointer set, and dropped every form after it.  The end
// tag closes the form its start was judged by.
func TestFormEndInIntegrationPointClearsThePointerWhenTrackerIsUnknown(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("svg", "foreignObject", "form", "div").
		AllowWithoutAttributes("svg", "foreignObject", "form", "div"))
	hstP3AssertCasesReparse(t, p, []hstP3Case{
		{
			"<svg><foreignObject><form>a</tr></form></foreignObject></svg>" +
				"<form>b</form>",
			"<svg><foreignObject><form>a</form></foreignObject></svg>" +
				"<form>b</form>",
		},
		{
			"<svg><foreignObject><form>a</tr></form></foreignObject></svg>" +
				"<div><form>b</form></div>",
			"<svg><foreignObject><form>a</form></foreignObject></svg>" +
				"<div><form>b</form></div>",
		},
	})
}

// TestFormEndInsideTemplateDoesNotClearOuterPointer checks that a form end
// inside template contents does not clear an outer pointer.
func TestFormEndInsideTemplateDoesNotClearOuterPointer(t *testing.T) {
	p := hstFormTablePolicy(t)
	input := "<table><form id=a><template></form></template><form id=b>" +
		"<tr><td>y</td></tr></table>"
	out := p.Sanitize(input)

	hstAssertEqual(t,
		"<table><form id=\"a\"></form><template></template>"+
			"<tbody><tr><td>y</td></tr></tbody></table>",
		out)
	hstAssertEqual(t, out, p.Sanitize(out))
	// validator.nu 1.4 does not model template contents closely enough for
	// this form-pointer comparison; the current tree-construction rule keeps
	// the outer pointer set because the end tag is inside template contents.
}

// TestFormInPushedOutTableContentIsPopped checks that a form in content
// foster-parented out of a table is also popped at once.
func TestFormInPushedOutTableContentIsPopped(t *testing.T) {
	p := hstFormTablePolicy(t)
	input := "<table><div><form>x<tr><td>y</td></tr></table>tail"
	out := p.Sanitize(input)

	hstAssertEqual(t,
		"<table></table><div><form></form>x</div>"+
			"<table><tbody><tr><td>y</td></tr></tbody></table>tail",
		out)
	hstAssertEqual(t, out, p.Sanitize(out))
	hstAssertEqual(t,
		hstParseAsBrowser(t, "<table></table>"+input), hstParseAsBrowser(t, out))
}

// TestLaterFormAfterPushedOutTableIsIdempotent checks that a pushed-out table
// cannot leave its outer output form pointer stale.
func TestLaterFormAfterPushedOutTableIsIdempotent(t *testing.T) {
	p := hstFormTablePolicy(t)
	hstP3AssertCases(t, p, []hstP3Case{
		{
			"<form id=a><table><div></form></table><div><form id=b>x",
			"<form id=\"a\"><table></table><div></div><div></div></form>" +
				"<form id=\"b\">x</form>",
		},
		{
			"<form id=a><strong><table><div></form></table>" +
				"<div><form id=b>x",
			"<form id=\"a\"><strong><table></table><div></div><div></div>" +
				"</strong></form><form id=\"b\"><strong>x</strong></form>",
		},
		{
			"<form id=a><a><table><div></form></table><div><form id=b>x",
			"<form id=\"a\"><table></table><div></div><div></div></form>" +
				"<form id=\"b\">x</form>",
		},
	})
}

// TestDroppedTableModeForm checks that dropping an empty table-mode form does
// not leave a policy stack entry.  The text around it is pushed out of the
// table as a browser foster-parents it, and none of it is lost.
func TestDroppedTableModeForm(t *testing.T) {
	p := hstTableFormReplacementPolicy(t, "")
	cases := []hstP3Case{
		{
			"<table><form>F<tr><td>R</td></tr></table>T",
			"<table></table>F<table><tbody><tr><td>R</td></tr></tbody></table>T",
		},
		{
			"<table><tbody><form>F<tr><td>R</td></tr></tbody></table>T",
			"<table><tbody></tbody></table>F" +
				"<table><tbody><tr><td>R</td></tr></tbody></table>T",
		},
		{
			"<table><tr><form>F<td>R</td></tr></table>T",
			"<table><tbody><tr></tr></tbody></table>F" +
				"<table><tbody><tr><td>R</td></tr></tbody></table>T",
		},
		{
			"<table><div>P<form>F<tr><td>R</td></tr></table>T",
			"<table></table><div>PF</div>" +
				"<table><tbody><tr><td>R</td></tr></tbody></table>T",
		},
		{
			"<template><table><form>F<tr><td>R</td></tr></table></template>T",
			"<template><table></table>F" +
				"<table><tbody><tr><td>R</td></tr></tbody></table></template>T",
		},
	}
	for _, c := range cases {
		out := p.Sanitize(c.input)
		hstAssertEqual(t, c.want, out, c.input)
		hstAssertEqual(t, out, p.Sanitize(out), c.input)
		hstAssertEqual(t,
			hstTextOf(hstParseAsBrowser(t, c.input)),
			hstTextOf(hstParseAsBrowser(t, out)), c.input)
	}
}

// TestTableModeFormUsesEmittedTableContext checks that table-mode detection
// follows the table and template policy emitted.
func TestTableModeFormUsesEmittedTableContext(t *testing.T) {
	droppedTable := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("tbody", "form"))
	noTable := droppedTable.Sanitize(
		"<table><tbody><form></form></table><form>x")
	hstAssertEqual(t, "<tbody><form></form></tbody><form>x</form>", noTable)
	hstAssertEqual(t, noTable, droppedTable.Sanitize(noTable))

	droppedTemplate := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tbody", "tr", "td", "form"))
	noTemplate := droppedTemplate.Sanitize("<table><template><form>x")
	// The dropped template changes the insertion mode, so the table is
	// closed for the content after the form; that content is kept.
	hstAssertEqual(t, "<table><form></form></table>x", noTemplate)
	hstAssertEqual(t, noTemplate, droppedTemplate.Sanitize(noTemplate))
}

// TestTextAfterRetiredOutputTableIsKept checks that text after a table-mode
// form is foster-parented out of the table, and a table part the policy
// dropped between them does not change that.  When the output table is
// closed for it, the text lands beside the table; it used to be judged as if
// still inside the table and silently dropped.  The same held for text in a
// dropped caption or cell of a kept table.
func TestTextAfterRetiredOutputTableIsKept(t *testing.T) {
	tableAndForm := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "form"))
	for _, c := range []hstP3Case{
		{"<tbody><form>B", "<table><form></form></table>B"},
		{"<tbody><form>B</form>C", "<table><form></form></table>BC"},
		{"<tr><form>B", "<table><form></form></table>B"},
		{"<table><tbody><form>B</form>C", "<table><form></form></table>BC"},
	} {
		hstAssertRoundTripAndBalanced(t, tableAndForm, c.input, c.want)
	}
	tableOnly := hstFactory(t, NewHTMLPolicyBuilder().AllowElements("table"))
	for _, c := range []hstP3Case{
		{"<table><caption>E", "<table></table>E"},
		{"<td>E", "<table></table>E"},
		{"<caption>E", "<table></table>E"},
	} {
		hstAssertRoundTripAndBalanced(t, tableOnly, c.input, c.want)
	}
	tableAndList := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "ul", "li"))
	hstAssertRoundTripAndBalanced(t,
		tableAndList, "<ul><caption>E", "<ul><li></li></ul><table></table>E")
}

// TestTableModeFormWithDroppedRowGroupKeepsOneTable checks that a row group or
// row the policy drops does not change the table insertion mode: the output
// parser implies it again.  The in-table form rule used to retire the output
// table for any such mismatch, so a form in a row whose tbody was dropped
// split the table in two, with the cells before and after it in different
// tables.  Only a dropped boundary that changes the mode, such as a template,
// still retires the table.
func TestTableModeFormWithDroppedRowGroupKeepsOneTable(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tr", "td", "form").
		AllowAttributes("id").OnElements("form"))
	for _, c := range []hstP3Case{
		{
			"<table><tr><form id=f><td>c</td></tr></table>",
			"<table><tr><form id=\"f\"></form><td>c</td></tr></table>",
		},
		{
			"<table><tr><td>a</td><form id=f><td>b</td></tr></table>",
			"<table><tr><td>a</td><form id=\"f\"></form><td>b</td></tr></table>",
		},
	} {
		out := p.Sanitize(c.input)
		hstAssertEqual(t, c.want, out, c.input)
		hstAssertEqual(t, out, p.Sanitize(out), c.input)
		hstAssertEqual(t, hstParseAsBrowser(t, c.input), hstParseAsBrowser(t, out), c.input)
	}
	// With the form directly in the dropped tbody, the output parser implies
	// the tbody only at the row, so the form becomes a child of the table
	// rather than of the row group.  The table is still one table, as on
	// main; the output is compared with its own reparse.
	input := "<table><tbody><form id=f><tr><td>c</td></tr></tbody></table>"
	out := p.Sanitize(input)
	hstAssertEqual(t,
		"<table><form id=\"f\"></form><tr><td>c</td></tr></table>", out)
	hstAssertEqual(t, out, p.Sanitize(out))
	hstAssertEqual(t, hstParseAsBrowser(t, out), hstParseAsBrowser(t, p.Sanitize(out)))
}

// TestTableModeFormWithDroppedHeaderGroupStillRetiresTheTable checks that a
// dropped thead or tfoot is not what the output parser implies again: it
// implies a tbody in its place, and a policy that keeps tbody emits one on
// the next pass.  So the table is still retired for the form there, as it is
// for a dropped template, and the output is a fixed point.
func TestTableModeFormWithDroppedHeaderGroupStillRetiresTheTable(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tbody", "tr", "td", "form").
		AllowWithoutAttributes("table", "tbody", "tr", "td", "form"))
	hstP3AssertCases(t, p, []hstP3Case{
		{
			"<table><thead><form><tr><td>x",
			"<table><form></form></table>" +
				"<table><tbody><tr><td>x</td></tr></tbody></table>",
		},
		{
			"<table><tfoot><form><tr><td>x",
			"<table><form></form></table>" +
				"<table><tbody><tr><td>x</td></tr></tbody></table>",
		},
	})
}

// TestFormInPolicyProducedTableIsRoundTripStable checks that content after a
// form cannot remain in a policy-produced output table.
func TestFormInPolicyProducedTableIsRoundTripStable(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(hstRenamingPolicy("table"), "template").
		AllowElements(
			"form", "table", "tbody", "tr", "td", "div", "strong").
		AllowTextIn("form", "td", "div", "strong"))
	cases := []hstP3Case{
		{
			"<template><form>x",
			"<table><form></form></table>x",
		},
		{
			"<form><table></form></table><template><form>x",
			"<form><table><form></form></table>" +
				"<table><form></form></table>x</form>",
		},
		{
			"<template><form></form><tbody><tr><td>x</td></tr></tbody>",
			"<table><form></form></table>" +
				"<table><tbody><tr><td>x</td></tr></tbody></table>",
		},
		{
			"<template><form></form><table><tr><td>x</td></tr></table>",
			"<table><form></form></table>" +
				"<table><tbody><tr><td>x</td></tr></tbody></table>",
		},
		{
			"<template><form></form><form>x</form>",
			"<table><form></form></table><form>x</form>",
		},
		{
			"<template><form></form><strong>x</strong>",
			"<table><form></form></table><strong>x</strong>",
		},
		{
			"<form><table><div></form><template><form>x</form></template>" +
				"<div><form>y</form></div></table>",
			"<form><table></table><div>x<div>y</div></div></form>",
		},
	}
	for _, c := range cases {
		out := p.Sanitize(c.input)
		hstAssertEqual(t, c.want, out, c.input)
		again := p.Sanitize(out)
		hstAssertEqual(t, out, again, c.input)
		hstAssertEqual(t, hstParseAsBrowser(t, out), hstParseAsBrowser(t, again), c.input)
	}
}

// TestFormInForeignElementRenamedToTableIsRoundTripStable checks that foreign
// input names renamed to an HTML table use its output form rules.
func TestFormInForeignElementRenamedToTableIsRoundTripStable(t *testing.T) {
	cases := []struct{ name, input, want string }{
		{"svg", "<svg><form>x", "<table><form></form></table>x"},
		{"math", "<math><form>x", "<table><form></form></table>x"},
		{
			"foreignObject", "<svg><foreignObject><form>x",
			"<svg></svg><table><form></form></table>x",
		},
		{
			"g", "<svg><g><form>x",
			"<svg></svg><table><form></form></table>x",
		},
		{
			"textArea", "<svg><textArea><form>x",
			"<svg></svg><table><form></form></table>x",
		},
	}
	for _, c := range cases {
		b := NewHTMLPolicyBuilder().
			AllowElementsWithPolicy(hstRenamingPolicy("table"), c.name).
			AllowElements("form", "table").
			AllowTextIn("form")
		if c.name != "svg" {
			b.AllowElements("svg")
		}
		p := hstFactory(t, b)
		out := p.Sanitize(c.input)
		hstAssertEqual(t, c.want, out, c.name)
		hstAssertEqual(t, out, p.Sanitize(out), c.name)
	}

	mappedSvg := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(hstRenamingPolicy("table"), "svg").
		AllowElements(
			"form", "table", "template", "foreignObject", "g", "textArea").
		AllowTextIn("form"))
	hstP3AssertCases(t, mappedSvg, []hstP3Case{
		{
			"<svg><foreignObject><form>x",
			"<table></table><foreignObject><form>x</form></foreignObject>",
		},
		{
			"<svg><g><form>x",
			"<table></table><g><form>x</form></g>",
		},
		{
			"<svg><textArea><form>x",
			"<table></table><textArea><form>x</form></textArea>",
		},
		{
			"<template><svg><form>x",
			"<template><form>x</form></template>",
		},
	})

	suppressMappedDescendantText := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(hstRenamingPolicy("table"), "svg").
		AllowElements("form", "table", "foreignObject").
		AllowTextIn("form").
		DisallowTextIn("foreignObject"))
	suppressedInput :=
		"<svg><foreignObject><form>x</form>after</foreignObject>tail"
	suppressed := suppressMappedDescendantText.Sanitize(suppressedInput)
	hstAssertEqual(t,
		"<table></table><foreignObject><form>x</form></foreignObject>tail",
		suppressed)
	hstAssertEqual(t,
		suppressed, suppressMappedDescendantText.Sanitize(suppressed))

	mappedMath := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(hstRenamingPolicy("table"), "math").
		AllowElements("form", "table", "template", "mrow", "mtext").
		AllowTextIn("form"))
	hstP3AssertCases(t, mappedMath, []hstP3Case{
		{
			"<math><mrow><form>x",
			"<table></table><mrow><form>x</form></mrow>",
		},
		{
			"<math><mtext><form>x",
			"<table></table><mtext><form>x</form></mtext>",
		},
		{
			"<template><math><form>x",
			"<template><form>x</form></template>",
		},
	})
}

// TestForeignFormDoesNotUsePushedOutHTMLTableRules checks that a foreign form
// beside a pushed-out table keeps its text.
func TestForeignFormDoesNotUsePushedOutHTMLTableRules(t *testing.T) {
	p := hstFormTablePolicy(t)
	input := "<table><svg><form>x</form></svg>" +
		"<tr><td>y</td></tr></table>"
	out := p.Sanitize(input)

	hstAssertEqual(t,
		"<table></table><svg><form>x</form></svg>"+
			"<table><tbody><tr><td>y</td></tr></tbody></table>",
		out)
	hstAssertEqual(t, out, p.Sanitize(out))
	hstAssertEqual(t,
		hstParseAsBrowser(t, "<table></table>"+input), hstParseAsBrowser(t, out))
}

// TestPolicyProducedFormPointerBlocksTableForm checks that a form introduced
// by policy can make a later table form start ignored.
func TestPolicyProducedFormPointerBlocksTableForm(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(hstRenamingPolicy("form"), "div").
		AllowElements(
			"form", "table", "strong", "template", "svg", "g", "math",
			"mrow").
		AllowTextIn("form", "div", "strong"))
	cases := []hstP3Case{
		{
			"<div><table><form>x",
			"<form><table></table>x</form>",
		},
		{
			"<div><table><strong><form>x",
			"<form><table></table><strong>x</strong></form>",
		},
		{
			"<table><div><form>x",
			"<table></table><form>x</form>",
		},
		{
			"<form><table></form></table><div><form>x",
			"<form><table><form></form></table><form>x</form></form>",
		},
		{
			"<form><table></form></table><div><table><form>x",
			"<form><table><form></form></table>" +
				"<form><table></table>x</form></form>",
		},
		{
			"<form><table><div></form></table>" +
				"<template><div><table><strong><form>x",
			"<form><table></table><template><form><table></table>" +
				"<strong><form></form>x</strong></form></template></form>",
		},
		{
			"<form><table></form></table><svg><g><div><form>x",
			"<form><table><form></form></table><svg><g>" +
				"<form><form>x</form></form></g></svg></form>",
		},
		{
			"<form><table></form></table><math><mrow><div><form>x",
			"<form><table><form></form></table><math><mrow>" +
				"<form><form>x</form></form></mrow></math></form>",
		},
		{
			"<form><table><div></form></table><svg><g><div><form>x",
			"<form><table></table><svg><g>" +
				"<form><form>x</form></form></g></svg></form>",
		},
		{
			"<form><table><div></form></table><math><mrow><div><form>x",
			"<form><table></table><math><mrow>" +
				"<form><form>x</form></form></mrow></math></form>",
		},
	}
	hstP3AssertCases(t, p, cases)

	// Output through the reporter decorator is under test.
	hstAssertEqual(t,
		cases[1].want, p.SanitizeWithListener(cases[1].input, hstIgnoringListener{}, nil))
}

// TestPolicyProducedFormStartUsesOutputContext checks that policy-produced
// form starts obey output pointer and namespace rules.
func TestPolicyProducedFormStartUsesOutputContext(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(hstRenamingPolicy("form"), "div").
		AllowElements("form", "template", "svg").
		AllowTextIn("form", "div"))
	hstP3AssertCases(t, p, []hstP3Case{
		{"<form><div>x", "<form>x</form>"},
		{
			"<template><form><div>x",
			"<template><form><form>x</form></form></template>",
		},
		{
			"<svg><form><div>x",
			"<svg><form><form>x</form></form></svg>",
		},
	})
}

// TestFormPointerResetRequiresEmittedTable checks that a pointer-reset pair
// requires a table in the policy's output scope.
func TestFormPointerResetRequiresEmittedTable(t *testing.T) {
	droppedTable := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("form").
		AllowTextIn("form"))
	dropped := droppedTable.Sanitize("<form><table></form></table>x")
	hstAssertEqual(t, "<form>x</form>", dropped)
	hstAssertEqual(t, dropped, droppedTable.Sanitize(dropped))

	renamedTable := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(hstRenamingPolicy("div"), "table").
		AllowElements("form", "div").
		AllowTextIn("form"))
	renamed := renamedTable.Sanitize("<form><table></form></table>x")
	hstAssertEqual(t, "<form><div></div>x</form>", renamed)
	hstAssertEqual(t, renamed, renamedTable.Sanitize(renamed))
}

// TestDeferredFormPointerRetirementFollowsPolicyOutput checks that a later
// emitted form retires a pointer that no output table could clear.
func TestDeferredFormPointerRetirementFollowsPolicyOutput(t *testing.T) {
	input := "<form><table></form></table><div>q<form>x"

	droppedTable := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("form", "div").
		AllowTextIn("form", "div"))
	dropped := droppedTable.Sanitize(input)
	hstAssertEqual(t, "<form><div>q</div></form><form>x</form>", dropped)
	hstAssertEqual(t, dropped, droppedTable.Sanitize(dropped))

	renamedTable := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(hstRenamingPolicy("div"), "table").
		AllowElements("form", "div").
		AllowTextIn("form", "div"))
	renamed := renamedTable.Sanitize(input)
	hstAssertEqual(t,
		"<form><div></div><div>q</div></form><form>x</form>", renamed)
	hstAssertEqual(t, renamed, renamedTable.Sanitize(renamed))
}

// TestDeferredFormPointerRetirementRequiresOutputForm checks that a dropped
// or renamed later form does not shorten the outer form.
func TestDeferredFormPointerRetirementRequiresOutputForm(t *testing.T) {
	input := "<form id=a><table></form></table>" +
		"<div>q<form id=b>x"

	droppedForm := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(ElementPolicyFunc(func(name string, attrs *[]string) (string, bool) {
			if hstHasID(*attrs, "b") {
				return "", false
			}
			return name, true
		}), "form").
		AllowElements("div").
		AllowAttributes("id").OnElements("form", "div").
		AllowTextIn("form", "div"))
	dropped := droppedForm.Sanitize(input)
	hstAssertEqual(t, "<form id=\"a\"><div>qx</div></form>", dropped)
	hstAssertEqual(t, dropped, droppedForm.Sanitize(dropped))

	renamedForm := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(ElementPolicyFunc(func(name string, attrs *[]string) (string, bool) {
			if hstHasID(*attrs, "b") {
				return "div", true
			}
			return name, true
		}), "form").
		AllowElements("div").
		AllowAttributes("id").OnElements("form", "div").
		AllowTextIn("form", "div"))
	renamed := renamedForm.Sanitize(input)
	hstAssertEqual(t,
		"<form id=\"a\"><div>q<div id=\"b\">x</div></div></form>",
		renamed)
	hstAssertEqual(t, renamed, renamedForm.Sanitize(renamed))
}

// TestDroppedTemplateDoesNotHideOutputFormPointer checks that dropping an
// input template makes its form ordinary in the output.
func TestDroppedTemplateDoesNotHideOutputFormPointer(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("form", "table", "div").
		AllowTextIn("form", "div"))
	input := "<form><table></form></table>" +
		"<template><form>x</form></template>" +
		"<div><form>y</form></div>"
	out := p.Sanitize(input)

	hstAssertEqual(t,
		"<form><table><form></form></table>"+
			"<form>x</form><div><form>y</form></div></form>",
		out)
	hstAssertEqual(t, out, p.Sanitize(out))
}

// TestRenamedTableModeFormIsEmpty checks that a renamed table-mode form is
// closed under its emitted output name.
func TestRenamedTableModeFormIsEmpty(t *testing.T) {
	// Output through the reporter decorator is under test.
	ignore := hstIgnoringListener{}
	cases := []struct{ replacement, input, want string }{
		{
			"style", "<table><form>F<tr><td>R</td></tr></table>T",
			"<table><style></style></table>F" +
				"<table><tbody><tr><td>R</td></tr></tbody></table>T",
		},
		{
			"div", "<table><div>P<form>F<tr><td>R</td></tr></table>T",
			"<table></table><div>P<div></div>F</div>" +
				"<table><tbody><tr><td>R</td></tr></tbody></table>T",
		},
		{
			"textarea", "<table><div>P<form>F<tr><td>R</td></tr></table>T",
			"<table></table><div>P<textarea></textarea>F</div>" +
				"<table><tbody><tr><td>R</td></tr></tbody></table>T",
		},
		{
			"svg", "<table><div>P<form>F<tr><td>R</td></tr></table>T",
			"<table></table><div>P<svg></svg>F</div>" +
				"<table><tbody><tr><td>R</td></tr></tbody></table>T",
		},
		{
			"math", "<table><div>P<form>F<tr><td>R</td></tr></table>T",
			"<table></table><div>P<math></math>F</div>" +
				"<table><tbody><tr><td>R</td></tr></tbody></table>T",
		},
		{
			"tbody", "<table><form>F<tr><td>R</td></tr></table>T",
			"<table><tbody></tbody></table>F" +
				"<table><tbody><tr><td>R</td></tr></tbody></table>T",
		},
		{
			"tr", "<table><tbody><form>F<tr><td>R</td></tr></tbody></table>T",
			"<table><tbody><tr></tr></tbody></table>F" +
				"<table><tbody><tr><td>R</td></tr></tbody></table>T",
		},
	}
	for _, c := range cases {
		p := hstTableFormReplacementPolicy(t, c.replacement)
		out := p.Sanitize(c.input)
		hstAssertEqual(t, c.want, out, c.replacement)
		hstAssertEqual(t, out, p.Sanitize(out), c.replacement)
		hstAssertEqual(t, out, p.SanitizeWithListener(c.input, ignore, nil), c.replacement)
	}
}

// TestTableFormBeforeLiteralAndForeignContent checks that literal and foreign
// content after a table form remains separate from it.
func TestTableFormBeforeLiteralAndForeignContent(t *testing.T) {
	p := hstFormTablePolicy(t)
	literal := "<table><form><style>x{}</style><script>f()</script>" +
		"<textarea>&lt;b&gt;</textarea><noscript><b>n</b></noscript>" +
		"<tr><td>y</td></tr></table>"
	literalOut := p.Sanitize(literal)
	hstAssertEqual(t,
		"<table><form></form><style>x{}</style><script>f()</script></table>"+
			"<textarea>&lt;b&gt;</textarea><noscript><b>n</b></noscript>"+
			"<table><tbody><tr><td>y</td></tr></tbody></table>",
		literalOut)
	hstAssertEqual(t, literalOut, p.Sanitize(literalOut))

	foreign := "<table><form><svg><g>s</g></svg>" +
		"<math><mrow>m</mrow></math><tr><td>y</td></tr></table>"
	foreignOut := p.Sanitize(foreign)
	hstAssertEqual(t,
		"<table><form></form></table><svg><g>s</g></svg>"+
			"<math><mrow>m</mrow></math>"+
			"<table><tbody><tr><td>y</td></tr></tbody></table>",
		foreignOut)
	hstAssertEqual(t, foreignOut, p.Sanitize(foreignOut))
}

// TestTableFormOpenAndCloseEventsAreBalanced checks that the balanced policy
// event stream contains an empty form.
func TestTableFormOpenAndCloseEventsAreBalanced(t *testing.T) {
	var events []string
	recorder := &hstReceiverFuncs{
		openDocument:  func() { events = append(events, "openDocument") },
		closeDocument: func() { events = append(events, "closeDocument") },
		openTag: func(elementName string, attrs []string) {
			events = append(events,
				"open "+elementName+" ["+strings.Join(attrs, ", ")+"]")
		},
		closeTag: func(elementName string) {
			events = append(events, "close "+elementName)
		},
		text: func(text string) { events = append(events, "text "+text) },
	}

	Sanitize(
		"<table><form id=f><tr><td>y</td></tr></table>", recorder, nil)

	want := []string{
		"openDocument", "open table []", "open form [id, f]", "close form",
		"open tbody []", "open tr []", "open td []", "text y", "close td",
		"close tr", "close tbody", "close table", "closeDocument",
	}
	if !slices.Equal(want, events) {
		t.Errorf("want %q\ngot  %q", want, events)
	}
}

// hstP3CountingReceiver counts the non-void open tags and the close tags it
// forwards.
type hstP3CountingReceiver struct {
	HTMLStreamEventReceiverWrapper
	opened, closed int
}

func (r *hstP3CountingReceiver) OpenTag(elementName string, attrs []string) {
	r.HTMLStreamEventReceiverWrapper.OpenTag(elementName, attrs)
	if !IsVoidElement(elementName) {
		r.opened++
	}
}

func (r *hstP3CountingReceiver) CloseTag(elementName string) {
	r.HTMLStreamEventReceiverWrapper.CloseTag(elementName)
	r.closed++
}

// TestTableFormPointerResetEventsAreBalanced checks that the synthetic
// pointer reset is balanced through the reporter wrapper.
func TestTableFormPointerResetEventsAreBalanced(t *testing.T) {
	var html strings.Builder
	renderer := NewHTMLStreamRendererToBuilder(&html, func(x string) {
		t.Errorf("Unexpected renderer error: %s", x)
	})
	counter := &hstP3CountingReceiver{
		HTMLStreamEventReceiverWrapper: HTMLStreamEventReceiverWrapper{Underlying: renderer},
	}
	// Output through the reporter decorator is under test.
	policy := hstFormTablePolicy(t).ApplyWithListener(counter, hstIgnoringListener{}, nil)

	Sanitize(
		"<form id=a><table></form><form id=b>"+
			"<tr><td>y</td></tr></table>",
		policy, nil)

	hstAssertEqual(t,
		"<form id=\"a\"><table><form></form><form id=\"b\"></form>"+
			"<tbody><tr><td>y</td></tr></tbody></table></form>",
		html.String())
	hstAssertEqual(t, counter.opened, counter.closed)
}

// TestForeignSelectRenamedFromTableHasStableEmptyContents checks that an
// HTML table renamed to a foreign select cannot safely preserve its
// table-shaped contents.  Keep the renamed element, but fail closed for the
// subtree so a second browser parse cannot rearrange it.
func TestForeignSelectRenamedFromTableHasStableEmptyContents(t *testing.T) {
	p := hstTableMutationPolicy(t, "table", "select", "table", "select")
	for _, c := range []hstP3Case{
		{
			"<svg><table><td><option><tr></option> ",
			"<svg><select></select></svg>",
		},
		{
			"<svg><table><td><select><div></div><tr><i><tr>",
			"<svg><select></select></svg>",
		},
		{
			"<svg><table><td><tbody><b><caption><th></caption><option>",
			"<svg><select></select></svg>",
		},
		{
			"<svg><table><td><style>a{b:c}</style><script>alert(1)</script>" +
				"<textarea>&lt;b&gt;</textarea><noscript><b>x</b></noscript>" +
				"<textArea>y</textArea></table></svg>",
			"<svg><select></select></svg>",
		},
		{
			"<svg><table><tr><td>a</td></tr></table><g>kept</g>" +
				"<table><caption>b</caption></table></svg>",
			"<svg><select></select><g>kept</g><select></select></svg>",
		},
	} {
		hstAssertRoundTripAndBalanced(t, p, c.input, c.want)
	}
}

// TestImpliedTableRenamedToLiteralDoesNotCaptureDeferredTablePart checks that
// a literal replacement closes before a part of its implied table returns.
func TestImpliedTableRenamedToLiteralDoesNotCaptureDeferredTablePart(t *testing.T) {
	input := "<tfoot><form><svg><th><table><caption>"
	for _, literal := range []string{"style", "script", "iframe"} {
		p := hstTableMutationPolicy(t, "table", literal, "table", literal)
		hstAssertRoundTripAndBalanced(t,
			p, input, "<"+literal+"></"+literal+">")
	}
}

// TestExplicitTableRenamedToLiteralStillPreparesFollowingTablePart checks
// that an explicit literal table owner must not hide a later orphan option.
func TestExplicitTableRenamedToLiteralStillPreparesFollowingTablePart(t *testing.T) {
	p := hstTableMutationPolicy(t, "table", "style", "table", "style")
	hstAssertRoundTripAndBalanced(t,
		p,
		"<table><colgroup><option>",
		"<style></style><select><option></option></select>")
}

// TestForeignSelectRenamedFromTableInsideRetainedTemplateIsStable checks that
// retained template contents have their own foreign-content context.
func TestForeignSelectRenamedFromTableInsideRetainedTemplateIsStable(t *testing.T) {
	p := hstTableMutationPolicy(t, "table", "select", "table", "select")
	for _, c := range []hstP3Case{
		{
			"<template><svg><table><style>x{}</style>" +
				"<script>alert(1)</script><textarea>&lt;b&gt;</textarea>" +
				"<noscript><b>x</b></noscript><b>after</b></table></svg>" +
				"</template><i>tail</i>",
			"<template><svg><select></select></svg></template><i>tail</i>",
		},
		{
			"<template><math><mtext><svg><table><style>x{}</style></table>" +
				"</svg></mtext></math></template><i>tail</i>",
			"<template><math><mtext><svg><select></select></svg></mtext>" +
				"</math></template><i>tail</i>",
		},
		{
			"<template><svg><foreignObject><template><svg><table>" +
				"<noscript><b>x</b></noscript><b>first</b></table></svg>" +
				"</template><svg><table><b>second</b></table></svg>" +
				"</foreignObject></svg></template><i>tail</i>",
			"<template><svg><foreignObject><template><svg><select></select>" +
				"</svg></template><svg><select></select></svg></foreignObject>" +
				"</svg></template><i>tail</i>",
		},
		{
			"<template><svg><textArea><svg><table><textarea>x</textarea>" +
				"<b>after</b></table></svg></textArea></svg></template>" +
				"<i>tail</i>",
			"<template><svg><textArea><svg><select></select></svg></textArea>" +
				"</svg></template><i>tail</i>",
		},
	} {
		hstAssertRoundTripAndBalanced(t, p, c.input, c.want)
	}
}

// TestPolicyCloseReconcilesTheMatchingFormPointer checks that a policy close
// can clear the form pointer below a synthetic table.
func TestPolicyCloseReconcilesTheMatchingFormPointer(t *testing.T) {
	p := hstTableMutationPolicy(t, "svg", "div", "p", "table")
	hstAssertRoundTripAndBalanced(t,
		p,
		"<form><thead></form><form>;"+
			"<foreignObject></form><form></foreignObject><col>",
		"<form><table><thead><form></form><form></form></thead></table>;"+
			"<foreignObject><form></form></foreignObject>"+
			"<table><colgroup><col /></colgroup></table></form>")
}

// TestImpliedTableEscapingSelectStaysSuppressedThroughPolicyRename checks
// that a policy-produced template cannot leak an implied table from a
// select.
func TestImpliedTableEscapingSelectStaysSuppressedThroughPolicyRename(t *testing.T) {
	p := hstTableMutationPolicy(t, "table", "template", "template", "div")
	hstAssertRoundTripAndBalanced(t,
		p, "<select><strong><col>",
		"<select><strong></strong></select>")
}

// TestDroppedImpliedListItemDoesNotOutliveForeignSelect checks that a dropped
// implied item cannot hide a table pushed past a retired select.
func TestDroppedImpliedListItemDoesNotOutliveForeignSelect(t *testing.T) {
	p := hstTableMutationPolicy(t, "div", "svg", "svg", "")
	oldOutput :=
		"<select><mtext><table><tbody><tr></tr></tbody></table>" +
			"<math><select><bar>;<b></b></bar></select></math>" +
			"<table><tbody><tr></tr></tbody></table></mtext></select>"
	stableOutput :=
		"<select><mtext><table><tbody><tr></tr></tbody></table>" +
			"<math></math></mtext></select><bar>;<b></b></bar>" +
			"<table><tbody><tr></tr></tbody></table>"
	hstAssertRoundTripAndBalanced(t,
		p,
		"<select><mtext><tr><math><select><bar>;<b><tr>",
		stableOutput)
	hstAssertEqual(t,
		hstParseAsBrowserWithNamespaces(t, oldOutput),
		hstParseAsBrowserWithNamespaces(t, stableOutput))
}

// TestOrphanTableSectionIsClosedInsteadOfPushedOut checks that a table
// section cannot be pushed out after losing its owning table.
func TestOrphanTableSectionIsClosedInsteadOfPushedOut(t *testing.T) {
	p := hstTableMutationPolicy(t, "template", "div", "foo", "foo")
	hstAssertRoundTripAndBalanced(t,
		p,
		"<tr><math><template><foreignObject><em><thead>"+
			"</foreignObject>><tr>",
		"<table><tbody><tr></tr></tbody></table><math></math><div>&gt;"+
			"<table><tbody><tr></tr></tbody></table></div>")
}

// TestImpliedWrapperUnderMappedSelectDoesNotRecurse checks that an implied
// wrapper under a policy-produced select must not recurse.
func TestImpliedWrapperUnderMappedSelectDoesNotRecurse(t *testing.T) {
	// Input select is allowed so the policy accepts its own emitted names.
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElementsWithPolicy(hstRenamingPolicy("select"), "table").
		AllowElements("select", "form", "noscript"))
	hstAssertRoundTripAndBalanced(t,
		p, "<table><form><noscript></form><form><col>",
		"<select><form><noscript></noscript></form><form></form></select>")

	// The same shape recursed with the table mapped to a list.  A list can
	// hold a form only through an item on the next pass, so that pass is
	// checked for balance rather than for exact idempotence.
	for _, list := range []string{"ul", "ol"} {
		q := hstFactory(t, NewHTMLPolicyBuilder().
			AllowElementsWithPolicy(hstRenamingPolicy(list), "table").
			AllowElements(list, "li", "form", "noscript"))
		input := "<table><form><noscript></form><form><col>"
		out := q.Sanitize(input)
		hstAssertEqual(t,
			"<"+list+"><form><noscript></noscript></form><form></form>"+
				"<li></li></"+list+">",
			out, list)
		hstAssertBalancedPolicyEvents(t, q, input)
		hstAssertBalancedPolicyEvents(t, q, out)
		hstAssertBalancedPolicyEvents(t, q, q.Sanitize(out))
	}
}

// TestForeignEndTagDoesNotReachOlderHTMLAncestor checks that a foreign end
// tag must not close an older HTML element of its name.
func TestForeignEndTagDoesNotReachOlderHTMLAncestor(t *testing.T) {
	names := []string{"noscript", "td", "svg", "tr", "table", "tbody"}
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(names...).AllowWithoutAttributes(names...).
		AllowTextIn("noscript"))
	// A browser drops the raw td and tr, which are outside any table, so the
	// output is compared with its own reparse only.
	hstAssertRoundTripAndBalanced(t,
		p, "<noscript><td><svg><noscript></svg><tr>",
		"<noscript><table><tbody><tr><td><svg><noscript></noscript></svg>"+
			"</td></tr><tr></tr></tbody></table></noscript>")

	// Content after the foreign close belongs to the outer noscript, and its
	// end tag still finds that element.
	input := "<noscript><svg><noscript></svg>x</noscript>y"
	expected := "<noscript><svg><noscript></noscript></svg>x</noscript>y"
	hstAssertRoundTripAndBalanced(t, p, input, expected)
	hstAssertEqual(t, hstParseAsBrowser(t, input), hstParseAsBrowser(t, expected))
}

// TestPolicyClosedSyntheticWrapperDoesNotAliasOlderWrapper checks that a
// wrapper the policy already closed cannot alias an older wrapper.
func TestPolicyClosedSyntheticWrapperDoesNotAliasOlderWrapper(t *testing.T) {
	names := []string{"select", "textArea", "foreignObject", "form", "table"}
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(names...).AllowWithoutAttributes(names...))
	// A browser reads the mixed-case name outside SVG as an HTML textarea and
	// its contents as text, so the output is compared with its own reparse.
	hstAssertRoundTripAndBalanced(t,
		p, "<select><textArea><select><foreignObject><form></textArea><table>",
		"<select></select><textArea><select><foreignObject><form></form>"+
			"</foreignObject></select></textArea><table></table>")
}

// TestForeignEndTagClosesPoppedElementsByIdentity checks that a foreign end
// tag pops nodes by identity.  A node the nesting limit dropped or the policy
// already closed matches nothing, so it cannot reach an older element with
// the same local name.
func TestForeignEndTagClosesPoppedElementsByIdentity(t *testing.T) {
	names := []string{
		"svg", "g", "path", "noscript", "select", "foreignObject", "td",
		"textArea",
	}
	keep := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(names...).AllowWithoutAttributes(names...).
		AllowTextIn("noscript"))
	for _, c := range []hstP3Case{
		{
			"<svg><noscript><noscript>x</noscript>y</noscript>z</svg>w",
			"<svg><noscript><noscript>x</noscript>y</noscript>z</svg>w",
		},
		{
			"<svg><noscript><g><noscript></g></noscript><path></path></svg>",
			"<svg><noscript><g><noscript></noscript></g></noscript>" +
				"<path></path></svg>",
		},
		// Table parts forwarded directly into foreign output have no entry
		// on the balancer's stack, so their end tags are forwarded for them.
		{
			"<svg><td><noscript></td>x</svg>",
			"<svg><td><noscript></noscript></td>x</svg>",
		},
		{
			"<svg><textArea><noscript></textArea>x</svg>",
			"<svg><textArea><noscript></noscript></textArea>x</svg>",
		},
	} {
		hstAssertRoundTripAndBalanced(t, keep, c.input, c.want)
		hstAssertEqual(t, hstParseAsBrowser(t, c.input), hstParseAsBrowser(t, c.want), c.input)
	}

	// The policy closes the inner mapped select at </g>.  That entry must not
	// be mistaken for the outer one, which </noscript> then closes, so the
	// path follows the outer select instead of nesting inside it.
	renamed := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("svg", "select", "foreignObject", "path").
		AllowElementsWithPolicy(hstRenamingPolicy("select"), "noscript").
		AllowElementsWithPolicy(hstRenamingPolicy("foreignObject"), "g").
		AllowWithoutAttributes(
			"svg", "select", "foreignObject", "path", "noscript", "g"))
	hstAssertRoundTripAndBalanced(t,
		renamed,
		"<svg><noscript><g><noscript></g></noscript><path></path></svg>",
		"<svg><select><foreignObject><select></select></foreignObject>"+
			"</select><path></path></svg>")
}

// TestUnrecognizedEndTagMirrorsPolicyStack checks that an unrecognized end
// tag closes the policy's stack down to its target.  The balancer mirrors
// exactly the entries closed there, so no stale entry can later close an
// older element with the same name, and formatting closed that way resumes as
// a browser reconstructs it.
func TestUnrecognizedEndTagMirrorsPolicyStack(t *testing.T) {
	names := []string{"foo", "b", "i", "template"}
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(names...).AllowWithoutAttributes(names...))
	for _, c := range []hstP3Case{
		{"<foo><b>x</foo>y", "<foo><b>x</b></foo><b>y</b>"},
		{"<b><foo><b>x</foo>y</b>z", "<b><foo><b>x</b></foo><b>y</b>z</b>"},
		{
			"<foo><i><b>x</foo>y",
			"<foo><i><b>x</b></i></foo><i><b>y</b></i>",
		},
	} {
		hstAssertRoundTripAndBalanced(t, p, c.input, c.want)
		hstAssertEqual(t, hstParseAsBrowser(t, c.input), hstParseAsBrowser(t, c.want), c.input)
	}
	// Formatting inside template contents does not resume outside them.  A
	// browser ignores this end tag at the template boundary, so the output
	// is compared with its own reparse only.
	hstAssertRoundTripAndBalanced(t,
		p, "<foo><template><b>x</foo>y",
		"<foo><template><b>x</b></template></foo>y")
}

// TestRunOfUnrecognizedTagsIsLinear checks that a long run of unrecognized
// tags the policy drops must not make each later end tag rescan every one of
// them.  They are indexed by name, so finding the element an end tag closes
// takes constant time however many are open, and the run is linear in the
// input.  The old scan took 5 seconds for 32,000 repeats and quadrupled per
// doubling; both runs below are well over a minute on it.
//
// Each case keeps a control suffix, so a regression that emitted nothing at
// all, or that let the run exhaust the nesting limit, fails here instead of
// passing with an empty result.
func TestRunOfUnrecognizedTagsIsLinear(t *testing.T) {
	p := Blocks.And(Formatting).
		And(Links).And(Tables)
	const tail = "<p>kept <b>text</b></p>"
	for _, unit := range []string{"<foo></div>", "<x-y></b>"} {
		html := strings.Repeat(unit, 100_000) + tail
		hstAssertEqual(t,
			tail,
			hstCompletesWithin(t, 20*time.Second, func() string { return p.Sanitize(html) }),
			unit)
	}
}

// TestDroppedUnknownTagsDoNotConsumeTheNestingLimit checks that nothing is
// emitted for an unknown tag the policy drops, so it nests nothing and must
// not consume the output nesting budget.  Counting them made a run of such
// tags strip the rest of the document: pasted word processor markup opens a
// run of o:p elements, and 256 of them silently deleted everything that
// followed.
func TestDroppedUnknownTagsDoNotConsumeTheNestingLimit(t *testing.T) {
	p := Blocks.And(Formatting).
		And(Links).And(Tables)
	tail := "<p>Hello <b>world</b></p>"
	for _, n := range []int{255, 256, 300, 1000} {
		hstAssertEqual(t,
			tail, p.Sanitize(strings.Repeat("<o:p>", n)+tail),
			fmt.Sprintf("%d dropped unknown tags", n))
	}
	hstAssertEqual(t,
		"<p>para</p><a href=\"http://x/\" rel=\"nofollow\">link</a>"+
			"<table><tbody><tr><td>c</td></tr></tbody></table>",
		p.Sanitize(
			strings.Repeat("<my-widget>", 256)+
				"<p>para</p><a href=\"http://x/\">link</a>"+
				"<table><tr><td>c"))
	// The elements the policy keeps are still bounded by the limit.
	deep := p.Sanitize(strings.Repeat("<div>", 300) + "x")
	hstAssertEqual(t, 256, strings.Count(deep, "<div>"), "kept elements are still bounded")
}

// TestForeignRootIsNotWrappedOutsideTableModes checks that an SVG or MathML
// root that HTML rules insert is put where it arrives, except in a table
// insertion mode, where a browser foster-parents it.  The containment
// metadata has no entry for it, and consulting it anyway implied a list item
// around a root in a list, and around one in a select a list item that the
// next pass wrapped in a list again, without end.
func TestForeignRootIsNotWrappedOutsideTableModes(t *testing.T) {
	names := []string{
		"ul", "li", "select", "option", "svg", "math", "mi", "table", "tbody",
		"tr", "td", "colgroup", "col", "b",
	}
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(names...).AllowWithoutAttributes(names...))
	for _, c := range []hstP3Case{
		{"<ul><svg></svg></ul>", "<ul><svg></svg></ul>"},
		{"<ul><math></math></ul>", "<ul><math></math></ul>"},
		{
			"<ul><li><math><mi>x</mi></math></li></ul>",
			"<ul><li><math><mi>x</mi></math></li></ul>",
		},
		{"<b>x<svg>y</svg></b>", "<b>x<svg>y</svg></b>"},
	} {
		hstAssertRoundTripAndBalanced(t, p, c.input, c.want)
		hstAssertEqual(t, hstParseAsBrowser(t, c.input), hstParseAsBrowser(t, c.want), c.input)
	}
	// In a table mode the root is foster-parented in front of the table,
	// popping an open column group first.  Content pushed out of a table is
	// serialized after the table it was pushed out of, as for text since
	// #481, so these compare the output with its own reparse only.
	for _, c := range []hstP3Case{
		{
			"<table><svg>x</svg><tr><td>y",
			"<table></table><svg>x</svg>" +
				"<table><tbody><tr><td>y</td></tr></tbody></table>",
		},
		{
			"<table><colgroup><svg>x</svg><tr><td>y",
			"<table><colgroup></colgroup></table><svg>x</svg>" +
				"<table><tbody><tr><td>y</td></tr></tbody></table>",
		},
		{
			"<table><tr><svg>x</svg><td>y",
			"<table><tbody><tr></tr></tbody></table><svg>x</svg>" +
				"<table><tbody><tr><td>y</td></tr></tbody></table>",
		},
	} {
		hstAssertRoundTripAndBalanced(t, p, c.input, c.want)
	}
	// A browser drops an svg inside a select, so these too are compared with
	// their own reparse only; the point is that they no longer grow.
	hstAssertRoundTripAndBalanced(t,
		p, "<select><svg>", "<select><svg></svg></select>")
	hstAssertRoundTripAndBalanced(t,
		p, "<select><math>", "<select><math></math></select>")
}

// TestForeignEndTagAfterBreakoutReachesOuterRoot checks that after an HTML
// breakout pops a nested foreign root, its end tag reaches the outer foreign
// root, as in a browser, rather than the nearest element that happens to
// share its name.
func TestForeignEndTagAfterBreakoutReachesOuterRoot(t *testing.T) {
	names := []string{"svg", "foreignObject", "i", "b"}
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(names...).AllowWithoutAttributes(names...))
	input :=
		"<svg><foreignObject><svg><i></i></svg><b>x</b></foreignObject></svg>y"
	expected :=
		"<svg><foreignObject><svg><i></i></svg></foreignObject></svg><b>x</b>y"
	hstAssertRoundTripAndBalanced(t, p, input, expected)
	hstAssertEqual(t, hstParseAsBrowser(t, input), hstParseAsBrowser(t, expected))
}

// TestFormattingIsNotResumedInForeignContent checks that formatting closed by
// the end tag of an integration point stays queued while content is inserted
// under SVG or MathML rules, where a browser neither reconstructs it nor
// keeps a formatting start tag inside the foreign root, and resumes where
// HTML content is inserted again.
func TestFormattingIsNotResumedInForeignContent(t *testing.T) {
	names := []string{
		"svg", "desc", "foreignObject", "g", "math", "mtext", "mrow", "b",
		"i", "p",
	}
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(names...).AllowWithoutAttributes(names...))
	// validator.nu closes desc and mtext on their end tags, which is the
	// tree these expectations follow; a browser treating them as special
	// ignores the end tag instead, and neither ever resumes the formatting
	// inside the foreign root.
	for _, c := range []hstP3Case{
		{
			"<svg><desc><b>x</desc><g>z</g></svg>w",
			"<svg><desc><b>x</b></desc><g>z</g></svg><b>w</b>",
		},
		{
			"<math><mtext><i>x</mtext><mrow>z</mrow></math>w",
			"<math><mtext><i>x</i></mtext><mrow>z</mrow></math><i>w</i>",
		},
		{
			"<svg><desc><b>x</desc><foreignObject>y</foreignObject></svg>",
			"<svg><desc><b>x</b></desc><foreignObject><b>y</b></foreignObject>" +
				"</svg>",
		},
		// A tag that breaks out of foreign content is inserted after the
		// browser pops the foreign nodes, so the formatting resumes for the
		// text inside it rather than in front of it.
		{
			"<svg><desc><b>x</desc><p>z</p></svg>",
			"<svg><desc><b>x</b></desc><p><b>z</b></p></svg>",
		},
	} {
		hstAssertRoundTripAndBalanced(t, p, c.input, c.want)
		hstAssertEqual(t, hstParseAsBrowser(t, c.input), hstParseAsBrowser(t, c.want), c.input)
	}
}

// TestTablePartsInsideCellContentReturnToTheOpenTable covers issue #483:
// table parts clear back to the table before implying tags.
func TestTablePartsInsideCellContentReturnToTheOpenTable(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "caption", "colgroup", "col", "thead", "tbody",
			"tfoot", "tr", "td", "th", "div", "b"))
	prefix := "<table><tr><td><div><b>x"
	closedCell := "<table><tbody><tr><td><div><b>x</b></div></td>"
	cases := [][2]string{
		{"<tr><td>y</td></tr></table>",
			closedCell + "</tr><tr><td>y</td></tr></tbody></table>"},
		{"<td>y</td></tr></table>",
			closedCell + "<td>y</td></tr></tbody></table>"},
		{"<th>y</th></tr></table>",
			closedCell + "<th>y</th></tr></tbody></table>"},
		{"<caption>y</caption></table>",
			closedCell + "</tr></tbody><caption>y</caption></table>"},
		{"<col></table>",
			closedCell + "</tr></tbody><colgroup><col /></colgroup></table>"},
		{"<colgroup><col></colgroup></table>",
			closedCell + "</tr></tbody><colgroup><col /></colgroup></table>"},
		{"<thead><tr><td>y</td></tr></thead></table>",
			closedCell + "</tr></tbody><thead><tr><td>y</td></tr></thead></table>"},
		{"<tbody><tr><td>y</td></tr></tbody></table>",
			closedCell + "</tr></tbody><tbody><tr><td>y</td></tr></tbody></table>"},
		{"<tfoot><tr><td>y</td></tr></tfoot></table>",
			closedCell + "</tr></tbody><tfoot><tr><td>y</td></tr></tfoot></table>"},
	}
	for _, c := range cases {
		input := prefix + c[0]
		out := p.Sanitize(input)
		hstAssertEqual(t, c[1], out, input)
		hstAssertEqual(t, out, p.Sanitize(out), input)
		hstAssertEqual(t, hstParseAsBrowser(t, input), hstParseAsBrowser(t, out), input)
	}
}

func TestRowAfterColumnUsesTheExistingTable(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "colgroup", "col", "tbody", "tr", "td"))
	input := "<table><col><tr><td>y</td></tr></table>"
	out := p.Sanitize(input)
	hstAssertEqual(t,
		"<table><colgroup><col /></colgroup>"+
			"<tbody><tr><td>y</td></tr></tbody></table>", out)
	hstAssertEqual(t, out, p.Sanitize(out))
	hstAssertEqual(t, hstParseAsBrowser(t, input), hstParseAsBrowser(t, out))
}

// TestTablePartReturnsToTheNearestNestedTable checks that an explicit table
// in a cell stays nested, and owns its later rows.
func TestTablePartReturnsToTheNearestNestedTable(t *testing.T) {
	p := hstTablePolicy(t)
	input := "<table><tr><td><table><tr><td><div>x" +
		"<tr><td>y</td></tr></table>z</td></tr></table>"
	out := p.Sanitize(input)
	hstAssertEqual(t,
		"<table><tbody><tr><td><table><tbody><tr><td><div>x</div></td></tr>"+
			"<tr><td>y</td></tr></tbody></table>z</td></tr></tbody></table>", out)
	hstAssertEqual(t, out, p.Sanitize(out))
	hstAssertEqual(t, hstParseAsBrowser(t, input), hstParseAsBrowser(t, out))
}

// TestImpliedTableClosesParagraphBeforeItsPartsOpen checks that the existing
// orphan-part wrapper obeys the containment of p.
func TestImpliedTableClosesParagraphBeforeItsPartsOpen(t *testing.T) {
	p := hstTablePolicy(t)
	out := p.Sanitize("<div><p>x<tr><td>y</td></tr>")
	expected := "<div><p>x</p><table><tbody><tr><td>y</td></tr>" +
		"</tbody></table></div>"
	hstAssertEqual(t, expected, out)
	hstAssertEqual(t, out, p.Sanitize(out))
	hstAssertEqual(t, hstParseAsBrowser(t, expected), hstParseAsBrowser(t, out))

	// The balancer still supplies the wrapper needed when an orphan part is
	// embedded in an unknown context; the explicit table is the equivalent
	// browser input, since a body parser drops the bare tr and td tags.
	hstAssertEqual(t, out, p.Sanitize("<div><p>x<table><tr><td>y</td></tr>"))
}

// TestMisnestedTablePartsStillApplyElementAndAttributePolicies checks that
// balancing never exempts table parts or their implied tags from policy.
func TestMisnestedTablePartsStillApplyElementAndAttributePolicies(t *testing.T) {
	p := hstTablePolicy(t)
	out := p.Sanitize(
		"<table onclick=blocked><tr><td><div data-denied=blocked>x" +
			"<tr onclick=blocked><td>y<script>blocked</script></table>")
	hstAssertEqual(t,
		"<table><tbody><tr><td><div>x</div></td></tr>"+
			"<tr><td>y</td></tr></tbody></table>", out)
	hstAssertEqual(t, out, p.Sanitize(out))

	textOnly := hstFactory(t, NewHTMLPolicyBuilder().AllowElements("p"))
	text := textOnly.Sanitize("<p>x<tr onclick=blocked><td>y</td></tr>")
	hstAssertEqual(t, "<p>x</p>y", text)
	hstAssertEqual(t, text, textOnly.Sanitize(text))
}

// TestTableContextReturnStopsAtDroppedTable checks that a logical table
// omitted by policy does not establish output context.
func TestTableContextReturnStopsAtDroppedTable(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("tbody", "tr", "td", "div"))
	input := "<table><tr><td><table><tr><td><div>x" +
		"<tr><td>y</table>z</table>"
	out := p.Sanitize(input)

	hstAssertEqual(t,
		"<tbody><tr><td><tbody><tr><td><div>x"+
			"<tbody><tr><td>y</td></tr></tbody>z</div></td></tr></tbody>"+
			"</td></tr></tbody>",
		out)
	hstAssertEqual(t, out, p.Sanitize(out))
}

// TestTemplateEndsThroughItsTableStructure checks that a template bounds
// table scope and its end tag closes all its content.
func TestTemplateEndsThroughItsTableStructure(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("template", "table", "tbody", "tr", "td", "div", "b"))
	cases := [][2]string{
		{"<template><tr><td>y</td></tr></template>z",
			"<template><table><tbody><tr><td>y</td></tr></tbody></table>" +
				"</template>z"},
		{"<template><table><tr><td><b>y</template>z",
			"<template><table><tbody><tr><td><b>y</b></td></tr></tbody>" +
				"</table></template>z"},
		{"<template><div><b>x</div></template>y",
			"<template><div><b>x</b></div></template>y"},
		{"<template><template><tr><td>x</template>y</template>z",
			"<template><template><table><tbody><tr><td>x</td></tr></tbody>" +
				"</table></template>y</template>z"},
		{"<table><tr><td><template><tr><td>x</template>y<tr><td>z</table>w",
			"<table><tbody><tr><td><template><table><tbody><tr><td>x</td></tr>" +
				"</tbody></table></template>y</td></tr><tr><td>z</td></tr>" +
				"</tbody></table>w"},
		{"<table><div><template><tr><td>x</template>y<tr><td>z</table>w",
			"<table></table><div><template><table><tbody><tr><td>x</td></tr>" +
				"</tbody></table></template>y</div><table><tbody><tr><td>z</td>" +
				"</tr></tbody></table>w"},
		{"<table><tr><td>x</template>y</td></tr></table>z",
			"<table><tbody><tr><td>xy</td></tr></tbody></table>z"},
		{"<template><noscript>x</template>y</noscript>z",
			"<template>z</template>"},
		{"<template><noembed>x</template>y</noembed>z",
			"<template>z</template>"},
		{"<template><noframes>x</template>y</noframes>z",
			"<template>z</template>"},
	}
	for _, c := range cases {
		out := p.Sanitize(c[0])
		hstAssertEqual(t, c[1], out, c[0])
		hstAssertEqual(t, out, p.Sanitize(out), c[0])
	}
}

// TestTablePartsInForeignCellContentKeepTheirContext checks that foreign
// table names remain foreign; integration points use HTML rules.
func TestTablePartsInForeignCellContentKeepTheirContext(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tbody", "tr", "td", "svg", "math",
			"foreignObject", "mtext"))
	for _, names := range [][2]string{
		{"svg", "foreignObject"}, {"math", "mtext"},
	} {
		foreign := "<" + names[0] + "><tr><td>x</td></tr></" + names[0] + ">"
		input := "<table><tr><td>" + foreign + "<tr><td>y</table>"
		out := p.Sanitize(input)
		hstAssertEqual(t, "<table><tbody><tr><td>"+foreign+
			"</td></tr><tr><td>y</td></tr></tbody></table>", out)
		hstAssertEqual(t, out, p.Sanitize(out))
		hstAssertEqual(t, hstParseAsBrowser(t, input), hstParseAsBrowser(t, out))

		input = "<table><tr><td><" + names[0] + "><" + names[1] +
			"><tr><td>x</table>"
		out = p.Sanitize(input)
		hstAssertEqual(t, "<table><tbody><tr><td><"+names[0]+"><"+names[1]+
			"></"+names[1]+"></"+names[0]+
			"></td></tr><tr><td>x</td></tr></tbody></table>", out)
		hstAssertEqual(t, out, p.Sanitize(out))
		hstAssertEqual(t, hstParseAsBrowser(t, input), hstParseAsBrowser(t, out))
	}
}

func TestIssue189StrayQuoteInTag(t *testing.T) {
	// A quote that does not directly follow an attribute name and '=' is part
	// of an attribute name in the WHATWG tokenizer, so it must not pair with
	// a later quote and swallow the rest of the document.
	hstAssertEqual(t,
		`<p>foo</p> <p class="p-test">bar</p> <p>baz</p>`,
		hstSanitize(t, `<p>foo</p> <p class="test" "="">bar</p> <p>baz</p>`))
	hstAssertEqual(t,
		`<p class="p-test">bar</p> <p>baz</p>`,
		hstSanitize(t, `<p class="test" ">bar</p> <p>baz</p>`))
	hstAssertEqual(t, "<p>b&#34;&gt;c</p>", hstSanitize(t, `<p "a>b">c</p>`))
	hstAssertEqual(t, `<p class="p-x">y</p>`, hstSanitize(t, `<p class="x"=">y</p>`))
	hstAssertEqual(t, "<p>y</p>", hstSanitize(t, `<p ="x">y</p>`))
	hstAssertEqual(t, "<p>y</p>", hstSanitize(t, `<p / "x">y</p>`))
	hstAssertEqual(t, `<p class="p-x">y</p>`, hstSanitize(t, `<p class="x"/=">y</p>`))
	hstAssertEqual(t, "<p>y</p>", hstSanitize(t, `<p title/=">y</p>`))
	// Here the second quote does follow '=', so it begins a value that never
	// closes; browsers hit EOF inside the tag and drop everything from it on,
	// and so does the sanitizer (#410).
	hstAssertEqual(t,
		"<p>foo</p> ",
		hstSanitize(t, `<p>foo</p> <p class="test" "=">bar</p> <p>baz</p>`))
}

// TestSelfClosingTagsInForeignContent covers issue #122.  Browsers honor the
// self-closing flag on <svg/> and <math/>, and on most start tags inside
// them, where <path/> is a complete, empty element.  The sanitizer discarded
// the flag, so each self-closing path nested inside the one before it and the
// end of the SVG closed them all at once.
func TestSelfClosingTagsInForeignContent(t *testing.T) {
	p := hstForeignContentPolicy(t)
	// The markup from the issue.
	hstAssertEqual(t,
		"<svg width=\"24\" height=\"24\" viewBox=\"0 0 24 24\">\n"+
			"    <path id=\"bounds\" opacity=\"0\" d=\"M0 0h24v24H0z\"></path>\n"+
			"    <path d=\"M2 2\"></path>\n"+
			"    <path d=\"M3 3\"></path>\n"+
			"</svg>",
		p.Sanitize(
			"<svg width=\"24\" height=\"24\" viewBox=\"0 0 24 24\">\n"+
				"    <path id=\"bounds\" opacity=\"0\" d=\"M0 0h24v24H0z\"/>\n"+
				"    <path d=\"M2 2\"/>\n"+
				"    <path d=\"M3 3\"/>\n"+
				"</svg>"))
	// What follows a self-closing tag is a sibling, not content.
	hstAssertEqual(t,
		`<svg><path d="M0 0"></path>text<path d="M1 1"></path></svg>`,
		p.Sanitize(`<svg><path d="M0 0"/>text<path d="M1 1"/></svg>`))
	hstAssertEqual(t,
		`<svg><g><path d="M0 0"></path><rect></rect></g>`+
			`<path d="M1 1"></path></svg>`,
		p.Sanitize(
			`<svg><g><path d="M0 0"/><rect/></g><path d="M1 1"/></svg>`))
	// Names that keep their case are foreign content too, and SVG's
	// textArea is not HTML's textarea.
	hstAssertEqual(t,
		"<svg><clipPath></clipPath><g></g>x</svg>",
		p.Sanitize("<svg><clipPath/><g/>x</svg>"))
	hstAssertEqual(t,
		"<svg><textArea></textArea>x</svg>",
		p.Sanitize("<svg><textArea/>x</svg>"))
	hstAssertEqual(t,
		"<math><mi></mi>x<mrow></mrow>y</math>",
		p.Sanitize("<math><mi/>x<mrow/>y</math>"))
	// The flag is honored on <svg/> and <math/> themselves, anywhere.
	hstAssertEqual(t, "<svg></svg>x", p.Sanitize("<svg/>x"))
	hstAssertEqual(t, "<svg></svg>x", p.Sanitize("<SVG/>x"))
	hstAssertEqual(t, "<math></math>x", p.Sanitize("<math/>x"))
	hstAssertEqual(t,
		`<svg><svg></svg><path d="M0 0"></path></svg>`,
		p.Sanitize(`<svg><svg/><path d="M0 0"/></svg>`))
	// Only a solidus right before the '>' sets the flag.
	hstAssertEqual(t,
		`<svg><path d="M0"></path>x</svg>`,
		p.Sanitize("<svg><path d=M0 />x</svg>"))
	hstAssertEqual(t,
		`<svg><path d="M0/&gt;"></path>x</svg>`,
		p.Sanitize(`<svg><path d="M0/>"/>x</svg>`))
	// In an unquoted value the solidus is part of the value.
	hstAssertEqual(t,
		`<svg><path d="M0/">x</path></svg>`,
		p.Sanitize("<svg><path d=M0/>x</svg>"))
	hstAssertEqual(t,
		`<svg><path d="/">x</path></svg>`,
		p.Sanitize("<svg><path d=/>x</svg>"))
	hstAssertEqual(t,
		"<svg><path>x</path></svg>", p.Sanitize("<svg><path / >x</svg>"))
}

// TestSelfClosingTagsOutsideForeignContent covers issue #122.  In HTML
// content the self-closing flag means nothing on a non-void element, so
// outside <svg> and <math> nothing changes: <path/> still opens an element
// that only an end tag closes.
func TestSelfClosingTagsOutsideForeignContent(t *testing.T) {
	p := hstForeignContentPolicy(t)
	hstAssertEqual(t,
		`<path d="M0 0">x</path>`, p.Sanitize(`<path d="M0 0"/>x`))
	hstAssertEqual(t, "<p>x</p>", p.Sanitize("<p/>x"))
	// Foreign content ends with the element that started it.
	hstAssertEqual(t,
		`<svg></svg><path d="M0 0">x</path>`,
		p.Sanitize(`<svg></svg><path d="M0 0"/>x`))
	hstAssertEqual(t,
		`<svg><path></path></svg><path d="M0 0">x</path>`,
		p.Sanitize(`<svg><path/></svg><path d="M0 0"/>x`))
}

// TestSelfClosingTagsThatBreakOutOfForeignContent covers issue #122.
// Browsers process the start tags that break out of foreign content as HTML,
// where the flag is ignored again; a void element is empty with or without
// it.
func TestSelfClosingTagsThatBreakOutOfForeignContent(t *testing.T) {
	p := hstForeignContentPolicy(t)
	hstAssertEqual(t, "<svg><div>x</div></svg>", p.Sanitize("<svg><div/>x</svg>"))
	hstAssertEqual(t, "<svg><p>x</p></svg>", p.Sanitize("<svg><p/>x</svg>"))
	// <font> breaks out only with a color, face or size attribute.
	hstAssertEqual(t,
		`<svg><font color="red">x</font></svg>`,
		p.Sanitize(`<svg><font color="red"/>x</svg>`))
	hstAssertEqual(t,
		"<svg><font></font>x</svg>", p.Sanitize("<svg><font/>x</svg>"))
	hstAssertEqual(t, "<svg><br />x</svg>", p.Sanitize("<svg><br/>x</svg>"))
}

// TestSelfClosingTagsAtHTMLIntegrationPoints covers issue #457.  Start tags
// at integration points use the HTML rules.
func TestSelfClosingTagsAtHTMLIntegrationPoints(t *testing.T) {
	p := hstForeignContentPolicy(t)
	hstAssertEqual(t,
		"<svg><foreignObject><path>x</path></foreignObject></svg>",
		p.Sanitize("<svg><foreignObject><path/>x</foreignObject></svg>"))
	hstAssertEqual(t,
		"<svg><desc><path>x</path></desc></svg>",
		p.Sanitize("<svg><desc><path/>x</desc></svg>"))
	hstAssertEqual(t,
		"<math><mi><path>x</path></mi></math>",
		p.Sanitize("<math><mi><path/>x</mi></math>"))
	hstAssertEqual(t,
		`<math><annotation-xml encoding="text/html"><path>x</path>`+
			"</annotation-xml></math>",
		p.Sanitize(
			"<math><annotation-xml encoding=text/html><path/>x"+
				"</annotation-xml></math>"))
	hstAssertEqual(t,
		"<math><mi><mglyph></mglyph>x</mi></math>",
		p.Sanitize("<math><mi><mglyph/>x</mi></math>"))
	// A dropped object remains open under HTML rules, so its fallback text
	// stays suppressed.
	hstAssertEqual(t,
		"<svg><foreignObject></foreignObject></svg>",
		p.Sanitize(
			"<svg><foreignObject><object/>hidden</foreignObject></svg>"))
}

// TestForeignContentBreakoutUpdatesFollowingContext covers issue #457.  A
// breakout token ends the surrounding foreign context.
func TestForeignContentBreakoutUpdatesFollowingContext(t *testing.T) {
	p := hstForeignContentPolicy(t)
	hstAssertEqual(t,
		"<svg><p><path>x</path></p></svg>",
		p.Sanitize("<svg><p/><path/>x</svg>"))
	hstAssertEqual(t,
		"<svg><p>x</p></svg>",
		p.Sanitize("<svg><p/>x<object/>hidden</svg>"))
	hstAssertEqual(t,
		`<svg><font color="red"><path>x</path></font></svg>`,
		p.Sanitize("<svg><font color=red /><path/>x</svg>"))
	hstAssertEqual(t,
		"<svg><path>x</path></svg>",
		p.Sanitize("<svg></p><path/>x</svg>"))
}

// TestForeignContentEndTagsUpdateTheMatchingContext covers issue #457.
// Foreign end tags match against the open-element stack.
func TestForeignContentEndTagsUpdateTheMatchingContext(t *testing.T) {
	p := hstForeignContentPolicy(t)
	hstAssertEqual(t,
		"<math><mi></mi>x</math>",
		p.Sanitize("<math></svg><mi/>x</math>"))
	hstAssertEqual(t,
		"<svg><math></math></svg><path>x</path>",
		p.Sanitize("<svg><math></svg><path/>x"))
	hstAssertEqual(t,
		"<math><svg></svg></math><path>x</path>",
		p.Sanitize("<math><svg></math><path/>x"))
	hstAssertEqual(t,
		"<svg><math></math><path></path>x</svg>",
		p.Sanitize("<svg><math></math><path/>x</svg>"))
	hstAssertEqual(t,
		"<svg><math></math></svg>",
		p.Sanitize("<svg><math></svg><object/>hidden"))
	// The end tag of an HTML element that is open below a foreign element
	// closes both, and puts the parser back under the HTML rules.
	hstAssertEqual(t,
		"<math><mi><div><svg></svg></div><path>x</path></mi></math>",
		p.Sanitize(
			"<math><mi><div><svg></div><path/>x</svg></div></mi></math>"))
}

// TestEndTagsOfHTMLAncestorsEndForeignContent covers issue #457.  An end tag
// that names none of the open foreign elements may close an HTML ancestor of
// the foreign root, which is not tracked.  The context is then unknown and
// the sanitizer falls back to the HTML rules, unless the browser would
// ignore the tag.
func TestEndTagsOfHTMLAncestorsEndForeignContent(t *testing.T) {
	p := hstForeignContentPolicy(t)
	hstAssertEqual(t,
		"<div><svg></svg></div>",
		p.Sanitize("<div><svg></div><object/>hidden"))
	hstAssertEqual(t,
		"<div><svg><path></path></svg></div>",
		p.Sanitize("<div><svg><path></div><object/>hidden"))
	hstAssertEqual(t,
		"<p><svg></svg></p>",
		p.Sanitize("<p><svg></p><object/>hidden"))
	hstAssertEqual(t,
		"<div><svg><path></path></svg></div><path>x</path>",
		p.Sanitize("<div><svg><path></div><path/>x"))
	// An integration point is in the special category and stops the search
	// for the named element, so the tag is ignored and the content of the
	// integration point stays under the HTML rules.
	hstAssertEqual(t,
		"<div><svg><foreignObject></foreignObject></svg></div>",
		p.Sanitize("<div><svg><foreignObject></div><object/>hidden"))
	hstAssertEqual(t,
		"<div><math><mi></mi></math></div>",
		p.Sanitize("<div><math><mi></div><object/>hidden"))
	// The path is still empty and closes at once.  Where the tag balancer
	// then puts it is its own concern.
	hstAssertEqual(t,
		"<div><svg><foreignObject><div><svg></svg></div></foreignObject>"+
			"<path></path>x</svg></div>",
		p.Sanitize(
			"<div><svg><foreignObject><div><svg></foreignObject>"+
				"<path/>x"))
	// No HTML element is named svg or math, so a stray foreign end tag is
	// ignored rather than taken as closing an ancestor.
	hstAssertEqual(t,
		"<div><math><mi></mi>x</math></div>",
		p.Sanitize("<div><math></svg><mi/>x</math></div>"))
	// A stray end tag that names nothing open is ignored by browsers, and
	// the self-closing flag is still honored after it.  The sanitizer does
	// not know that nothing below the svg matched, so it errs toward the
	// HTML rules, where the flag is ignored and the path holds the text.
	hstAssertEqual(t,
		"<svg><path>x</path></svg>",
		p.Sanitize("<svg></foo><path/>x</svg>"))
}

// TestSelfClosingForeignLiteralContentNames covers issue #457.  HTML
// raw-text and RCDATA modes do not apply to self-closing foreign elements
// that happen to have the same names.
func TestSelfClosingForeignLiteralContentNames(t *testing.T) {
	p := hstForeignContentPolicy(t)
	hstAssertEqual(t,
		"<svg><title></title>x</svg><p>after</p>",
		p.Sanitize("<svg><title/>x</svg><p>after</p>"))
	hstAssertEqual(t,
		"<svg><style></style>x</svg><p>after</p>",
		p.Sanitize("<svg><style/>x</svg><p>after</p>"))
	hstAssertEqual(t,
		"<svg><textarea></textarea>x</svg>",
		p.Sanitize("<svg><textarea/>x</textarea></svg>"))
	hstAssertEqual(t,
		"<math><textarea></textarea>x</math><p>after</p>",
		p.Sanitize("<math><textarea/>x</math><p>after</p>"))
	// The dropped script closes before ordinary text, so that text survives.
	hstAssertEqual(t,
		"<svg>visible</svg><p>after</p>",
		p.Sanitize("<svg><script/>visible</svg><p>after</p>"))
	hstAssertEqual(t,
		"<svg>visible</svg><p>after</p>",
		p.Sanitize("<svg><plaintext/>visible</svg><p>after</p>"))
	// At an HTML integration point, the same name really is RCDATA and a
	// solidus does not close it.
	hstAssertEqual(t,
		"<svg><foreignObject><title>x</title></foreignObject></svg>",
		p.Sanitize(
			"<svg><foreignObject><title/>x</title></foreignObject></svg>"))
}

// TestSelfClosingTagsInForeignContentAreStillSanitized covers issue #122.  A
// self-closing tag is still subject to the policy, and what follows one is
// still text or markup that the policy sees, so the flag cannot smuggle
// anything past either.
func TestSelfClosingTagsInForeignContentAreStillSanitized(t *testing.T) {
	p := hstForeignContentPolicy(t)
	hstAssertEqual(t,
		"<svg><path></path>x</svg>",
		p.Sanitize(`<svg><path onload="alert(1)"/>x</svg>`))
	// The solidus does not end this tag, so what follows it is an attribute.
	hstAssertEqual(t,
		"<svg><path>x</path></svg>",
		p.Sanitize("<svg><path/onload=alert(1)>x</svg>"))
	hstAssertEqual(t,
		"<svg>x</svg>",
		p.Sanitize(`<svg><a href="javascript:alert(1)"/>x</svg>`))
	hstAssertEqual(t,
		`<svg><a href="http://example.com/"></a>x</svg>`,
		p.Sanitize(`<svg><a href="http://example.com/"/>x</svg>`))
	hstAssertEqual(t,
		"<svg><g></g></svg>",
		p.Sanitize("<svg><g/><img src=x onerror=alert(1)></svg>"))
	hstAssertEqual(t,
		"<svg><foreignObject></foreignObject><div>x</div></svg>",
		p.Sanitize("<svg><foreignObject/><div>x</div></svg>"))
	// A self-closing foreign RCDATA element closes before the next tag.
	hstAssertEqual(t,
		"<svg><title></title></svg>",
		p.Sanitize("<svg><title/><img src=x onerror=alert(1)></title></svg>"))
	hstAssertEqual(t,
		"<svg><style></style></svg>",
		p.Sanitize("<svg><style/><script>alert(1)</script></style></svg>"))
	// Text after a dropped element that closed itself is shown, as in a
	// browser, where that element is empty.
	hstAssertEqual(t, "<svg>x</svg>", p.Sanitize("<svg><noscript/>x</svg>"))
	// Self-closing elements are siblings, so they never reach the nesting
	// limit.
	out := p.Sanitize("<svg>" + strings.Repeat("<g/>", 300) + "x</svg>")
	hstAssertEqual(t, 300, strings.Count(out, "<g></g>"))
	hstAssertTrue(t, strings.HasSuffix(out, "x</svg>"))
}

// TestSelfClosingTagEvents covers issue #122: the events a policy sees for a
// self-closing tag.
func TestSelfClosingTagEvents(t *testing.T) {
	var events []string
	recorder := &hstReceiverFuncs{
		openDocument:  func() { events = append(events, "openDocument") },
		closeDocument: func() { events = append(events, "closeDocument") },
		openTag: func(elementName string, attrs []string) {
			events = append(events,
				"openTag "+elementName+" ["+strings.Join(attrs, ", ")+"]")
		},
		closeTag: func(elementName string) {
			events = append(events, "closeTag "+elementName)
		},
		text: func(text string) { events = append(events, "text "+text) },
	}
	Sanitize(
		`<svg><path d="M0 0"/>x</svg><path/>y`, recorder, nil)
	// The self-closing flag is honored in SVG, so the first path closes at
	// once.  HTML ignores it, so the second path stays open around the text
	// and is closed only with everything else at the end of the document.
	want := []string{
		"openDocument",
		"openTag svg []",
		"openTag path [d, M0 0]",
		"closeTag path",
		"text x",
		"closeTag svg",
		"openTag path []",
		"text y",
		"closeTag path",
		"closeDocument",
	}
	hstAssertEqual(t, strings.Join(want, "\n"), strings.Join(events, "\n"))
}

// TestTableScopeEndTagsEndForeignContent covers issue #461.  Browsers
// process the end tags of table structure with table scope, which no
// integration point bounds, so they can close the foreign content around a
// cell along with the cell.
func TestTableScopeEndTagsEndForeignContent(t *testing.T) {
	p := hstForeignContentPolicy(t)
	for _, endTag := range []string{"</table>", "</tbody>", "</tr>", "</td>"} {
		hstAssertEqual(t,
			"<svg><foreignObject><svg></svg></foreignObject></svg>",
			p.Sanitize(
				"<table><tbody><tr><td><svg><foreignObject><svg>"+endTag+
					"<object/>hidden"),
			endTag)
	}
	hstAssertEqual(t,
		"<svg><foreignObject><svg></svg></foreignObject></svg>",
		p.Sanitize(
			"<table><caption><svg><foreignObject><svg></caption>"+
				"<object/>hidden"))
	hstAssertEqual(t,
		"<svg><desc><svg></svg></desc></svg>",
		p.Sanitize("<table><tr><td><svg><desc><svg></table><object/>hidden"))
	hstAssertEqual(t,
		"<math><mi><svg></svg></mi></math>",
		p.Sanitize("<table><tr><td><math><mi><svg></table><object/>hidden"))
	hstAssertEqual(t,
		`<math><annotation-xml encoding="text/html"><svg></svg>`+
			"</annotation-xml></math>",
		p.Sanitize(
			"<table><tr><td><math><annotation-xml encoding=text/html><svg>"+
				"</table><object/>hidden"))
	// This table began below the tracked foreign root, so the context stays
	// unknown after the end tag.
	hstAssertEqual(t,
		"<svg><foreignObject><svg></svg></foreignObject></svg>"+
			"<svg><path>x</path></svg>",
		p.Sanitize(
			"<table><tr><td><svg><foreignObject><svg></table><svg><path/>x"))
	// Table structure inside an integration point follows the inherited
	// table insertion mode, including implied elements and cell closing.
	hstAssertEqual(t,
		"<svg><foreignObject><svg></svg></foreignObject></svg>",
		p.Sanitize(
			"<svg><foreignObject><table><tr><td><svg></tbody>"+
				"<object/>hidden"))
	hstAssertEqual(t,
		"<svg><foreignObject><svg>hidden</svg></foreignObject></svg>",
		p.Sanitize("<svg><foreignObject><select><svg><object/>hidden"))
	// An end tag searched in the default or list-item scope stops at the
	// integration point, so a browser ignores it and the dropped element
	// still closes itself in foreign content.
	hstAssertEqual(t,
		"<svg><foreignObject><svg></svg></foreignObject></svg>shown",
		p.Sanitize(
			"<ul><li><svg><foreignObject><svg></li><object/>shown"))
}

// TestHTMLStartTagsUpdateForeignContentContext covers issue #461.  HTML
// start-tag rules can remove tracked stack entries.
func TestHTMLStartTagsUpdateForeignContentContext(t *testing.T) {
	p := hstForeignContentPolicy(t)
	inputs := []string{
		// image is rewritten to the void img element.
		"<svg><foreignObject><image><math></svg><object/>hidden",
		// command and isindex are ordinary elements in the current parser,
		// despite legacy serialization tables classifying them as void.
		"<svg><foreignObject><command><math></math></foreignObject>" +
			"<object/>hidden",
		"<svg><foreignObject><isindex><math></math></foreignObject>" +
			"<object/>hidden",
		// A block start closes p in button scope.
		"<svg><foreignObject><p><div></div><math></svg><object/>hidden",
		"<svg><foreignObject><p><hr><math></svg><object/>hidden",
		// A heading start pops a heading current node.
		"<svg><foreignObject><h2><h1></h1><math></svg><object/>hidden",
		// A second button pops the first button and everything above it.
		"<svg><foreignObject><button><div><button></button></div>" +
			"<math></svg><object/>hidden",
		// Duplicate formatting elements invoke the adoption agency rules.
		"<svg><foreignObject><a><div><a></a></div><math></svg>" +
			"<object/>hidden",
		"<svg><foreignObject><nobr><div><nobr></nobr></div><math></svg>" +
			"<object/>hidden",
		// A non-formatting end tag can strand b in the active formatting
		// list, from which a later start tag reconstructs it.
		"<svg><foreignObject><div><b></div><math></math>" +
			"</foreignObject><object/>hidden",
		// An adoption-agency end tag removes only its own formatting entry;
		// other formatting elements it pops can still be reconstructed.
		"<svg><foreignObject><b><i></b><math></math></foreignObject>" +
			"<object/>hidden",
		// A duplicate form is ignored while the form pointer is non-null.
		"<svg><foreignObject><form><div><form></form></div><math></svg>" +
			"<object/>hidden",
		// A form start closes p before inserting the form.
		"<svg><foreignObject><p><form></form><math></svg><object/>hidden",
		// A form end generates implied end tags before removing the form.
		"<svg><foreignObject><form><option></form><image><math></svg>" +
			"<object/>hidden",
		// New list and description items close an earlier item.
		"<svg><foreignObject><li><div><li></li></div><math></svg>" +
			"<object/>hidden",
		"<svg><foreignObject><dd><div><dt></dt></div><math></svg>" +
			"<object/>hidden",
		// A second option closes the current option even without a select.
		"<svg><foreignObject><option><option></option><math></svg>" +
			"<object/>hidden",
		// input pops a select that is in scope under the current rules.
		"<svg><foreignObject><select><input><math></svg><object/>hidden",
		// In table mode a form is inserted and immediately popped.
		"<table><svg><foreignObject><form><math></svg><object/>hidden",
	}
	for _, input := range inputs {
		output := p.Sanitize(input)
		hstAssertFalse(t, strings.Contains(output, "hidden"), input+" -> "+output)
	}
	// bgsound is still inserted and immediately popped by the tree builder,
	// even though it is absent from the sanitizer's legacy void table.
	hstAssertEqual(t,
		"<svg><foreignObject><math></math></foreignObject>hidden</svg>",
		p.Sanitize(
			"<svg><foreignObject><bgsound><math></math></foreignObject>"+
				"<object/>hidden"))
}

// TestFormEndTagInTemplatePopsThroughForm covers issue #461: </form> has a
// different effect in a template.
func TestFormEndTagInTemplatePopsThroughForm(t *testing.T) {
	hstAssertEqual(t,
		"<form><svg></svg></form>",
		hstForeignContentPolicy(t).Sanitize(
			"<body><template><form><svg></form><object/>hidden"))
}

// TestForeignContentContextRecoversAfterHTMLIsland checks that well-formed
// HTML islands do not poison later foreign-content tracking.
func TestForeignContentContextRecoversAfterHTMLIsland(t *testing.T) {
	p := hstForeignContentPolicy(t)
	hstAssertEqual(t,
		"<svg><path></path><rect></rect></svg>"+
			"<svg><path></path></svg>",
		p.Sanitize(
			"<table><tr><td><svg><path/><rect/></svg></td></tr></table>"+
				"<svg><path/></svg>"))
	hstAssertEqual(t,
		"<svg><foreignObject></foreignObject></svg>"+
			"<svg><path></path><rect></rect></svg>",
		p.Sanitize(
			"<svg><foreignObject><table></table></foreignObject></svg>"+
				"<svg><path/><rect/></svg>"))
	hstAssertEqual(t,
		"<svg><foreignObject></foreignObject></svg>"+
			"<svg><title></title><path></path></svg><p>after</p>",
		p.Sanitize(
			"<svg><foreignObject><select></select></foreignObject></svg>"+
				"<svg><title/><path/></svg><p>after</p>"))
}

// TestSpecialElementsBlockHTMLEndTagsInForeignContent covers issue #461.
// Under the HTML rules an end tag search stops at an element in the special
// category, so the elements above it stay open, and the end tag of the
// integration point holding them is ignored while they do.
func TestSpecialElementsBlockHTMLEndTagsInForeignContent(t *testing.T) {
	p := hstForeignContentPolicy(t)
	hstAssertEqual(t,
		"<svg><foreignObject><cite><div></div></cite></foreignObject></svg>",
		p.Sanitize(
			"<svg><foreignObject><cite><div></cite></foreignObject>"+
				"<object/>hidden"))
	hstAssertEqual(t,
		"<math><mi><cite><div></div></cite></mi></math>",
		p.Sanitize("<math><mi><cite><div></cite></mi><object/>hidden"))
	// A td start tag is ignored in body, but the div it seems to hold is
	// still special.
	hstAssertEqual(t,
		"<svg><foreignObject><div></div></foreignObject></svg>",
		p.Sanitize(
			"<svg><foreignObject><td><div></td></foreignObject>"+
				"<object/>hidden"))
	// Without a special element in the way the end tags match, the
	// integration point closes, and the flag is honored again.
	hstAssertEqual(t,
		"<svg><foreignObject><cite><kbd></kbd></cite></foreignObject>"+
			"<path></path>x</svg>",
		p.Sanitize(
			"<svg><foreignObject><cite><kbd></cite></foreignObject>"+
				"<path/>x"))
	// Any h1 through h6 end tag closes an open heading.
	hstAssertEqual(t,
		"<svg><foreignObject><h2><svg></svg></h2></foreignObject></svg>",
		p.Sanitize("<svg><foreignObject><h2><svg></h1><object/>hidden"))
	// </form> removes the form without closing what it holds.
	hstAssertEqual(t,
		"<svg><foreignObject><form><cite></cite></form></foreignObject></svg>",
		p.Sanitize(
			"<svg><foreignObject><form><cite></form></foreignObject>"+
				"<object/>hidden"))
	hstAssertEqual(t,
		"<svg><foreignObject><form><svg></svg></form>shown</foreignObject>"+
			"</svg>",
		p.Sanitize(
			"<svg><foreignObject><form><svg></form><object/>shown"))
	// The adoption agency algorithm rebuilds the stack around a special
	// element and drops the foreign nodes above it.
	hstAssertEqual(t,
		"<svg><foreignObject><b><div><svg></svg></div></b></foreignObject>"+
			"</svg>",
		p.Sanitize(
			"<svg><foreignObject><b><div><svg></b></foreignObject>"+
				"<object/>hidden"))
	// When a special element blocks the end tag, the foreign element above
	// it is still the current node, where the flag is honored.
	hstAssertEqual(t,
		"<svg><foreignObject><cite><div><svg></svg></div></cite>shown"+
			"</foreignObject></svg>",
		p.Sanitize(
			"<svg><foreignObject><cite><div><svg></cite><object/>shown"))
}

// TestStrayEndTagLeavesForeignContentContextUnknown covers issue #461.
// After a stray end tag the tracker cannot tell whether the browser left the
// foreign content, and the next svg start tag inside MathML is a MathML
// element whose foreignObject is not an integration point, so the tracker
// stays unknown rather than starting over.
func TestStrayEndTagLeavesForeignContentContextUnknown(t *testing.T) {
	p := hstForeignContentPolicy(t)
	hstAssertEqual(t,
		"<math><mrow><svg><foreignObject><div></div></foreignObject></svg>"+
			"</mrow></math>",
		p.Sanitize(
			"<math><mrow></foo><svg><foreignObject><div></div>"+
				"</foreignObject><object/>hidden"))
	hstAssertEqual(t,
		"<svg><g></g></svg><svg><path>x</path></svg>",
		p.Sanitize("<svg><g></foo></g></svg><svg><path/>x</svg>"))
	// A self-closing root is still empty in every context.
	hstAssertEqual(t,
		"<svg><g></g></svg><svg></svg>x",
		p.Sanitize("<svg><g></foo></g></svg><svg/>x"))
}

// TestMoreHTMLStartTagRulesInForeignContentContext covers issue #461.  More
// start-tag rules that change the tracked stack, and those whose outcome the
// sanitizer cannot know.
func TestMoreHTMLStartTagRulesInForeignContentContext(t *testing.T) {
	p := hstForeignContentPolicy(t)
	// xmp closes a p in button scope, as pre and listing do.
	hstAssertEqual(t,
		"<svg><foreignObject><p></p><math></math></foreignObject></svg>",
		p.Sanitize(
			"<svg><foreignObject><p><xmp></xmp><math></svg><object/>hidden"))
	hstAssertEqual(t,
		"<svg><foreignObject><p></p></foreignObject></svg>"+
			"<svg><path></path></svg>",
		p.Sanitize(
			"<svg><foreignObject><p><xmp></xmp></foreignObject></svg>"+
				"<svg><path/></p></foreignObject><object/>hidden"))
	// Whether a table start closes an open p depends on the quirks mode of
	// the document that embeds the output, so the context fails closed.
	hstAssertEqual(t,
		"<svg><foreignObject><p></p></foreignObject></svg>",
		p.Sanitize(
			"<svg><foreignObject><p><table></table></foreignObject>"+
				"<object/>hidden"))
	// The tokenizer keeps only the first of duplicate attributes, so this
	// input is not hidden: in table mode it still pops the open select.
	hstAssertEqual(t,
		"<svg><foreignObject></foreignObject></svg>",
		p.Sanitize(
			"<table><svg><foreignObject><select><input type=text type=hidden>"+
				"</foreignObject></svg></select></foreignObject>"+
				"<object/>hidden"))
	// A table inside a cell's foreign content is tracked exactly and hands
	// the cell's in-body rules back when it closes.
	hstAssertEqual(t,
		"<svg><foreignObject></foreignObject></svg>",
		p.Sanitize(
			"<table><tr><td><svg><foreignObject><table></table>"+
				"<object/>hidden"))
	// A self-closing root closes itself even where the tracker gives up.
	hstAssertEqual(t,
		"<svg><foreignObject><svg></svg>x</foreignObject></svg>",
		p.Sanitize("<svg><foreignObject><table><svg/>x"))
}

// TestSearchElementCategoryIsNotReliedOn covers issue #461.  The
// specification puts search in the special category but Chrome does not, so
// an end-tag or list-item walk that reaches one has no single right answer,
// and the context fails closed.
func TestSearchElementCategoryIsNotReliedOn(t *testing.T) {
	p := hstForeignContentPolicy(t)
	hstAssertEqual(t,
		"<svg><foreignObject><cite></cite></foreignObject></svg>",
		p.Sanitize(
			"<svg><foreignObject><cite><search><span></cite></foreignObject>"+
				"</svg></span></search></cite></foreignObject><object/>hidden"))
	hstAssertEqual(t,
		"<svg><foreignObject></foreignObject></svg>",
		p.Sanitize(
			"<svg><foreignObject><li><search><li></li></foreignObject></svg>"+
				"</search></li></foreignObject><object/>hidden"))
}

// TestDialogElementCategoryIsNotReliedOn covers issue #461.  Like search,
// dialog is in the special category of the WHATWG parsing algorithm but not
// in Chrome's special-node set, so a walk that reaches an open dialog has no
// single right answer across browsers and the context must fail closed.
// Without this a following <object/> was honored as self-closing, exposing
// text that a spec-compliant parser keeps inside the HTML object.
func TestDialogElementCategoryIsNotReliedOn(t *testing.T) {
	p := hstForeignContentPolicy(t)
	// "Any other end tag" (</cite>) walks past the open dialog.
	hstAssertEqual(t,
		"<svg><foreignObject><cite></cite></foreignObject></svg>",
		p.Sanitize(
			"<svg><foreignObject><cite><dialog></cite></foreignObject>"+
				"<object/>hidden"))
	// A list-item start (<li>) walks past the open dialog.
	hstAssertEqual(t,
		"<svg><foreignObject></foreignObject></svg>",
		p.Sanitize(
			"<svg><foreignObject><li><dialog><li></li></foreignObject>"+
				"<object/>hidden"))
	// The adoption agency's furthest-block search (</b>) reaches the dialog.
	hstAssertEqual(t,
		"<svg><foreignObject><b><svg></svg></b></foreignObject></svg>",
		p.Sanitize(
			"<svg><foreignObject><b><dialog><svg></b></foreignObject>"+
				"<object/>hidden"))
}

// TestUntrackedTableEndTagsMustNameTheOpenPart covers issue #461.  The
// insertion mode inherited from an untracked table depends on which cell,
// caption or section is open, and browsers ignore the end tags that name
// something else.
func TestUntrackedTableEndTagsMustNameTheOpenPart(t *testing.T) {
	p := hstForeignContentPolicy(t)
	svgForm := "<svg><foreignObject><form></foreignObject><object/>hidden"
	// Inside a cell or caption the in-body rules insert the form, which
	// stays open and keeps the object's fallback text hidden.
	hidden := "<svg><foreignObject><form></form></foreignObject></svg>"
	for _, context := range []string{
		"<table><tr><th></td>", "<table><tr><td></th>",
		"<table><thead><tr><td></tbody>", "<table><tr><td></tfoot>",
		"<table><tr><td></caption>", "<table><caption></tr>",
		"<table><caption></tbody>", "<table><caption></td>",
		"<table><caption>", "<table><tr><td><table></table>",
		"<table><tr><td><table><tr><td></table>",
		"<table><tr><td><table><tr><td></td></tr></table>",
	} {
		hstAssertEqual(t, hidden, p.Sanitize(context+svgForm), context)
	}
	// Back in the table modes the form is inserted and popped at once, so
	// the foreignObject closes and the object is foreign.
	shown := "<svg><foreignObject><form></form></foreignObject>hidden</svg>"
	for _, context := range []string{
		"<table><tr><td></td>", "<table><tr><td></tr>",
		"<table><thead><tr><td></thead>", "<table><caption></caption>",
		"<table><tr><td><table></table></td>",
		"<table><tr><td><table><tr><td></td></tr></table></td>",
	} {
		hstAssertEqual(t, shown, p.Sanitize(context+svgForm), context)
	}
	// Table structure inside a caption closes the caption and everything
	// above it, which the tracker does not follow.
	hstAssertEqual(t,
		"<svg><foreignObject></foreignObject></svg>",
		p.Sanitize(
			"<table><caption><svg><foreignObject><td></foreignObject>"+
				"<object/>hidden"))
}

// TestForeignContentContextRecoversAfterNestedTables checks that well-formed
// nested tables and captions do not poison later SVG.
func TestForeignContentContextRecoversAfterNestedTables(t *testing.T) {
	p := hstForeignContentPolicy(t)
	hstAssertEqual(t,
		"x<svg><path></path><rect></rect></svg>",
		p.Sanitize(
			"<table><tr><td><table><tr><td>x</td></tr></table></td></tr>"+
				"</table><svg><path/><rect/></svg>"))
	hstAssertEqual(t,
		"x<svg><path></path><rect></rect></svg>",
		p.Sanitize(
			"<table><caption>x</caption></table><svg><path/><rect/></svg>"))
	hstAssertEqual(t,
		"<svg><path></path><rect></rect></svg>",
		p.Sanitize(
			"<table><caption><table></table></caption></table>"+
				"<svg><path/><rect/></svg>"))
}

// TestModeledTransitionsKeepHonoringSelfClosingTags covers issue #461.  The
// modeled transitions are followed exactly rather than by failing closed: a
// self-closing tag is still honored in later SVG.
func TestModeledTransitionsKeepHonoringSelfClosingTags(t *testing.T) {
	p := hstForeignContentPolicy(t)
	inputs := []string{
		"<svg><foreignObject><p><div></div><math></svg><svg><path/>x",
		"<svg><foreignObject><h2><h1></h1><math></svg><svg><path/>x",
		"<svg><foreignObject><button><div><button></button></div><math>" +
			"</svg><svg><path/>x",
		"<svg><foreignObject><form><div><form></form></div><math></svg>" +
			"<svg><path/>x",
		"<svg><foreignObject><li><div><li></li></div><math></svg>" +
			"<svg><path/>x",
		"<svg><foreignObject><dd><div><dt></dt></div><math></svg>" +
			"<svg><path/>x",
		"<svg><foreignObject><option><option></option><math></svg>" +
			"<svg><path/>x",
		"<svg><foreignObject><select><input><math></svg><svg><path/>x",
		"<svg><foreignObject><p><hr><math></svg><svg><path/>x",
		"<svg><foreignObject><p><xmp></xmp><math></svg><svg><path/>x",
		"<svg><foreignObject><image><math></svg><svg><path/>x",
		"<svg><foreignObject><form><option></form><image><math></svg>" +
			"<svg><path/>x",
		"<svg><foreignObject><h2><svg></h1><svg><path/>x",
		"<svg><foreignObject><form><cite></form></foreignObject>" +
			"<svg><path/>x",
		"<svg><foreignObject><cite><div></cite></foreignObject>" +
			"<svg><path/>x",
		"<table><svg><foreignObject><form><math></svg><svg><path/>x",
		"<table><tr><th></td><svg><foreignObject><form></foreignObject>" +
			"</svg><svg><path/>x",
		"<table><tr><td><table><tr><td>x</td></tr></table></td></tr></table>" +
			"<svg><foreignObject><form></foreignObject></svg><svg><path/>x",
	}
	for _, input := range inputs {
		output := p.Sanitize(input)
		hstAssertTrue(t, strings.Contains(output, "<path></path>x"), input+" -> "+output)
	}
}

// TestDeepForeignContentContextFailsClosed checks that the bounded context
// tracker falls back to suppressing dropped content.
func TestDeepForeignContentContextFailsClosed(t *testing.T) {
	p := hstForeignContentPolicy(t)
	html := "<svg>" + strings.Repeat("<g>", 300) + "<object/>hidden"
	out := p.Sanitize(html)
	hstAssertFalse(t, strings.Contains(out, "hidden"), out)
}

// TestDroppedSelectDoesNotImplyAListItem: a select the policy drops leaves no
// list item behind.  The option's container in the output was judged to be
// the body, and the containment metadata answers an option there with an
// implied select, which the same policy drops again.  Preparing that select
// under the dropped one also implied a synthetic list item, which was
// emitted and held everything up to the enclosing block: an ordinary
// dropdown under Blocks came out as <li>x<p>y</p></li> and grew a
// <ul> on the next pass.
func TestDroppedSelectDoesNotImplyAListItem(t *testing.T) {
	blocks := Blocks.And(Formatting)
	cases := [][2]string{
		{"<select><option>x</option></select>", "x"},
		{"<select><option>x</option><option>y</option></select>", "xy"},
		{"<select><option>x</option></select><p>y</p><p>z</p>",
			"x<p>y</p><p>z</p>"},
		{"<p>a</p><select><option>x</option></select><p>y</p>",
			"<p>a</p>x<p>y</p>"},
		{"<form><select><option>x</option></select></form><p>y</p>",
			"x<p>y</p>"},
		{"<select><option>x</select><p>y</p>", "x<p>y</p>"},
		{"<select><option></option></select><p>y</p>", "<p>y</p>"},
		{"<select><option>x</option></select><h1>y</h1><ul><li>z</li></ul>",
			"x<h1>y</h1><ul><li>z</li></ul>"},
		{"<select name=s onchange=alert(1)><option value=1>One</option>" +
			"<option value=2>Two</option></select><b>after</b>",
			"OneTwo<b>after</b>"},
	}
	for _, c := range cases {
		hstAssertRoundTripAndBalanced(t, blocks, c[0], c[1])
	}
	// Nothing changes for a select the policy keeps, or one nested in a
	// container the policy keeps.
	selects := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("select", "option", "p", "div"))
	hstAssertRoundTripAndBalanced(t,
		selects, "<select><option>x</option></select><p>y</p>",
		"<select><option>x</option></select><p>y</p>")
	hstAssertRoundTripAndBalanced(t,
		blocks, "<div><select><option>x</option></select></div><p>y</p>",
		"<div>x</div><p>y</p>")
	// An option the policy keeps under a dropped select is emitted where the
	// select was, with no implied wrapper around it.
	options := hstFactory(t, NewHTMLPolicyBuilder().AllowElements("option", "p"))
	hstAssertEqual(t,
		"<option>x</option><p>y</p>",
		options.Sanitize("<select><option>x</option></select><p>y</p>"))
}

// hstP5RecordingListener records the element names of discarded tags and of
// tags whose attributes were discarded.
type hstP5RecordingListener struct {
	NopHTMLChangeListener
	discarded *[]string
}

func (l hstP5RecordingListener) DiscardedTag(context any, elementName string) {
	*l.discarded = append(*l.discarded, elementName)
}

func (l hstP5RecordingListener) DiscardedAttributes(
	context any, tagName string, attributeNames ...string) {
	*l.discarded = append(*l.discarded, tagName)
}

// TestSelectContentDoesNotGrowAListLevelPerPass is item 5 of #492.  The
// containment metadata answers content a select cannot hold with a list
// item, so that it nests inside the select the way a browser nests its text.
// No browser creates that item.  A policy that allowed li emitted it:
// <select>x</select> came out as <select><li>x</li></select>, the next pass
// wrapped the li in a ul, the one after that wrapped the ul in a li, and so
// on until the nesting limit truncated the document.  The emitted li also
// bounded the select end tag's scope search, so text after </select> landed
// inside the select.  The item now stays on the balancer's stack and is
// never sent.
func TestSelectContentDoesNotGrowAListLevelPerPass(t *testing.T) {
	names := []string{
		"select", "option", "optgroup", "svg", "math", "foreignObject",
		"table", "tbody", "tr", "td", "ul", "li", "div", "b"}
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(names...).AllowWithoutAttributes(names...))
	// Each output is a fixed point and parses to the tree a browser builds
	// from the input.
	faithful := [][2]string{
		// The reproductions from the issue.
		{"<select><svg>x</svg></select>", "<select><svg>x</svg></select>"},
		{"<select><math>x</math></select>",
			"<select><math>x</math></select>"},
		{"<select><table><svg>x</svg>",
			"<select><table></table><svg>x</svg></select>"},
		// The growth needs no foreign root: bare text, and any element the
		// select cannot hold, took the same wrappers.
		{"<select>x</select>", "<select>x</select>"},
		{"<select><li>x", "<select><ul><li>x</li></ul></select>"},
		{"<select><ul><li>x", "<select><ul><li>x</li></ul></select>"},
		{"<select><div>x</div></select>", "<select><div>x</div></select>"},
		{"<select><td>x",
			"<select><table><tbody><tr><td>x</td></tr></tbody></table>" +
				"</select>"},
		// An option or optgroup around the root, or beside it.
		{"<select><option><svg>x</svg></option></select>",
			"<select><option><svg>x</svg></option></select>"},
		{"<select><optgroup><svg>x</svg></optgroup></select>",
			"<select><optgroup><svg>x</svg></optgroup></select>"},
		{"<select><optgroup><svg>x</svg></optgroup><option>y</option>" +
			"</select>",
			"<select><optgroup><svg>x</svg></optgroup><option>y</option>" +
				"</select>"},
		{"<select><svg>x</svg><option>y</option></select>",
			"<select><svg>x</svg><option>y</option></select>"},
		{"<select><option>a</option>x<option>b</option></select>",
			"<select><option>a</option>x<option>b</option></select>"},
		// An integration point, a cell around the select, and a nested
		// select, which a browser reads as the end of the first.
		{"<select><svg><foreignObject>x</foreignObject></svg></select>",
			"<select><svg><foreignObject>x</foreignObject></svg></select>"},
		{"<table><tr><td><select>x</select></td></tr></table>",
			"<table><tbody><tr><td><select>x</select></td></tr></tbody>" +
				"</table>"},
		{"<select><select>x", "<select></select>x"},
		// Text before and after the root, and after the select: the emitted
		// item hid the select from its end tag, so the b landed inside it.
		{"<select>a<svg>x</svg>b</select>",
			"<select>a<svg>x</svg>b</select>"},
		{"a<select>x</select>b", "a<select>x</select>b"},
		{"<ul><li><select>x</select></li><li>y</li></ul>",
			"<ul><li><select>x</select></li><li>y</li></ul>"},
	}
	for _, c := range faithful {
		hstAssertRoundTripAndBalanced(t, p, c[0], c[1])
		hstAssertEqual(t, hstParseAsBrowser(t, c[0]), hstParseAsBrowser(t, c[1]), c[0])
	}
	// A free list item after the select gets the list it gets anywhere
	// else, and the output is a fixed point.
	hstAssertRoundTripAndBalanced(t,
		p, "<select>x</select><li>y",
		"<select>x</select><ul><li>y</li></ul>")

	// Hostile content in those positions is still removed, and what is kept
	// stays where a browser puts it: the output parses as the input with its
	// payload taken out.
	hostile := [][3]string{
		{"<select><li onclick=alert(1)><img src=x onerror=alert(1)>y",
			"<select><ul><li>y</li></ul></select>", "<select><li>y"},
		{"<select><li><a href=javascript:alert(1)>y</a>",
			"<select><ul><li>y</li></ul></select>", "<select><li>y"},
		{"<select><table><svg onload=alert(1)>x</svg>",
			"<select><table></table><svg>x</svg></select>",
			"<select><table><svg>x</svg>"},
		{"a<select>x</select><b onmouseover=alert(1)>b</b>",
			"a<select>x</select><b>b</b>", "a<select>x</select><b>b</b>"},
	}
	for _, c := range hostile {
		hstAssertRoundTripAndBalanced(t, p, c[0], c[1])
		hstAssertFalse(t, strings.Contains(c[1], "alert"), c[1])
		hstAssertEqual(t, hstParseAsBrowser(t, c[2]), hstParseAsBrowser(t, c[1]), c[0])
	}
	// With the item emitted, the select end tag was lost and the script body
	// came out as text inside the select.
	script := "<select>x</select><script>alert(1)</script>y"
	hstAssertRoundTripAndBalanced(t, p, script, "<select>x</select>y")
	hstAssertEqual(t,
		hstParseAsBrowser(t, "<select>x</select>y"),
		hstParseAsBrowser(t, p.Sanitize(script)))

	// The prepackaged policies drop the select and leave its text where the
	// select was.  Blocks emitted a bare li there and wrapped it in
	// a ul on the next pass.
	blocks := Blocks.And(Tables)
	dropped := [][2]string{
		{"<select>x</select>", "x"},
		{"<p>a</p><select>x</select><p>b</p>", "<p>a</p>x<p>b</p>"},
		{"<select><svg>x</svg></select><p>y</p>", "x<p>y</p>"},
		{"<select><table><svg>x</svg>", "<table></table>x"},
		{"<ul><li><select>x</select></li><li>y</li></ul>",
			"<ul><li>x</li><li>y</li></ul>"},
	}
	for _, c := range dropped {
		hstAssertRoundTripAndBalanced(t, blocks, c[0], c[1])
	}

	// The item is never sent, so a policy without li has nothing to report.
	discarded := []string{}
	listener := hstP5RecordingListener{discarded: &discarded}
	selects := hstFactory(t, NewHTMLPolicyBuilder().AllowElements("select", "svg"))
	hstAssertEqual(t,
		"<select><svg>x</svg></select>",
		selects.SanitizeWithListener("<select><svg>x</svg></select>", listener, nil))
	hstAssertEqual(t, 0, len(discarded), fmt.Sprint(discarded))
}

// TestDroppedListAndSelectContextsAreStable covers residuals from #494 under
// policies that keep li but drop its usual wrappers.  A dropped inferred
// list must not capture later text or a following select after its emitted
// item.  An inferred item inside an output select is just as
// browser-invisible as the select's synthetic item.  Neither may hide the
// select's end tag.  Finally, a kept option below a dropped nested select
// must close the option open in the output, and a dropped list after a
// closed select must not nest its inferred item in the item that held the
// select.
func TestDroppedListAndSelectContextsAreStable(t *testing.T) {
	liOnly := hstFactory(t, NewHTMLPolicyBuilder().AllowElements("li"))
	liOption := hstFactory(t, NewHTMLPolicyBuilder().AllowElements("li", "option"))
	liSelect := hstFactory(t, NewHTMLPolicyBuilder().AllowElements("li", "select"))
	droppedSelect := "<ul><li onclick=alert(1)></li></ul><select>" +
		"<img src=x onerror=alert(1)>tail</select>"
	hstAssertRoundTripAndBalanced(t, liOnly, droppedSelect, "<li></li>tail")
	hstAssertRoundTripAndBalanced(t, liOption, droppedSelect, "<li></li>tail")
	hstAssertRoundTripAndBalanced(t,
		liOption, "<select><option>one<select><option>two",
		"<option>one</option><option>two</option>")
	hstAssertRoundTripAndBalanced(t,
		liSelect, "<form><li onclick=alert(1)></form><select>"+
			"<img src=x onerror=alert(1)>tail</select>",
		"<li></li><select>tail</select>")
	hstAssertRoundTripAndBalanced(t,
		liSelect, "<select>x<ul><img src=x onerror=alert(1)>tail",
		"<select>xtail</select>")
	hstAssertRoundTripAndBalanced(t,
		liSelect, "<select><li></li></select>tail",
		"<select><li></li></select>tail")
	hstAssertRoundTripAndBalanced(t,
		liSelect, "<ol><select></select><ul>tail",
		"<li><select></select></li>tail")
}

// TestDroppedTemplateListResidualsAreStable: the eight residual flags
// recorded for #499 reduce to an inferred list whose emitted item closes
// while the inferred wrapper produces no output.  Later text, option or
// select output must not become that list's next item only when the output
// is sanitized again.
func TestDroppedTemplateListResidualsAreStable(t *testing.T) {
	liOnly := hstFactory(t, NewHTMLPolicyBuilder().AllowElements("li"))
	liOption := hstFactory(t, NewHTMLPolicyBuilder().AllowElements("li", "option"))
	liSelect := hstFactory(t, NewHTMLPolicyBuilder().AllowElements("li", "select"))
	droppedTemplateColumn := "<template><col><ol><br><table><option>" +
		"<img src=x onerror=alert(1)>tail"
	hstAssertRoundTripAndBalanced(t,
		liOnly, droppedTemplateColumn, "<li></li>tail")
	hstAssertRoundTripAndBalanced(t,
		liOption, droppedTemplateColumn,
		"<li></li><option>tail</option>")
	hstAssertRoundTripAndBalanced(t,
		liSelect, droppedTemplateColumn,
		"<li></li><select>tail</select>")
	hstAssertRoundTripAndBalanced(t,
		liOnly,
		"<svg><li onclick=alert(1)></svg><template>"+
			"<img src=x onerror=alert(1)>tail",
		"<li></li>tail")
}

// TestDroppedNestedListKeepsBrowserItemContext: a nested item start has
// already ended the output item for a browser.  When the list around that
// nested item has no output, keeping its logical context lets later text
// acquire its own item too.  Retiring the list instead moved the text
// outside any item when the first output was parsed, so its tree changed on
// the next sanitization.
func TestDroppedNestedListKeepsBrowserItemContext(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().AllowElements("ul", "li", "p"))
	input := "<li onclick=alert(1)><ol><tbody></li>" +
		"<img src=x onerror=alert(1)>&amp;"
	out := p.Sanitize(input)
	again := p.Sanitize(out)
	hstAssertEqual(t, hstParseAsBrowser(t, out), hstParseAsBrowser(t, again))
	hstAssertTrue(t, strings.Contains(out, "&amp;"))
	hstAssertFalse(t, strings.Contains(out, "alert") || strings.Contains(out, "<img"))
	hstAssertBalancedPolicyEvents(t, p, input)
	hstAssertBalancedPolicyEvents(t, p, out)
}

// TestSelectExitStartsRestoreTheBrowserTextGate: input, keygen and textarea
// starts make a browser leave its in-select insertion mode; another select
// start closes the open select and is ignored.  The serialized output has to
// retire the same select before the policy judges later text.  Otherwise an
// allowed select admits text that a browser reparses directly in an ancestor
// where the policy disallows it.
func TestSelectExitStartsRestoreTheBrowserTextGate(t *testing.T) {
	names := []string{
		"table", "tbody", "tr", "td", "th", "foo", "select", "option",
		"optgroup",
		"input", "keygen", "textarea", "hr", "button", "b", "svg", "math",
	}
	noTextInFoo := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(names...).AllowWithoutAttributes(names...).
		DisallowTextIn("foo"))
	blocked := [][2]string{
		// The minimized issue reproduction includes the free option wrapper.
		{"<th><FOO><option><input>hidden",
			"<table><tbody><tr><th><foo><select><option></option></select>" +
				"<input /></foo></th></tr></tbody></table>"},
		{"<foo><select><input>hidden",
			"<foo><select></select><input /></foo>"},
		{"<foo><select><keygen>hidden",
			"<foo><select></select><keygen /></foo>"},
		{"<foo><select><textarea>hidden",
			"<foo><select></select><textarea></textarea></foo>"},
		{"<foo><select><select>hidden",
			"<foo><select></select></foo>"},
		// A browser ignores these roots in select mode.  They do not make the
		// following input foreign, even though a lexical tracker sees them.
		{"<foo><select><svg><input>hidden",
			"<foo><select><svg></svg></select><input /></foo>"},
		{"<foo><select><math><input>hidden",
			"<foo><select><math></math></select><input /></foo>"},
		// A real descendant after the exit owns and admits its own text.
		{"<foo><select><option>safe<input>hidden<b>shown</b>hidden",
			"<foo><select><option>safe</option></select><input />" +
				"<b>shown</b></foo>"},
		// A template or table ignored in select mode establishes no output
		// container; retained descendants still precede the exit.
		{"<foo><select><template><b>safe</b><input>hidden",
			"<foo><select><b>safe</b></select><input /></foo>"},
		{"<foo><select><table><input>hidden",
			"<foo><select><table></table></select><input /></foo>"},
		// A table pushed in front of foreign-looking select content remains
		// available to reopen after the select exit.
		{"<foo><select><mtext><tr><math><input>hidden<b>shown</b><tr>",
			"<foo><select><table><tbody><tr></tr></tbody></table>" +
				"<math></math></select><input /><b>shown</b>" +
				"<table><tbody><tr></tr></tbody></table></foo>"},
		// A select implied only for containment must neither retire a real
		// output select nor hide that select from its explicit end tag.
		{"<foo><select><option><optgroup><input>hidden",
			"<foo><select><option><optgroup></optgroup></option></select>" +
				"<input /></foo>"},
		{"<foo><select><select><option><input>hidden",
			"<foo><select></select><select><option></option></select>" +
				"<input /></foo>"},
		{"<foo><select><table><optgroup><tbody><input>hidden",
			"<foo><select><table></table><optgroup></optgroup></select>" +
				"<table><tbody></tbody></table><input /></foo>"},
		// Synthetic table context inside the select is gone after the exit;
		// a later table part gets a new, stable implied table.
		{"<foo><select><td><input><tr>",
			"<foo><select><table><tbody><tr><td></td></tr></tbody></table>" +
				"</select><input /><table><tbody><tr></tr></tbody></table>" +
				"</foo>"},
		// A select retired while table context is pushed out must not hide
		// the implied select around a later option in a cell.
		{"<foo><select><tr><option><td><option>shown",
			"<foo><select><table><tbody><tr></tr></tbody></table>" +
				"<option></option></select><table><tbody><tr><td><select>" +
				"<option>shown</option></select></td></tr></tbody></table></foo>"},
		// Outputless containment entries between an option and its implied
		// select are not element metadata and must not be indexed as such.
		{"<foo><option><optgroup><option>",
			"<foo><select><option><optgroup><option></option></optgroup>" +
				"</option></select></foo>"},
		// These starts stay in select mode, so their text remains in select.
		{"<foo><select><hr>kept",
			"<foo><select><hr />kept</select></foo>"},
		{"<foo><select><button>kept",
			"<foo><select><button>kept</button></select></foo>"},
	}
	for _, c := range blocked {
		hstAssertRoundTripAndBalanced(t, noTextInFoo, c[0], c[1])
	}
	hstAssertEqual(t,
		"safeshown",
		hstTextOf(hstParseAsBrowser(t, noTextInFoo.Sanitize(blocked[7][0]))))

	textInFoo := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(names...).AllowWithoutAttributes(names...))
	retained := [][2]string{
		{"<foo><select><option>safe<input>tail",
			"<foo><select><option>safe</option></select><input />tail</foo>"},
		{"<foo><select><option>safe<select>tail",
			"<foo><select><option>safe</option></select>tail</foo>"},
	}
	for _, c := range retained {
		hstAssertRoundTripAndBalanced(t, textInFoo, c[0], c[1])
		hstAssertEqual(t, hstParseAsBrowser(t, c[0]), hstParseAsBrowser(t, c[1]), c[0])
	}

	// A retained HTML template bounds the select's scope.  An exit-looking
	// start inside it belongs to the template and must not retire the select
	// below it or restore foo's text gate around the template's contents.
	templateNames := []string{
		"foo", "select", "template", "option",
		"input", "keygen", "textarea", "u",
	}
	keptTemplate := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(templateNames...).AllowWithoutAttributes(templateNames...).
		DisallowTextIn("foo"))
	scopedByTemplate := [][2]string{
		{"<foo><select><template><input>shown</template></select>hidden",
			"<foo><select><template><input />shown</template></select></foo>"},
		{"<foo><select><template><keygen>shown</template></select>hidden",
			"<foo><select><template><keygen />shown</template></select></foo>"},
		{"<foo><select><template><textarea>shown</textarea></template>" +
			"</select>hidden",
			"<foo><select><template><textarea></textarea>shown</template>" +
				"</select></foo>"},
		{"<foo><select><template><select><option>shown</option></select>" +
			"</template></select>hidden",
			"<foo><select><template><select><option>shown</option></select>" +
				"</template></select></foo>"},
		// The nested select start is ignored after closing the outer one; it
		// cannot hide the surrounding option from the option that follows.
		{"<foo><template><option><select><select><option>",
			"<foo><template><option><select></select></option>" +
				"<option></option></template></foo>"},
		// The outer select is likewise out of scope when containment implies
		// an inner select for an option below another template descendant.
		{"<foo><select><template><u><option>shown",
			"<foo><select><template><u><select><option>shown</option>" +
				"</select></u></template></select></foo>"},
	}
	for _, c := range scopedByTemplate {
		hstAssertRoundTripAndBalanced(t, keptTemplate, c[0], c[1])
	}

	// Table and MathML-looking starts are ignored by an output parser in
	// select mode, so the later option still closes the earlier option.
	ignoredSelectStarts := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("foo", "select", "option", "math", "mtext", "table").
		AllowWithoutAttributes(
			"foo", "select", "option", "math", "mtext", "table").
		DisallowTextIn("foo"))
	hstAssertRoundTripAndBalanced(t,
		ignoredSelectStarts,
		"<foo><option><math><mtext><mtext><table><option>",
		"<foo><select><option><math><mtext><mtext><table></table>"+
			"</mtext></mtext></math></option><option></option></select>"+
			"</foo>")

	// The output name decides.  A custom element mapped to input exits the
	// select; an input mapped to a div is ignored there like any other child.
	mappedToInput := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("foo", "select", "option", "input", "b").
		AllowElementsWithPolicy(hstRenamingPolicy("input"), "bar").
		AllowWithoutAttributes("bar", "input").
		DisallowTextIn("foo"))
	hstAssertRoundTripAndBalanced(t,
		mappedToInput,
		"<foo><select><option>safe<bar>hidden</bar><b>shown</b>hidden",
		"<foo><select><option>safe</option></select><input />"+
			"<b>shown</b></foo>")
	mappedFromInput := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("foo", "select", "option", "div", "b").
		AllowElementsWithPolicy(hstRenamingPolicy("div"), "input").
		AllowWithoutAttributes("input").
		DisallowTextIn("foo"))
	hstAssertRoundTripAndBalanced(t,
		mappedFromInput,
		"<foo><select><option>safe<input>kept<b>shown</b></select>",
		"<foo><select><option>safe<div></div>kept<b>shown</b></option>"+
			"</select></foo>")
}

// TestSelectContentAtTheNestingLimitRoundTrips: the synthetic item nests
// nothing in the output, so it does not consume the nesting budget.
// Counting it made the second pass over <select><li>x</li></select> near the
// limit drop the li the first pass had emitted: the explicit ul of the
// second pass implied the item, where the li of the first pass had implied
// only the ul.
func TestSelectContentAtTheNestingLimitRoundTrips(t *testing.T) {
	names := []string{"div", "select", "svg", "ul", "li", "b"}
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(names...).AllowWithoutAttributes(names...))
	inners := []string{
		"<select>x</select>", "<select><svg>x</svg></select>",
		"<select><li>x</li></select>", "<select><ul><li>x</li></ul></select>",
		"<select><b>x</b></select>", "<select><div>x</div></select>",
		"<select><b>x</b></select>y",
	}
	for _, inner := range inners {
		for _, depth := range []int{252, 253, 254, 255, 256} {
			label := fmt.Sprintf("%s at depth %d", inner, depth)
			input := hstNest(inner, depth)
			out := p.Sanitize(input)
			again := p.Sanitize(out)
			hstAssertEqual(t, out, again, label)
			hstAssertEqual(t, hstParseAsBrowser(t, out), hstParseAsBrowser(t, again), label)
			hstAssertTrue(t, strings.Contains(out, "x"), label)
			if depth <= 254 {
				// Everything fits, or only the li of a list the browser ignores
				// inside a select is dropped, so the output reads as the input.
				hstAssertEqual(t, hstParseAsBrowser(t, input), hstParseAsBrowser(t, out), label)
			}
		}
	}
	// The li at the 256th level is emitted; one level deeper it is not, and
	// the text flattens into the list.  Both read back the same.
	hstAssertEqual(t,
		hstNest("<select><ul><li>x</li></ul></select>", 253),
		p.Sanitize(hstNest("<select><li>x</li></select>", 253)))
	hstAssertEqual(t,
		hstNest("<select><ul></ul>x</select>", 254),
		p.Sanitize(hstNest("<select><li>x</li></select>", 254)))
	// With the select itself at the limit, its item still holds the content
	// the child would have held, and the select is not closed for it.  The
	// limit check that refused the item here moved the text out of the
	// select while bare text stayed in.
	hstAssertEqual(t,
		hstNest("<select>x</select>y", 255),
		p.Sanitize(hstNest("<select><b>x</b></select>y", 255)))
	hstAssertEqual(t,
		hstNest("<select>x</select>", 255),
		p.Sanitize(hstNest("<select><div>x</div></select>", 255)))
}

// hstP5BrowserParentOf is hstBrowserParentOf with a missing parent rendered
// as "null", for messages and comparisons.
func hstP5BrowserParentOf(t testing.TB, html, name string) string {
	t.Helper()
	parent, ok := hstBrowserParentOf(t, html, name)
	if !ok {
		return "null"
	}
	return parent
}

// TestFreeWrappersApplyUnderEveryOtherContainer is item 9 of #492.  The
// containment metadata's select around a free option or optgroup, and its
// list around a free list item, apply under any container that is not one
// of the few that hold the element directly.  Those few were kept as a bit
// set only as long as its highest member, and an ancestor past its end was
// read as one of them, so an option under a span, a th or a ul, and a list
// item under a var, got no wrapper.  Under a ul the list's own item was
// implied instead, and the next pass, seeing the option in that item, added
// the select: not a fixed point.  The table parts' wrappers keep the old
// reading, since the balancer returns a part to a table in scope first and
// its handling of parts in dropped tables was built on it.
func TestFreeWrappersApplyUnderEveryOtherContainer(t *testing.T) {
	names := []string{
		"ul", "ol", "li", "select", "option", "optgroup", "table", "tbody",
		"tr", "td", "th", "span", "u", "var", "video", "tt", "div", "p", "b"}
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(names...).AllowWithoutAttributes(names...))
	cases := [][2]string{
		// Containers whose element index is past the wrapper's set.
		{"<ul><option>x", "<ul><li><select><option>x</option></select></li></ul>"},
		{"<ul><optgroup>x",
			"<ul><li><select><optgroup>x</optgroup></select></li></ul>"},
		{"<span><option>x", "<span><select><option>x</option></select></span>"},
		{"<u><optgroup>x", "<u><select><optgroup>x</optgroup></select></u>"},
		{"<var><li>x", "<var><ul><li>x</li></ul></var>"},
		{"<video><li>x", "<video><ul><li>x</li></ul></video>"},
		{"<table><th><option>x",
			"<table><tbody><tr><th><select><option>x</option></select></th></tr>" +
				"</tbody></table>"},
		{"<table><td>x<option>y",
			"<table><tbody><tr><td>x<select><option>y</option></select></td>" +
				"</tr></tbody></table>"},
		{"<ul><li>x</li><option>y",
			"<ul><li>x</li><li><select><option>y</option></select></li></ul>"},
		// Containers before it, and the containers that hold the element
		// directly, are as they were.
		{"<div><option>x", "<div><select><option>x</option></select></div>"},
		{"<u><li>x", "<u><ul><li>x</li></ul></u>"},
		{"<ul><li>x", "<ul><li>x</li></ul>"},
		{"<select><option>x", "<select><option>x</option></select>"},
		{"<select><optgroup><option>x",
			"<select><optgroup><option>x</option></optgroup></select>"},
		{"<table><tr><td>x",
			"<table><tbody><tr><td>x</td></tr></tbody></table>"},
	}
	for _, c := range cases {
		hstAssertRoundTripAndBalanced(t, p, c[0], c[1])
	}
	// The issue's shape: the option's cell is dropped by the policy, and an
	// optgroup beside it, or in the cell's place, gets its select too.
	noTable := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("select", "option", "optgroup", "p", "b", "div", "ul",
			"li").
		AllowWithoutAttributes("select", "option", "optgroup", "p", "b",
			"div", "ul", "li"))
	dropped := [][2]string{
		{"<table><th><option>tail", "<select><option>tail</option></select>"},
		{"<table><th><optgroup>tail",
			"<select><optgroup>tail</optgroup></select>"},
		{"<table><tr><td><optgroup>a</optgroup><option>b",
			"<select><optgroup>a</optgroup><option>b</option></select>"},
		{"<td><optgroup>tail", "<select><optgroup>tail</optgroup></select>"},
		{"<table><td><ul><optgroup>x",
			"<ul><li><select><optgroup>x</optgroup></select></li></ul>"},
	}
	for _, c := range dropped {
		hstAssertRoundTripAndBalanced(t, noTable, c[0], c[1])
	}
	// With the table kept and only the cell dropped, the option's select
	// lands where a browser foster-parents one written in a row: before the
	// table, not inside the row.
	noCell := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tbody", "tr", "td", "select", "option",
			"optgroup").
		AllowWithoutAttributes("table", "tbody", "tr", "td", "select",
			"option", "optgroup"))
	droppedCell := [][2]string{
		{"<table><th><option>tail",
			"<table><tbody><tr></tr></tbody></table>" +
				"<select><option>tail</option></select>"},
		{"<table><th><optgroup>tail",
			"<table><tbody><tr></tr></tbody></table>" +
				"<select><optgroup>tail</optgroup></select>"},
		{"<table><caption><option>tail",
			"<table></table><select><option>tail</option></select>"},
		{"<table><td><table><th><option>tail",
			"<table><tbody><tr><td><table><tbody><tr></tr></tbody></table>" +
				"<select><option>tail</option></select></td></tr></tbody></table>"},
		// The balancer closes a table it pushes content out of, as it does
		// for text, so the cell after the option opens a new one.
		{"<table><th><option>a</option></th><td>b",
			"<table><tbody><tr></tr></tbody></table>" +
				"<select><option>a</option></select>" +
				"<table><tbody><tr><td>b</td></tr></tbody></table>"},
		// The dropped cell still closes what it holds at its end tag: text
		// after it is not the option's.
		{"<table><th><option>a</th>b",
			"<table><tbody><tr></tr></tbody></table>" +
				"<select><option>a</option></select>b"},
		// Dropped elements between the cell and the option, of any name,
		// change nothing: the output's row is what holds the option.
		{"<table><th><p><option>a</p></th>b",
			"<table><tbody><tr></tr></tbody></table>" +
				"<select><option>a</option></select>b"},
		{"<table><th><b><i><optgroup>a",
			"<table><tbody><tr></tr></tbody></table>" +
				"<select><optgroup>a</optgroup></select>"},
		{"<table><th><template><option>a",
			"<table><tbody><tr></tr></tbody></table>" +
				"<select><option>a</option></select>"},
	}
	for _, c := range droppedCell {
		hstAssertRoundTripAndBalanced(t, noCell, c[0], c[1])
		// The select is not in table structure in the output's browser tree.
		parent := hstP5BrowserParentOf(t, noCell.Sanitize(c[0]), "select")
		hstAssertTrue(t, parent == "" || parent == "td", c[0]+" -> "+parent)
	}
	// A kept element around the table holds the select; a kept formatting
	// element inside the dropped cell is pushed out with it; a row holding
	// the option directly is closed and the next row opens a new table.
	names3 := []string{
		"table", "tbody", "tr", "td", "select", "option", "div", "b"}
	noCellDiv := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(names3...).AllowWithoutAttributes(names3...))
	around := [][2]string{
		{"<div><table><th><option>x",
			"<div><table><tbody><tr></tr></tbody></table>" +
				"<select><option>x</option></select></div>"},
		{"<table><th><b><option>x</b>y</th>z",
			"<table><tbody><tr></tr></tbody></table>" +
				"<b><select><option>x</option></select></b>yz"},
		{"<table><tr><option>x</option></tr><tr><td>y",
			"<table><tbody><tr></tr></tbody></table>" +
				"<select><option>x</option></select>" +
				"<table><tbody><tr><td>y</td></tr></tbody></table>"},
	}
	for _, c := range around {
		hstAssertRoundTripAndBalanced(t, noCellDiv, c[0], c[1])
	}
	hstAssertEqual(t,
		"div", hstP5BrowserParentOf(t, noCellDiv.Sanitize("<div><table><th><option>x"),
			"select"))
	// Hostile content around the wrapper is still removed, with the link
	// allowed so that its URL is what the policy judges.
	withLinks := p.And(hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a").AllowAttributes("href").OnElements("a").
		AllowStandardURLProtocols().AllowWithoutAttributes("a")))
	hstAssertRoundTripAndBalanced(t,
		withLinks,
		"<span><option onmouseover=alert(1)>x</option>"+
			"<a href=javascript:alert(1)>y</a><a href=https://e/>z</a></span>",
		"<span><select><option>x</option><a>y</a>"+
			"<a href=\"https://e/\">z</a></select></span>")
	hostile := [][2]string{
		{"<span><option onmouseover=alert(1)>x</option>" +
			"<a href=javascript:alert(1)>y</a></span>",
			"<span><select><option>x</option>y</select></span>"},
		{"<var><li onclick=alert(1)><img src=x onerror=alert(1)>x",
			"<var><ul><li>x</li></ul></var>"},
		{"<table><th><option>x</option></th></tr></table>" +
			"<script>alert(1)</script>y",
			"<table><tbody><tr><th><select><option>x</option></select></th>" +
				"</tr></tbody></table>y"},
		// The style inside an option is text there, as CVE-2021-42575
		// requires, with or without the select around it.
		{"<u><option>x<style>*{}</style>y",
			"<u><select><option>x*{}y</option></select></u>"},
	}
	for _, c := range hostile {
		hstAssertRoundTripAndBalanced(t, p, c[0], c[1])
		hstAssertFalse(t, strings.Contains(p.Sanitize(c[0]), "alert"), c[0])
	}
}

// TestOptionUnderDroppedTemplateGetsItsSelect covers items 9 and 2 of #492.
// A template holds an option directly, as a browser's does, so no select is
// implied for one there.  A template the policy dropped or renamed
// establishes none in the output, though: the option is judged where the
// template was, or in what it became, and gets its select there; inside
// table structure the select is pushed out of the table, as a browser
// foster-parents one written in a row.
func TestOptionUnderDroppedTemplateGetsItsSelect(t *testing.T) {
	names := []string{
		"u", "table", "tbody", "tr", "td", "select", "option", "optgroup"}
	noTemplate := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(names...).AllowWithoutAttributes(names...))
	dropped := [][2]string{
		{"<u><template><option>x", "<u><select><option>x</option></select></u>"},
		{"<u><template><optgroup>x",
			"<u><select><optgroup>x</optgroup></select></u>"},
		{"<table><template><option>x",
			"<table></table><select><option>x</option></select>"},
		{"<table><tr><template><option>x",
			"<table><tbody><tr></tr></tbody></table>" +
				"<select><option>x</option></select>"},
		{"<table><td><template><option>x",
			"<table><tbody><tr><td><select><option>x</option></select></td></tr>" +
				"</tbody></table>"},
		{"<table><template><option>a</option></template><tr><td>b",
			"<table></table><select><option>a</option></select>" +
				"<table><tbody><tr><td>b</td></tr></tbody></table>"},
		// Hostile content in the option's place is still removed.  The script
		// inside the option is text there, as CVE-2021-42575 requires of a
		// literal-content element in a select, with or without the template.
		{"<u><template><option onclick=alert(1)>x<script>alert(1)</script>y",
			"<u><select><option>xalert(1)y</option></select></u>"},
		{"<table><template><option>x<img src=x onerror=alert(1)>",
			"<table></table><select><option>x</option></select>"},
	}
	for _, c := range dropped {
		hstAssertRoundTripAndBalanced(t, noTemplate, c[0], c[1])
		out := noTemplate.Sanitize(c[0])
		hstAssertFalse(t,
			strings.Contains(out, "<script") || strings.Contains(out, "onclick") ||
				strings.Contains(out, "onerror") || strings.Contains(out, "<img"),
			out)
		parent := hstP5BrowserParentOf(t, out, "select")
		hstAssertTrue(t,
			parent == "" || parent == "td" || parent == "u",
			c[0]+" -> "+parent)
	}
	// A template the policy renames is the option's container in the output,
	// and holds no option directly; renamed into table structure it cannot
	// hold the select either, which is pushed out of it.
	renamed := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(names...).AllowWithoutAttributes(names...).
		AllowElementsWithPolicy(hstRenamingPolicy("u"), "template"))
	hstAssertRoundTripAndBalanced(t,
		renamed, "<u><template><option>x",
		"<u><u><select><option>x</option></select></u></u>")
	renamedToTable := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(names...).AllowWithoutAttributes(names...).
		AllowElementsWithPolicy(hstRenamingPolicy("table"), "template"))
	hstAssertRoundTripAndBalanced(t,
		renamedToTable, "<u><template><option>x",
		"<u><table></table><select><option>x</option></select></u>")
	// With the cell dropped as well, the select is pushed out of the table
	// that remains.
	noCellNoTemplate := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tbody", "tr", "select", "option").
		AllowWithoutAttributes("table", "tbody", "tr", "select", "option"))
	hstAssertRoundTripAndBalanced(t,
		noCellNoTemplate, "<table><td><template><option>x",
		"<table><tbody><tr></tr></tbody></table>"+
			"<select><option>x</option></select>")
	// Under a select, the template sits above the select's own logical list
	// item, which has no output; the option's judgment stops there.
	inSelect := [][2]string{
		{"<select><template><option>x",
			"<select><template><option>x</option></template></select>"},
		{"<select><optgroup><template><option>x",
			"<select><optgroup><template><option>x</option></template>" +
				"</optgroup></select>"},
	}
	pOnly := hstFactory(t, NewHTMLPolicyBuilder().AllowElements("p"))
	selectOnly := hstFactory(t, NewHTMLPolicyBuilder().AllowElements("select", "option"))
	for _, c := range inSelect {
		hstAssertRoundTripAndBalanced(t, pOnly, c[0], "x")
		hstAssertRoundTripAndBalanced(t,
			selectOnly, c[0], "<select><option>x</option></select>")
		hstAssertRoundTripAndBalanced(t,
			Blocks.And(Tables), c[0], "x")
	}
	// A template the policy keeps still holds the option directly.
	withTemplate := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("u", "template", "select", "option"))
	hstAssertRoundTripAndBalanced(t,
		withTemplate, "<u><template><option>x",
		"<u><template><option>x</option></template></u>")
}

// TestListItemStartClosesTheOpenItemThroughFormatting is item 8 of #492.  A
// browser's list item start tag closes an open list item before it inserts
// the new one, walking down its stack past the formatting elements open
// inside that item, so the two items are siblings and the formatting is
// reconstructed inside the second.  The containment metadata answered the
// open formatting element with a fresh list inside it instead, and each item
// after the first nested one level deeper.  The walk stops at the elements
// the parsing algorithm calls special, other than address, div and p.
func TestListItemStartClosesTheOpenItemThroughFormatting(t *testing.T) {
	names := []string{
		"ul", "ol", "li", "b", "i", "a", "span", "div", "p", "h1", "form",
		"table", "tbody", "tr", "td", "template"}
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(names...).AllowWithoutAttributes(names...).
		AllowAttributes("href").OnElements("a").AllowStandardURLProtocols())
	// Each output parses to the browser tree of its input.
	faithful := [][2]string{
		{"<ul><li><b>x<li>y",
			"<ul><li><b>x</b></li><li><b>y</b></li></ul>"},
		{"<ul><li><b><i>x<li>y",
			"<ul><li><b><i>x</i></b></li><li><b><i>y</i></b></li></ul>"},
		{"<ul><li><b>x<li>y<li>z",
			"<ul><li><b>x</b></li><li><b>y</b></li><li><b>z</b></li></ul>"},
		{"<ol><li><b>x<li>y</b>z",
			"<ol><li><b>x</b></li><li><b>y</b>z</li></ol>"},
		// The rule steps over address, div and p, and over anything that is
		// not special at all.
		{"<ul><li><div>d<li>y",
			"<ul><li><div>d</div></li><li>y</li></ul>"},
		{"<ul><li><p>p<li>y", "<ul><li><p>p</p></li><li>y</li></ul>"},
		{"<ul><li><span>s<li>y",
			"<ul><li><span>s</span></li><li>y</li></ul>"},
		{"<ul><li><b>x<div>d<li>y",
			"<ul><li><b>x<div>d</div></b></li><li><b>y</b></li></ul>"},
		// Formatting the input closed is not resumed, and an item with none
		// open was already closed by the containment rules.
		{"<ul><li><b>x</b><li>y", "<ul><li><b>x</b></li><li>y</li></ul>"},
		{"<ul><li>x<li>y", "<ul><li>x</li><li>y</li></ul>"},
		// A list inside the item is special, so the walk stops there and the
		// new item goes into that list, as it does in a browser.
		{"<ul><li><b>x<ul><li>y",
			"<ul><li><b>x<ul><li>y</li></ul></b></li></ul>"},
	}
	for _, c := range faithful {
		hstAssertRoundTripAndBalanced(t, p, c[0], c[1])
		hstAssertEqual(t, hstParseAsBrowser(t, c[0]), hstParseAsBrowser(t, c[1]), c[0])
	}
	// Hostile content around the item is still removed.  The tree is the
	// input's but for the attributes the policy dropped, so a link resumed
	// inside the new item carries no URL, as a resumed element carries none
	// anywhere else.
	hostile := [][2]string{
		{"<ul><li><a href=javascript:alert(1)>x<li>y",
			"<ul><li><a>x</a></li><li><a>y</a></li></ul>"},
		{"<ul><li><b onmouseover=alert(1)>x<li>y",
			"<ul><li><b>x</b></li><li><b>y</b></li></ul>"},
		{"<ul><li><a href=\"https://e/\">x<li>y",
			"<ul><li><a href=\"https://e/\">x</a></li><li><a>y</a></li></ul>"},
	}
	for _, c := range hostile {
		hstAssertRoundTripAndBalanced(t, p, c[0], c[1])
		hstAssertFalse(t, strings.Contains(p.Sanitize(c[0]), "alert"), c[0])
	}
	// A script between the items is text the policy removes, and the item
	// still closes.
	hstAssertRoundTripAndBalanced(t,
		p, "<ul><li><b>x<li><script>alert(1)</script>y",
		"<ul><li><b>x</b></li><li><b>y</b></li></ul>")
	// An element the parsing algorithm calls special, other than the three
	// the rule steps over, stops the walk: the item stays open and the new
	// one goes inside it, where a browser puts it too.  A browser needs no
	// list around an item, and this receiver never emits one without.
	barriers := [][2]string{
		{"<ul><li><h1>h<li>y",
			"<ul><li><h1>h<ul><li>y</li></ul></h1></li></ul>"},
		{"<ul><li><form>f<li>y",
			"<ul><li><form>f<ul><li>y</li></ul></form></li></ul>"},
		{"<ul><li><template><li>y",
			"<ul><li><template><ul><li>y</li></ul></template></li></ul>"},
	}
	for _, c := range barriers {
		hstAssertRoundTripAndBalanced(t, p, c[0], c[1])
	}
	// A table this receiver closed in the output to put the item in front of
	// it bounds nothing a browser reading that output can see, so the item
	// closes.  A browser reading the input keeps the item open and
	// foster-parents the new one into it; the output would not say so.
	hstAssertRoundTripAndBalanced(t,
		p, "<ul><li><b>x<table><li>y",
		"<ul><li><b>x<table></table></b></li><li><b>y</b></li></ul>")
	// Formatting is not reconstructed inside an element whose content the
	// lexer reads as text: a browser reconstructs it around that element, and
	// a tag written inside it would come out as its text.  It resumes for the
	// text that follows the element, as a browser reconstructs it there.
	rawNames := []string{
		"ul", "li", "em", "span", "textarea", "style", "x-y", "textArea"}
	raw := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(rawNames...).AllowWithoutAttributes(rawNames...).
		AllowTextIn("style", "textarea"))
	rawText := [][2]string{
		{"<span><li><em>x<li><textarea>tail",
			"<span><ul><li><em>x</em></li><li><textarea>tail</textarea></li>" +
				"</ul></span>"},
		{"<span><li><em>x<li><style>tail",
			"<span><ul><li><em>x</em></li><li><style>tail</style></li></ul>" +
				"</span>"},
		// and again for the text that follows it, as a browser does.
		{"<span><li><em>x<li><textarea>tail</textarea>after",
			"<span><ul><li><em>x</em></li><li><textarea>tail</textarea>" +
				"<em>after</em></li></ul></span>"},
		// One forwarded under a name this receiver does not recognize, an
		// SVG-cased textArea, has no entry on the stack, and a browser reading
		// the output lowercases it and reads its content as text, so nothing
		// is resumed inside it, at any depth.
		{"<span><li><em>x<li><textArea>tail",
			"<span><ul><li><em>x</em></li><li><textArea>tail</textArea></li>" +
				"</ul></span>"},
		{"<span><li><em>x<li><x-y><textArea>tail",
			"<span><ul><li><em>x</em></li><li><x-y><textArea>tail</textArea>" +
				"</x-y></li></ul></span>"},
		{"<span><li><em>x<li><textArea><x-y>tail",
			"<span><ul><li><em>x</em></li><li><textArea><x-y>tail</x-y>" +
				"</textArea></li></ul></span>"},
		// Hostile content in that text stays text: the element the lexer read
		// as raw text is written back with its content escaped.
		{"<span><li><em>x<li><textarea>&lt;/textarea&gt;&lt;img src=x " +
			"onerror=alert(1)&gt;",
			"<span><ul><li><em>x</em></li><li><textarea>&lt;/textarea&gt;" +
				"&lt;img src&#61;x onerror&#61;alert(1)&gt;</textarea></li></ul>" +
				"</span>"},
		{"<span><li><em>x<li><style>&lt;/style&gt;&lt;script&gt;alert(1)" +
			"&lt;/script&gt;",
			"<span><ul><li><em>x</em></li><li><style>&lt;/style&gt;&lt;script" +
				"&gt;alert(1)&lt;/script&gt;</style></li></ul></span>"},
	}
	for _, c := range rawText {
		hstAssertRoundTripAndBalanced(t, raw, c[0], c[1])
		out := raw.Sanitize(c[0])
		hstAssertFalse(t, strings.Contains(out, "<img") || strings.Contains(out, "<script"), out)
	}
	// The elements a browser reads as text are siblings of the formatting it
	// reconstructs, so with the list written out the output parses to the
	// input's tree.
	hstAssertRoundTripAndBalanced(t,
		raw, "<ul><li><em>x<li><textarea>tail</textarea>after",
		"<ul><li><em>x</em></li><li><textarea>tail</textarea>"+
			"<em>after</em></li></ul>")
	hstAssertEqual(t,
		hstParseAsBrowser(t, "<ul><li><em>x<li><textarea>tail</textarea>after"),
		hstParseAsBrowser(t,
			"<ul><li><em>x</em></li><li><textarea>tail</textarea>"+
				"<em>after</em></li></ul>"))
	// Formatting is reconstructed only where it needs no wrapper implied
	// under the container: after the items close, a list holds the style
	// directly, as a browser puts it there with no formatting around it.
	listRaw := []string{"ul", "ol", "li", "b", "style", "script"}
	listRawPolicy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(listRaw...).AllowWithoutAttributes(listRaw...).
		AllowTextIn("style", "script"))
	bareList := [][2]string{
		{"<ul><li><b>x<li>y</li><style>s</style>",
			"<ul><li><b>x</b></li><li><b>y</b></li><style>s</style></ul>"},
		{"<ol><li><b>x<li>y</li><script>t</script>",
			"<ol><li><b>x</b></li><li><b>y</b></li><script>t</script></ol>"},
	}
	for _, c := range bareList {
		hstAssertRoundTripAndBalanced(t, listRawPolicy, c[0], c[1])
		hstAssertEqual(t, hstParseAsBrowser(t, c[0]), hstParseAsBrowser(t, c[1]), c[0])
	}
	// One list item after another over the same open formatting element
	// keeps at most three of a name, as a browser's Noah's Ark clause does,
	// so the output stays a constant factor of the input.
	manyItems := "<ul>" + strings.Repeat("<li><b>", 400)
	amplified := Blocks.And(Formatting).Sanitize(manyItems)
	hstAssertTrue(t,
		len(amplified) < len(manyItems)*8,
		fmt.Sprintf("%d from %d", len(amplified), len(manyItems)))
	// An element the policy dropped bounds nothing in the output, so the item
	// closes there as it does on the output's own next pass.
	itemsOnly := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("li", "div", "b").AllowWithoutAttributes("li", "div", "b"))
	hstAssertRoundTripAndBalanced(t,
		itemsOnly, "<li><div><h1><li>", "<li><div></div></li><li></li>")
	hstAssertRoundTripAndBalanced(t,
		itemsOnly, "<li><div><template><li>", "<li><div></div></li><li></li>")
	// A name the specification calls special but Chrome does not is not a
	// barrier here either, as TestDialogElementCategoryIsNotReliedOn says.
	dialogNames := []string{"ul", "li", "dialog", "b"}
	dialogs := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(dialogNames...).AllowWithoutAttributes(dialogNames...))
	hstAssertRoundTripAndBalanced(t,
		dialogs, "<ul><li><dialog>d<li>y",
		"<ul><li><dialog>d</dialog></li><li>y</li></ul>")
	hstAssertEqual(t,
		hstParseAsBrowser(t, "<ul><li><dialog>d<li>y"),
		hstParseAsBrowser(t, "<ul><li><dialog>d</dialog></li><li>y</li></ul>"))
	// The item a select keeps for content it cannot hold is none of the
	// input's, so an item written in a select is unaffected.
	selectNames := []string{"select", "option", "ul", "li"}
	selects := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(selectNames...).AllowWithoutAttributes(selectNames...))
	hstAssertRoundTripAndBalanced(t,
		selects, "<select>x<li>y", "<select>x</select><ul><li>y</li></ul>")
	hstAssertRoundTripAndBalanced(t,
		selects, "<select><option>x<li>y",
		"<select><option>x<ul><li>y</li></ul></option></select>")
	// The issue's shape, and an item whose formatting the policy drops.
	blocksFormatting := Blocks.And(Formatting)
	hstAssertRoundTripAndBalanced(t,
		blocksFormatting, "<math><b>x</math><li>y<li>z",
		"<b>x</b><ul><li><b>y</b></li><li><b>z</b></li></ul>")
	hstAssertRoundTripAndBalanced(t,
		blocksFormatting, "<ul><li><b>x<li>y</li></ul>after",
		"<ul><li><b>x</b></li><li><b>y</b></li></ul><b>after</b>")
	hstAssertRoundTripAndBalanced(t,
		Blocks, "<ul><li><b>x<li>y<li>z",
		"<ul><li>x</li><li>y</li><li>z</li></ul>")
}

// TestListItemStartKeepsSelectAndForeignOutputContexts: the item-start walk
// keeps the output contexts that make it a fixed point.
func TestListItemStartKeepsSelectAndForeignOutputContexts(t *testing.T) {
	droppedSelect := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("ul", "li", "script").
		AllowWithoutAttributes("ul", "li", "script").
		AllowTextIn("script"))
	hstAssertRoundTripAndBalanced(t,
		droppedSelect,
		"<li><optgroup><li><script><hr>",
		"<ul><li><ul><li><script></script>&lt;hr&gt;</li></ul></li></ul>")

	// A breakout start has already popped the input's SVG root, but closing
	// the output item across that still-open root would turn foreign PCDATA
	// into HTML raw text.  Keep the stable foreign path, where hostile tags
	// remain escaped text rather than live markup.
	foreignRaw := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("ul", "li", "u", "label", "svg", "script", "style").
		AllowWithoutAttributes(
			"ul", "li", "u", "label", "svg", "script", "style").
		AllowTextIn("script", "style"))
	hostile := "<li><u><Svg><li><script></col><img src=x onerror=alert(1)></script>"
	escaped := "<ul><li><u><svg><ul><li><script>&lt;/col&gt;&lt;img src&#61;x " +
		"onerror&#61;alert(1)&gt;</script></li></ul></svg></u></li></ul>"
	hstAssertRoundTripAndBalanced(t, foreignRaw, hostile, escaped)
	hstAssertFalse(t, strings.Contains(foreignRaw.Sanitize(hostile), "<img"))
	hstAssertRoundTripAndBalanced(t,
		foreignRaw,
		"<li><label><svg><li><svg></svg><style></ul>",
		"<ul><li><label><svg><ul><li><svg></svg><style>&lt;/ul&gt;</style>"+
			"</li></ul></svg></label></li></ul>")

	// The reduced li/option residual from #494 stays nested on both passes.
	itemsAndOptions := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("li", "option").
		AllowWithoutAttributes("li", "option"))
	hstAssertRoundTripAndBalanced(t,
		itemsAndOptions,
		"<ul><option></select><strong><textArea><li>",
		"<li><option></option><li></li></li>")
}

// TestTablePartUnderDroppedTemplateGetsItsTable is item 2 of #492.  A
// template holds a caption or column group directly, so the containment
// metadata implies no table for one there.  A template the policy dropped
// establishes no template in the output, though: the caption landed where
// the template was, as an orphan that a browser drops, and the next pass
// gave it its table.  Parts under a dropped template are now judged where
// the template was.  The prepackaged policies drop the template and, being
// allowed no table they did not emit before, the output narrows to what the
// second pass already gave.
func TestTablePartUnderDroppedTemplateGetsItsTable(t *testing.T) {
	tables := [][2]string{
		{"<template><ul><math><caption>TEXT",
			"<table><caption>TEXT</caption></table>"},
		{"<template><ul><svg><caption>TEXT",
			"<table><caption>TEXT</caption></table>"},
		{"<template><ul><math><colgroup>TEXT",
			"<table><colgroup></colgroup></table>TEXT"},
		{"<template><caption>TEXT", "<table><caption>TEXT</caption></table>"},
		{"<template><caption>TEXT</caption></template>after",
			"<table><caption>TEXT</caption></table>after"},
		{"<div><template><caption>TEXT",
			"<table><caption>TEXT</caption></table>"},
		// A cell already got its table there.
		{"<template><ul><math><td>TEXT",
			"<table><tbody><tr><td>TEXT</td></tr></tbody></table>"},
		// Hostile content in the caption's place is still removed.
		{"<template><caption><script>alert(1)</script>TEXT",
			"<table><caption>TEXT</caption></table>"},
		{"<template><ul><math><caption onclick=alert(1)>TEXT" +
			"<img src=x onerror=alert(1)>",
			"<table><caption>TEXT</caption></table>"},
	}
	for _, c := range tables {
		hstAssertRoundTripAndBalanced(t, Tables, c[0], c[1])
	}
	// A dropped template bounds no table scope in the output: a part under it
	// inside an open table returns to that table, closing a column group, or
	// comes out beside the table it was written in.
	inTable := [][2]string{
		{"<table><colgroup><template><caption>x",
			"<table><colgroup></colgroup></table>" +
				"<table><caption>x</caption></table>"},
		// A col is held directly by a template too.
		{"<template><col>x", "<table><colgroup><col /></colgroup></table>x"},
		{"<template><ul><math><col>x",
			"<table><colgroup><col /></colgroup></table>x"},
		{"<template><colgroup onclick=alert(1)><col onclick=alert(1)>" +
			"<script>alert(1)</script>x",
			"<table><colgroup><col /></colgroup></table>x"},
	}
	for _, c := range inTable {
		hstAssertRoundTripAndBalanced(t, Tables, c[0], c[1])
		hstAssertFalse(t,
			strings.Contains(Tables.Sanitize(c[0]), "alert"), c[0])
	}
	// Text the policy disallows in the template is not the caption's, so the
	// caption a template holds keeps its own, as it does without one.
	noTemplateText := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "caption", "colgroup", "col").
		DisallowTextIn("template"))
	hstAssertEqual(t,
		noTemplateText.Sanitize("<caption>TEXT</caption>"),
		noTemplateText.Sanitize("<template><caption>TEXT</caption></template>"))
	hstAssertRoundTripAndBalanced(t,
		noTemplateText, "<template><caption>TEXT</caption></template>",
		"<table><caption>TEXT</caption></table>")
	// A part under a template inside an open table keeps the shape it has
	// without this change: the template still bounds table scope, so the part
	// stays in the cell and the next pass moves it, as it does on its own.
	// Closing that scope belongs with the other five scans that read it, not
	// with this rule.
	inCell := []string{
		"<table><tr><td><template><caption>x",
		"<table><tbody><template><colgroup>x",
	}
	for _, c := range inCell {
		hstAssertEqual(t,
			Tables.Sanitize(strings.ReplaceAll(c, "<template>", "")),
			Tables.Sanitize(Tables.Sanitize(c)),
			c)
	}
	// The template's place is judged in the output: under a container the
	// policy drops, the caption gets its table there.  A formatting element
	// the policy keeps is the container in the output, and a browser drops a
	// caption written in one, so that shape is left as it was,
	// non-idempotent here as on its own.
	hstAssertRoundTripAndBalanced(t,
		Tables, "<u><template><caption>TEXT",
		"<table><caption>TEXT</caption></table>")
	hstAssertRoundTripAndBalanced(t,
		Tables, "<u><template><colgroup>TEXT",
		"<table><colgroup></colgroup></table>TEXT")
	// A policy that drops the caption itself still gets the part's table, as
	// it does for a bare caption without the template.
	noCaption := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tr", "td", "u"))
	hstAssertEqual(t,
		noCaption.Sanitize("<caption>x"),
		noCaption.Sanitize("<template><caption>x"))
	hstAssertRoundTripAndBalanced(t,
		noCaption, "<template><caption>x", "<table></table>x")
	// With the list kept, the caption's table stands beside the list, as it
	// does for <ul><caption> without the template.
	hstAssertRoundTripAndBalanced(t,
		Blocks.And(Tables),
		"<template><ul><math><caption>TEXT",
		"<ul><li></li></ul><table><caption>TEXT</caption></table>")
	// A template the policy keeps still holds the caption directly, as a
	// browser does.
	withTemplate := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "caption", "colgroup", "template"))
	hstAssertRoundTripAndBalanced(t,
		withTemplate, "<template><caption>TEXT</caption></template>",
		"<template><caption>TEXT</caption></template>")
	hstAssertEqual(t,
		hstParseAsBrowser(t, "<template><caption>TEXT</caption></template>"),
		hstParseAsBrowser(t,
			withTemplate.Sanitize("<template><caption>TEXT</caption></template>")))
}

// hstP6TagRecorder is a change listener that records the names of discarded
// tags, and, if recordAttributes is set, the names of the tags whose
// attributes were discarded.
type hstP6TagRecorder struct {
	NopHTMLChangeListener
	discarded        *[]string
	recordAttributes bool
}

// DiscardedTag records elementName.
func (r hstP6TagRecorder) DiscardedTag(_ any, elementName string) {
	*r.discarded = append(*r.discarded, elementName)
}

// DiscardedAttributes records tagName if the recorder records attributes.
func (r hstP6TagRecorder) DiscardedAttributes(_ any, tagName string, _ ...string) {
	if r.recordAttributes {
		*r.discarded = append(*r.discarded, tagName)
	}
}

// TestForeignRootContentDoesNotGetTheListsImpliedItem covers item 1 of #492.
// The list item the containment metadata implies for a list's content landed
// inside a forwarded SVG or MathML root: the root has no entry on the
// balancer's stack, so the text or foreign child inside it was judged against
// the list below.  An li is a breakout name, so a browser popped the root at
// the item and read the SVG textarea or a that followed as an HTML element.
// Content a browser inserts into a foreign node, or into an integration point
// inside the root, is now neither wrapped nor closed for by the HTML entries
// below the root.  The policy also judges an element the output parser
// inserts as SVG or MathML as one, so the text of a foreign tbody no longer
// depends on that item's gate.
func TestForeignRootContentDoesNotGetTheListsImpliedItem(t *testing.T) {
	names := []string{
		"ul", "ol", "li", "svg", "math", "textarea", "a", "mi", "mtext",
		"table", "tbody", "tr", "td", "b", "p", "div", "span",
		"foreignObject", "desc", "path", "select"}
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(names...).AllowWithoutAttributes(names...))
	// Each is its own output and parses to the tree a browser builds from
	// it, namespaces included.
	faithful := []string{
		// The reproductions from the issue.
		"<ul><svg><textarea>x</textarea></svg></ul>",
		"<ul><svg><a>x</a></svg></ul>",
		"<ul><math><mi>x</mi></math></ul>",
		"<ul><svg><tbody>D</tbody></svg></ul>",
		// Text in the root itself, in an ordered list, after an item, in a
		// nested block, and in an integration point, with HTML inside it.
		"<ul><svg>x</svg></ul>",
		"<ul><math>x</math></ul>",
		"<ol><svg><textarea>x</textarea></svg></ol>",
		"<ul><li>a</li><svg><textarea>x</textarea></svg></ul>",
		"<div><ul><svg><textarea>x</textarea></svg></ul></div>",
		"<ul><svg><desc>x</desc></svg></ul>",
		"<ul><svg><foreignObject>x</foreignObject></svg></ul>",
		"<ul><svg><foreignObject><li>x</li></foreignObject></svg></ul>",
		"<ul><svg><foreignObject><p>a</p><div>b</div></foreignObject></svg>" +
			"</ul>",
		"<ol><math><mtext>x</mtext></math></ol>",
		"<ul><math><mi>x</mi>y</math></ul>",
		// Foreign children with HTML names, and text after one.
		"<ul><svg><a>x</a>y</svg></ul>",
		"<ul><svg><tr><td>x</td></tr></svg></ul>",
		"<ul><svg><select>x</select></svg></ul>",
		// Other HTML containers below the root: a paragraph, a link, a
		// cell, a select.
		"<p><svg><a>x</a></svg>y</p>",
		"<a><svg><a>x</a></svg></a>",
		"<table><tbody><tr><td>a<svg>x</svg>b</td></tr></tbody></table>",
		"<select><svg>x</svg></select>",
	}
	for _, c := range faithful {
		// Unchanged, so the output's browser tree is the input's, namespaces
		// included; the foreign children are pinned as foreign below.
		hstAssertRoundTripAndBalanced(t, p, c, c)
	}
	hstAssertForeignInOutput(t,
		p, "<ul><svg><textarea>x</textarea><a>y</a></svg></ul>",
		[]string{"textarea", "a"})
	hstAssertForeignInOutput(t,
		p, "<ul><math><mi>x</mi><mtext>y</mtext></math></ul>",
		[]string{"mi", "mtext"})
	hstAssertForeignInOutput(t,
		p, "<ul><svg><tr><td>x</td></tr></svg></ul>", []string{"tr", "td"})
	// Unclosed forms reach the same outputs, with the input's tree.
	unclosed := [][2]string{
		{"<ul><svg><tbody>D", "<ul><svg><tbody>D</tbody></svg></ul>"},
		{"<svg><tbody>D", "<svg><tbody>D</tbody></svg>"},
		{"<ul><svg><foreignObject><p>a<div>b",
			"<ul><svg><foreignObject><p>a</p><div>b</div></foreignObject></svg>" +
				"</ul>"},
	}
	for _, c := range unclosed {
		hstAssertRoundTripAndBalanced(t, p, c[0], c[1])
		hstAssertEqual(t,
			hstParseAsBrowserWithNamespaces(t, c[0]),
			hstParseAsBrowserWithNamespaces(t, c[1]), c[0])
	}
	// Text after the root is the list's own content and gets the list's
	// item, as any text written directly in a list does.
	hstAssertRoundTripAndBalanced(t,
		p, "<ul><svg>x</svg>y</ul>", "<ul><svg>x</svg><li>y</li></ul>")
	hstAssertRoundTripAndBalanced(t,
		p, "<ul><svg><tbody>D</tbody>E</svg>F</ul>",
		"<ul><svg><tbody>D</tbody>E</svg><li>F</li></ul>")

	// Hostile content in those positions is still removed, and what is kept
	// stays in the namespace a browser gives it.
	hostile := [][2]string{
		{"<ul><svg><a href=javascript:alert(1)>x</a></svg></ul>",
			"<ul><svg><a>x</a></svg></ul>"},
		{"<ul><svg onload=alert(1)><a>x</a></svg></ul>",
			"<ul><svg><a>x</a></svg></ul>"},
		{"<ul><math><mi onclick=alert(1)>x</mi></math></ul>",
			"<ul><math><mi>x</mi></math></ul>"},
		{"<ul><svg><foreignObject><iframe src=javascript:alert(1)></iframe>" +
			"x</foreignObject></svg></ul>",
			"<ul><svg><foreignObject>x</foreignObject></svg></ul>"},
		// A browser reads the SVG textarea's content as markup and the lexer
		// as text; escaped, it stays text either way.
		{"<ul><svg><textarea><b onmouseover=alert(1)>x</b></textarea></svg>" +
			"</ul>",
			"<ul><svg><textarea>&lt;b onmouseover&#61;alert(1)&gt;x&lt;/b&gt;" +
				"</textarea></svg></ul>"},
	}
	for _, c := range hostile {
		hstAssertRoundTripAndBalanced(t, p, c[0], c[1])
		hstAssertFalse(t, strings.Contains(p.Sanitize(c[0]), "alert(1)>"), c[0])
	}
	// A breakout inside the root is the list's content again: a browser pops
	// the root at the img, and the text after it gets the list's item as
	// text written in the list does.
	hstAssertRoundTripAndBalanced(t,
		p, "<ul><svg><a>x</a><img src=x onerror=alert(1)>y</svg></ul>",
		"<ul><svg><a>x</a><li>y</li></svg></ul>")

	// The gate: a tbody the output parser inserts as an SVG element holds
	// text like any other foreign element, the author's disallowTextIn still
	// wins, an HTML table part still holds none, and style keeps its bar
	// wherever it is written.
	noTbodyText := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(names...).AllowWithoutAttributes(names...).
		DisallowTextIn("tbody"))
	hstAssertEqual(t,
		"<svg><tbody></tbody></svg>", noTbodyText.Sanitize("<svg><tbody>D"))
	hstAssertEqual(t,
		"<ul><svg><tbody></tbody></svg></ul>",
		noTbodyText.Sanitize("<ul><svg><tbody>D"))
	hstAssertEqual(t,
		"<table><tbody></tbody></table>D", p.Sanitize("<table><tbody>D"))
	withStyle := []string{"ul", "li", "svg", "style"}
	style := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(withStyle...).AllowWithoutAttributes(withStyle...))
	hstAssertEqual(t,
		"<svg><style></style></svg>",
		style.Sanitize("<svg><style>*{color:red}</style>"))
	hstAssertEqual(t,
		"<ul><svg><style></style></svg></ul>",
		style.Sanitize("<ul><svg><style>*{}</style></svg></ul>"))
	// A dropped foreign tbody leaves its text in the root.  A dropped root
	// leaves the content in the list, where the item applies.
	noTbody := []string{"ul", "li", "svg", "b"}
	dropTbody := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(noTbody...).AllowWithoutAttributes(noTbody...))
	hstAssertRoundTripAndBalanced(t,
		dropTbody, "<ul><svg><tbody>D", "<ul><svg>D</svg></ul>")
	noSvg := []string{"ul", "li", "a", "textarea"}
	dropSvg := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(noSvg...).AllowWithoutAttributes(noSvg...))
	hstAssertRoundTripAndBalanced(t,
		dropSvg, "<ul><svg><textarea>x</textarea></svg></ul>",
		"<ul><li><textarea>x</textarea></li></ul>")
	hstAssertRoundTripAndBalanced(t,
		dropSvg, "<ul><svg>x</svg></ul>", "<ul><li>x</li></ul>")
	// Nothing is implied, so a policy without li has nothing to report.
	var discarded []string
	listener := hstP6TagRecorder{discarded: &discarded, recordAttributes: true}
	ulSvg := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("ul", "svg", "textarea"))
	hstAssertEqual(t,
		"<ul><svg><textarea>x</textarea></svg></ul>",
		ulSvg.SanitizeWithListener(
			"<ul><svg><textarea>x</textarea></svg></ul>", listener, nil))
	if len(discarded) != 0 {
		t.Errorf("want nothing discarded, got %q", discarded)
	}
}

// TestForeignRootBoundaryFollowsBreakouts checks that the root is a boundary
// only while the output parser is still inside it.  A breakout element with a
// stack entry pops the root in both parsers, so what follows it is HTML flow
// again and a link below the root is still ended by a new link; a link inside
// an integration point, on the other hand, is out of the outer link's scope,
// as it is for a browser's adoption agency algorithm, and the formatting
// element around it is not closed and reopened.  After a breakout out of an
// inner root only, the next root out is the boundary.
func TestForeignRootBoundaryFollowsBreakouts(t *testing.T) {
	names := []string{
		"a", "svg", "div", "p", "span", "b", "li", "ul", "foreignObject",
		"math", "option", "select"}
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(names...).AllowWithoutAttributes(names...).
		AllowAttributes("href").OnElements("a").
		AllowStandardURLProtocols())
	// A breakout, then a link: the outer link ends, as on main.
	breakouts := [][2]string{
		{"<a href=\"https://good/\"><svg><div>x<a href=\"https://evil/\">" +
			"click</a></div></svg></a>",
			"<a href=\"https://good/\"><svg><div>x</div></svg></a>" +
				"<a href=\"https://evil/\">click</a>"},
		{"<a href=\"https://good/\"><svg><p>x<a href=\"https://evil/\">" +
			"click</a></p></svg></a>",
			"<a href=\"https://good/\"><svg><p>x</p></svg></a>" +
				"<a href=\"https://evil/\">click</a>"},
		{"<a href=\"https://good/\"><svg><span>x<a href=\"https://evil/\">" +
			"click</a></span></svg></a>",
			"<a href=\"https://good/\"><svg><span>x</span></svg></a>" +
				"<a href=\"https://evil/\">click</a>"},
		{"<a href=\"https://good/\"><svg><b>x<a href=\"https://evil/\">" +
			"click</a></b></svg></a>",
			"<a href=\"https://good/\"><svg><b>x</b></svg></a>" +
				"<b><a href=\"https://evil/\">click</a></b>"},
		{"<p><svg><div>x", "<p><svg></svg></p><div>x</div>"},
	}
	for _, c := range breakouts {
		hstAssertRoundTripAndBalanced(t, p, c[0], c[1])
	}
	// Inside an integration point, and after a breakout out of an inner
	// root only: the output parses to the input's tree.
	faithful := []string{
		"<a><svg><foreignObject><b>x<a>y</a></b></foreignObject></svg></a>",
		"<a><svg><foreignObject><p>x<a>y</a></p></foreignObject></svg></a>",
		"<ul><svg><foreignObject><p>a<svg></svg></p><div>b</div>" +
			"</foreignObject></svg></ul>",
	}
	for _, c := range faithful {
		hstAssertRoundTripAndBalanced(t, p, c, c)
	}
	hstAssertRoundTripAndBalanced(t,
		p, "<ul><svg><foreignObject><p>a<svg><div>b",
		"<ul><svg><foreignObject><p>a<svg></svg></p><div>b</div>"+
			"</foreignObject></svg></ul>")
	hstAssertEqual(t,
		hstParseAsBrowserWithNamespaces(t, "<ul><svg><foreignObject><p>a<svg><div>b"),
		hstParseAsBrowserWithNamespaces(t,
			p.Sanitize("<ul><svg><foreignObject><p>a<svg><div>b")))
	// A breakout directly in a nested root inside an integration point lands
	// at the integration point, inside the outer root, with no item from
	// the list below.
	nested := []string{
		"<ul><svg><foreignObject><svg><div>b</div></svg></foreignObject>" +
			"</svg></ul>",
		"<ul><svg><foreignObject><b>x</b><svg><div>y</div></svg>" +
			"</foreignObject></svg></ul>",
	}
	for _, c := range nested {
		hstAssertRoundTripAndBalanced(t, p, c, c)
	}
	// An option that is a foreign element gets no select: an SVG option is
	// not an HTML option.  One inside HTML at an integration point does,
	// and the list below the root implies nothing for it.
	options := [][2]string{
		{"<svg><option>x</option></svg>", "<svg><option>x</option></svg>"},
		{"<ul><svg><option>x</option></svg></ul>",
			"<ul><svg><option>x</option></svg></ul>"},
		{"<ul><svg><foreignObject><b><option>x",
			"<ul><svg><foreignObject><b><select><option>x</option></select></b>" +
				"</foreignObject></svg></ul>"},
	}
	for _, c := range options {
		hstAssertRoundTripAndBalanced(t, p, c[0], c[1])
	}
	hstAssertForeignInOutput(t,
		p, "<ul><svg><option>x</option></svg></ul>", []string{"option"})
	hstAssertTrue(t,
		strings.Contains(hstParseAsBrowserWithNamespaces(t,
			p.Sanitize("<ul><svg><foreignObject><b><option>x")), "<select>"))
}

// TestTablePartUnderDroppedIntegrationPointStaysForeign: a table part at an
// integration point that the policy dropped is HTML in the input, where a
// browser ignores it, but its output would sit directly in the foreign root.
// An implied HTML table there would break out of the root in the output
// parser and turn every following SVG or MathML sibling into HTML.  The part
// is forwarded as the foreign element the output parser makes of it instead.
func TestTablePartUnderDroppedIntegrationPointStaysForeign(t *testing.T) {
	names := []string{
		"svg", "math", "tbody", "table", "a", "textarea", "tr", "td",
		"mtext", "ul", "li"}
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(names...).AllowWithoutAttributes(names...))
	cases := [][2]string{
		{"<svg><foreignObject><tbody></tbody></foreignObject><a>x</a>" +
			"<textarea>&lt;b&gt;y&lt;/b&gt;</textarea></svg>",
			"<svg><tbody></tbody><a>x</a><textarea>&lt;b&gt;y&lt;/b&gt;" +
				"</textarea></svg>"},
		{"<math><mi><tbody>x</tbody></mi><mtext>y</mtext></math>",
			"<math><tbody>x</tbody><mtext>y</mtext></math>"},
		{"<svg><foreignObject><tr><td>x</td></tr></foreignObject><a>y</a>" +
			"</svg>",
			"<svg><tr><td>x</td></tr><a>y</a></svg>"},
		{"<ul><svg><foreignObject><tbody>D</tbody></foreignObject></svg>" +
			"</ul>",
			"<ul><svg><tbody>D</tbody></svg></ul>"},
	}
	for _, c := range cases {
		hstAssertRoundTripAndBalanced(t, p, c[0], c[1])
		// The part and its siblings are foreign in the output's browser tree.
		hstAssertForeignInOutput(t, p, c[0], hstForeignNamesIn(c[1]))
	}
	// The part's stray end tag does not lose the input parser its context,
	// so a foreign sibling under a list still gets no list item; an HTML
	// element between the dropped integration point and the part changes
	// nothing, since the output decides; and a hostile sibling stays text.
	names2 := []string{
		"ul", "li", "svg", "tbody", "tr", "td", "a", "textarea", "section",
		"label"}
	q := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(names2...).AllowWithoutAttributes(names2...))
	siblings := [][2]string{
		{"<ul><svg><foreignObject><tbody>x</tbody></foreignObject><a>y</a>" +
			"</svg></ul>",
			"<ul><svg><tbody>x</tbody><a>y</a></svg></ul>"},
		{"<ul><svg><foreignObject><tr><td>x</td></tr></foreignObject>" +
			"<textarea>&lt;b&gt;z&lt;/b&gt;</textarea></svg></ul>",
			"<ul><svg><tr><td>x</td></tr><textarea>&lt;b&gt;z&lt;/b&gt;" +
				"</textarea></svg></ul>"},
		{"<svg><foreignObject><section><tbody>x</tbody></section>" +
			"</foreignObject><a>y</a></svg>",
			"<svg><section><tbody>x</tbody></section><a>y</a></svg>"},
		{"<svg><foreignObject><label><tr><td>x</td></tr></label>" +
			"</foreignObject><a>y</a></svg>",
			"<svg><label><tr><td>x</td></tr></label><a>y</a></svg>"},
		{"<ul><svg><foreignObject><tbody></tbody></foreignObject>" +
			"<textarea>&lt;img src=x onerror=alert(1)&gt;</textarea></svg></ul>",
			"<ul><svg><tbody></tbody><textarea>&lt;img src&#61;x onerror&#61;" +
				"alert(1)&gt;</textarea></svg></ul>"},
		// An HTML-named element at the dropped integration point is foreign
		// in the output, so it gets no list item either, and neither does
		// one inside a forwarded part.
		{"<ul><svg><foreignObject><textarea>x</textarea></foreignObject>" +
			"<a>y</a></svg></ul>",
			"<ul><svg><textarea>x</textarea><a>y</a></svg></ul>"},
		{"<ul><svg><foreignObject><tbody><a>y</a></tbody></foreignObject>" +
			"</svg></ul>",
			"<ul><svg><tbody><a>y</a></tbody></svg></ul>"},
		// The forwarded part's end tag pops an outer foreign node of the
		// same name through the integration point, as a browser's foreign
		// end-tag algorithm does, so the sibling after it is outside both.
		{"<svg><tbody><foreignObject><tbody>x</tbody><a>y</a></foreignObject>" +
			"</svg>",
			"<svg><tbody><tbody>x</tbody></tbody><a>y</a></svg>"},
	}
	for _, c := range siblings {
		hstAssertRoundTripAndBalanced(t, q, c[0], c[1])
		hstAssertForeignInOutput(t, q, c[0], hstForeignNamesIn(c[1]))
		hstAssertFalse(t, strings.Contains(q.Sanitize(c[0]), "<img"), c[0])
	}
	// An option there is a foreign option: no select, and a fixed point.
	r := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("ul", "li", "svg", "tbody", "option", "select").
		AllowWithoutAttributes("ul", "li", "svg", "tbody", "option", "select"))
	hstAssertRoundTripAndBalanced(t,
		r,
		"<ul><svg><foreignObject><tbody><option>x</option></tbody>"+
			"</foreignObject></svg></ul>",
		"<ul><svg><tbody><option>x</option></tbody></svg></ul>")
	hstAssertForeignInOutput(t,
		r, "<ul><svg><foreignObject><tbody><option>x</option></tbody>"+
			"</foreignObject></svg></ul>",
		[]string{"tbody", "option"})
}

// TestOnlyTablePartsKeepTextAsForeignElements checks that the text gate's
// relaxation for foreign elements reaches exactly the HTML names whose
// default is no text because a browser foster-parents text out of them: the
// table parts.  A void name holds no text anywhere, a breakout such as table
// is HTML in the output, and a literal-content name keeps its bar.
// Enumerated from the containment metadata so that regenerating the tables
// cannot widen it unnoticed.
func TestOnlyTablePartsKeepTextAsForeignElements(t *testing.T) {
	tables := htmlElementTablesGet()
	var relaxed []string
	for i, n := 0, tables.NElementTypes(); i < n; i++ {
		if tables.CanContainPlainText(i) {
			continue
		}
		name := tables.CanonNameForIndex(i)
		for _, root := range []string{"svg", "math"} {
			p := hstFactory(t, NewHTMLPolicyBuilder().
				AllowElements(root, name).AllowWithoutAttributes(root, name))
			out := p.Sanitize(
				"<" + root + "><" + name + ">D</" + name + "></" + root + ">")
			if strings.HasPrefix(out, "<"+root+"><"+name+">D") {
				relaxed = append(relaxed, root+":"+name)
			}
		}
	}
	want := []string{
		"svg:colgroup", "math:colgroup", "svg:tbody", "math:tbody",
		"svg:tfoot", "math:tfoot", "svg:thead", "math:thead",
		"svg:tr", "math:tr"}
	if !slices.Equal(want, relaxed) {
		t.Errorf("want %q\ngot  %q", want, relaxed)
	}
}

// TestChildrenOfADroppedForeignRootBesideATableAreKept: a foreign root that
// HTML rules foster-parent out of a table is dropped or renamed by the
// policy, and holds an element the policy keeps but this receiver does not
// recognize.  That child was judged a foreign breakout beside the pushed-out
// table and suppressed with everything in it, though with no foreign root in
// the output there is nothing to break out of: it is ordinary HTML beside the
// table, like its siblings, and lands where a browser puts the root.
func TestChildrenOfADroppedForeignRootBesideATableAreKept(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(
			"table", "tbody", "tfoot", "tr", "td", "colgroup", "col",
			"o:p", "foo", "b", "div"))
	before := "<table><tbody><tr></tr></tbody></table>"
	after := "<table><tbody><tr><td>y</td></tr></tbody></table>"
	cases := [][2]string{
		{"<table><tr><svg><o:p>x</o:p></svg><td>y",
			before + "<o:p>x</o:p>" + after},
		{"<table><tr><math><foo>x</foo></math><td>y",
			before + "<foo>x</foo>" + after},
		{"<table><tr><svg><g><foo>x</foo></g></svg><td>y",
			before + "<foo>x</foo>" + after},
		{"<table><tr><svg><foo>x</foo></svg><b>q</b><td>y",
			before + "<foo>x</foo><b>q</b>" + after},
		{"<table><tr><svg><foo><b>x</b></foo></svg><td>y",
			before + "<foo><b>x</b></foo>" + after},
		{"<table><tr><svg><foo>x", before + "<foo>x</foo>"},
		{"<table><svg><o:p>tail", "<table></table><o:p>tail</o:p>"},
		{"<table><tfoot><svg><o:p>tail</o:p></svg><tr><td>y",
			"<table><tfoot></tfoot></table><o:p>tail</o:p>" +
				"<table><tfoot><tr><td>y</td></tr></tfoot></table>"},
		{"<table><tr><svg><o:p onclick=alert(1)>x</o:p></svg><td>y",
			before + "<o:p>x</o:p>" + after},
	}
	for _, c := range cases {
		hstAssertRoundTripAndBalanced(t, p, c[0], c[1])
	}
	// The same when the root is renamed to an HTML element.
	renamed := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tbody", "tr", "td", "o:p", "div").
		AllowElementsWithPolicy(hstRenamingPolicy("div"), "svg"))
	hstAssertRoundTripAndBalanced(t,
		renamed, "<table><tr><svg><o:p>x</o:p></svg><td>y",
		before+"<div><o:p>x</o:p></div>"+after)
	// A root the policy keeps still carries its children with it.
	kept := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tbody", "tr", "td", "svg", "foo", "b"))
	hstAssertRoundTripAndBalanced(t,
		kept, "<table><tr><svg><foo>x</foo></svg><td>y",
		before+"<svg><foo>x</foo></svg>"+after)
}

// TestCellTextOfADroppedTableInAnIntegrationPointIsKept: a table the policy
// drops inside an SVG or MathML integration point has its rows and cells
// suppressed, since a browser reading the output drops them there, but their
// text still goes where the browser puts it.  The policy's fail-closed rule
// for text in a suppressed table part, meant for the renderer's lexical SVG
// nesting left open after an emitted breakout, also fired inside an
// integration point, where the root is still on the browser's stack and HTML
// rules apply, and deleted the cell text.
func TestCellTextOfADroppedTableInAnIntegrationPointIsKept(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(
			"svg", "foreignObject", "desc", "math", "mtext",
			"form", "tbody", "tr", "td", "p", "b", "div"))
	cases := [][2]string{
		{"<svg><foreignObject><table><form><tr><td>y</td></tr></table>",
			"<svg><foreignObject><form>y</form></foreignObject></svg>"},
		{"<svg><foreignObject><table><form>y<tr><td>z",
			"<svg><foreignObject><form>yz</form></foreignObject></svg>"},
		{"<svg><foreignObject><table><tbody><form><tr><td>y",
			"<svg><foreignObject><form>y</form></foreignObject></svg>"},
		{"<svg><foreignObject><table><tr><form><td>y</td></tr></table>z",
			"<svg><foreignObject><form>yz</form></foreignObject></svg>"},
		{"<svg><desc><table><form><tr><td>y",
			"<svg><desc><form>y</form></desc></svg>"},
		{"<math><mtext><table><form><tr><td>y</td></tr></table>",
			"<math><mtext><form>y</form></mtext></math>"},
		{"<svg><foreignObject><table><form><tr><td>y</td></tr></table>" +
			"</foreignObject></svg><p>after</p>",
			"<svg><foreignObject><form>y</form></foreignObject></svg>" +
				"<p>after</p>"},
		{"<svg><foreignObject><table><form action=x onsubmit=alert(1)>" +
			"<tr><td><p>para</p></td></tr></table>",
			"<svg><foreignObject><form><p>para</p></form></foreignObject>" +
				"</svg>"},
	}
	for _, c := range cases {
		hstAssertRoundTripAndBalanced(t, p, c[0], c[1])
	}
	// Outside an integration point the parts themselves survive, as before.
	hstAssertRoundTripAndBalanced(t,
		p, "<div><table><form><tr><td>y</td></tr></table>",
		"<div><form><tbody><tr><td>y</td></tr></tbody></form></div>")
	// A table the policy keeps is unchanged: the form is inserted and
	// popped in the table, as a browser does, and the cell keeps its text.
	tables := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(
			"svg", "foreignObject", "table", "form", "tbody", "tr", "td"))
	input := "<svg><foreignObject><table><form><tr><td>y</td></tr>" +
		"</table>"
	out := "<svg><foreignObject><table><form></form><tbody><tr><td>y" +
		"</td></tr></tbody></table></foreignObject></svg>"
	hstAssertRoundTripAndBalanced(t, tables, input, out)
	hstAssertEqual(t, hstParseAsBrowser(t, input), hstParseAsBrowser(t, out), input)
}

// TestTextAfterDroppedTableWithIgnoredSecondFormIsKept: an ignored second
// form must not make text after a dropped table vanish.
func TestTextAfterDroppedTableWithIgnoredSecondFormIsKept(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(
			"svg", "foreignObject", "math", "mtext", "form", "tr", "td",
			"p", "b").
		AllowAttributes("id").OnElements("form"))
	cases := [][2]string{
		{
			"<svg><foreignObject><table><form id=a><tr><form id=r>" +
				"<td>y</td></tr></table>z",
			"<svg><foreignObject><form id=\"a\">yz</form>" +
				"</foreignObject></svg>",
		},
		{
			"<math><mtext><table><form id=a><tr><form id=r>" +
				"<td>y</td></tr></table>z",
			"<math><mtext><form id=\"a\">yz</form></mtext></math>",
		},
		{
			"<svg><foreignObject><table><form id=a><tr><form id=r></form>" +
				"<td>y</td></tr></table>z",
			"<svg><foreignObject><form id=\"a\"></form>yz" +
				"</foreignObject></svg>",
		},
		{
			"<svg><foreignObject><table><form id=a onsubmit=alert(1)>" +
				"<tr><form id=r onclick=alert(1)><td>" +
				"<p onclick=alert(1)>y<img src=x onerror=alert(1)></p>" +
				"</td></tr></table>z<script>alert(1)</script>",
			"<svg><foreignObject><form id=\"a\"><p>y</p>z</form>" +
				"</foreignObject></svg>",
		},
		{
			"<svg><foreignObject><table><form id=a><tr><form id=r>" +
				"<td><b>y</b></td></tr></table>z",
			"<svg><foreignObject><form id=\"a\"><b>y</b>z</form>" +
				"</foreignObject></svg>",
		},
	}
	for _, c := range cases {
		hstAssertRoundTripAndBalanced(t, p, c[0], c[1])
		hstAssertFalse(t, strings.Contains(p.Sanitize(c[0]), "alert"), c[0])
	}
}

// TestIgnoredSecondFormDoesNotExposeDroppedTableParts: an ignored form must
// not expose parts of the table that contains it.
func TestIgnoredSecondFormDoesNotExposeDroppedTableParts(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(
			"svg", "foreignObject", "desc", "math", "mtext", "form",
			"tbody", "tr", "td", "p", "b", "div").
		DisallowTextIn("form"))
	cases := [][2]string{
		{
			"<svg><foreignObject><table><form><table></form><form><thead>" +
				"<tr><td>tail</td></tr></thead></table>z",
			"<svg><foreignObject><form></form></foreignObject></svg>",
		},
		{
			"<table><template><form><p><math><label><caption><mtext>" +
				"<form><mtext><td>tail",
			"<form><p><math><mtext><mtext>tail</mtext></mtext></math>" +
				"</p></form>",
		},
	}
	for _, c := range cases {
		hstAssertRoundTripAndBalanced(t, p, c[0], c[1])
	}
}

// TestFormattingIsNotResumedAroundAWrapperImpliedForTheNextTag: formatting
// closed by a foreign or unrecognized end tag resumes around later content,
// as a browser reconstructs it.  It was resumed for a tag the resumed element
// cannot hold directly: for a list item the element went inside the list
// implied for the item and a second list was implied inside it, so
// <math><b>x</math><li>y</li> became <b>x</b><ul><b><ul><li>y</li></ul></b></ul>
// under Blocks and grew another item on the next pass.  An element
// that would need a wrapper implied inside it now stays queued for the
// content inside the tag, where a browser reconstructs it.
func TestFormattingIsNotResumedAroundAWrapperImpliedForTheNextTag(t *testing.T) {
	blocks := Blocks.And(Formatting)
	published := [][2]string{
		{"<math><b>x</math><li>y</li>", "<b>x</b><ul><li><b>y</b></li></ul>"},
		{"<math><b>x</math><li>y</li><li>z</li>",
			"<b>x</b><ul><li><b>y</b></li><li><b>z</b></li></ul>"},
		{"<math><i><b>x</math><li>y",
			"<i><b>x</b></i><ul><li><i><b>y</b></i></li></ul>"},
		{"<math><b onclick=alert(1)>x</math><li onclick=alert(1)>y",
			"<b>x</b><ul><li><b>y</b></li></ul>"},
		// The same rule for a list item that closes the item before it,
		// which was not a fixed point before either.
		{"<ol><li><b>x</li><li>y</li></ol>",
			"<ol><li><b>x</b></li><li><b>y</b></li></ol>"},
	}
	for _, c := range published {
		hstAssertRoundTripAndBalanced(t, blocks, c[0], c[1])
	}
	hstAssertEqual(t,
		hstParseAsBrowser(t, "<ol><li><b>x</li><li>y</li></ol>"),
		hstParseAsBrowser(t, blocks.Sanitize("<ol><li><b>x</li><li>y</li></ol>")))
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(
			"svg", "math", "foo", "b", "i", "ul", "li", "dt", "p",
			"select", "option", "hr", "table", "tbody", "tr", "td"))
	cases := [][2]string{
		{"<svg><b></svg><li>x", "<svg><b></b></svg><ul><li><b>x</b></li></ul>"},
		{"<foo><b>x</foo><li>y", "<foo><b>x</b></foo><ul><li><b>y</b></li></ul>"},
		{"<ul><li><b>x</li><li>y", "<ul><li><b>x</b></li><li><b>y</b></li></ul>"},
		{"<foo><b>x</foo><option>y",
			"<foo><b>x</b></foo><select><option><b>y</b></option></select>"},
		{"<foo><b>x</foo><td>y",
			"<foo><b>x</b></foo>" +
				"<table><tbody><tr><td><b>y</b></td></tr></tbody></table>"},
		// An element that holds the tag directly still resumes around it.
		{"<foo><b>x</foo><p>y</p>z", "<foo><b>x</b></foo><b><p>y</p>z</b>"},
		{"<foo><b>x</foo><dt>y", "<foo><b>x</b></foo><b><dt>y</dt></b>"},
		{"<foo><b><i>x</foo>y<hr>z",
			"<foo><b><i>x</i></b></foo><b><i>y<hr />z</i></b>"},
		// Nothing to resume once the formatting element closed itself.
		{"<b><foo>x</foo></b><li>y", "<b><foo>x</foo></b><ul><li>y</li></ul>"},
	}
	for _, c := range cases {
		hstAssertRoundTripAndBalanced(t, p, c[0], c[1])
	}
	for _, input := range []string{
		"<ul><li><b>x</li><li>y", "<foo><b><i>x</foo>y<hr>z"} {
		hstAssertEqual(t, hstParseAsBrowser(t, input), hstParseAsBrowser(t, p.Sanitize(input)))
	}
}

// TestRecognizedTagsAfterARunOfUnrecognizedTagsAreLinear: the policy keeps a
// logical entry for every element it drops, including unknown tags, and that
// stack is not bounded by the nesting limit.  Its check of whether a form
// start is in a table scope walked the whole stack from the top, and the
// balancer asks it for every recognized start tag, so a run of unclosed
// unknown tags followed by ordinary markup was quadratic: 128,000 <foo> then
// 128,000 <li> took twelve seconds where main takes 42 ms.  The names that
// decide the check are now indexed, so the walk is bounded by the emitted
// depth.  Both cases below exceed the timeout several times over on the old
// scan.
func TestRecognizedTagsAfterARunOfUnrecognizedTagsAreLinear(t *testing.T) {
	p := Blocks.And(Formatting).
		And(Links).And(Tables)
	const n = 200_000
	unknowns := strings.Repeat("<foo>", n)
	items := unknowns + strings.Repeat("<li>", n)
	hstAssertEqual(t,
		"<ul>"+strings.Repeat("<li></li>", n)+"</ul>",
		hstCompletesWithin(t, 20*time.Second, func() string { return p.Sanitize(items) }),
		"list items after unknown tags")
	options := strings.Repeat("<my-widget>", n) +
		strings.Repeat("<option>x</option>", n)
	hstAssertEqual(t,
		strings.Repeat("x", n),
		hstCompletesWithin(t, 20*time.Second, func() string { return p.Sanitize(options) }),
		"options after unknown tags")
	inputPolicy := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("input").AllowWithoutAttributes("input"))
	inputs := unknowns + strings.Repeat("<input>", n)
	hstAssertEqual(t,
		strings.Repeat("<input />", n),
		hstCompletesWithin(t, 20*time.Second, func() string { return inputPolicy.Sanitize(inputs) }),
		"select-exit starts after unknown tags")
	// The scope check itself still answers as before, across a run of
	// dropped unknown tags: a form directly in a table is popped at once,
	// one inside a cell is an ordinary container.
	forms := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tbody", "tr", "td", "form", "select",
			"option"))
	hstAssertRoundTripAndBalanced(t,
		forms,
		strings.Repeat("<foo>", 300)+"<table><form>x<tr><td>y",
		"<table><form></form></table>x"+
			"<table><tbody><tr><td>y</td></tr></tbody></table>")
	hstAssertRoundTripAndBalanced(t,
		forms,
		strings.Repeat("<foo>", 300)+
			"<table><tr><td><select><form>x</form></select></td></tr></table>",
		"<table><tbody><tr><td><select><form>x</form></select></td></tr>"+
			"</tbody></table>")
}

// TestRetiredImpliedTableFormKeepsItsTextPolicy covers item 3 of #492.  A
// form written in a table the balancer implied is inserted and popped by that
// table's rules, but a browser reading the input sees no table and leaves the
// form open.  When the table is closed to put later text beside it, the
// form's text policy must therefore stay in force until an effective form end
// tag.
func TestRetiredImpliedTableFormKeepsItsTextPolicy(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tbody", "tr", "td", "form").
		DisallowTextIn("form"))
	tableAndEmptyForm := "<table><tbody><form></form></tbody></table>"
	cases := [][2]string{
		{"<tbody><form>B", tableAndEmptyForm},
		{"<tr><form>B",
			"<table><tbody><tr><form></form></tr></tbody></table>"},
		{"<colgroup><form>B", "<table><form></form></table>"},
		{"<thead><form>B", "<table><form></form></table>"},
		{"<tfoot><form>B", "<table><form></form></table>"},
		{"<caption><form>B", "<table><form></form></table>"},
		{"<th><form>B",
			"<table><tbody><tr><form></form></tr></tbody></table>"},
		{"<td><form>B",
			"<table><tbody><tr><td><form></form></td></tr></tbody></table>"},
		// A descendant the policy drops does not hide the form's gate.
		{"<tbody><form><p>B", tableAndEmptyForm},
		{"<tbody><form><my-widget>B", tableAndEmptyForm},
		// The form end restores the gate outside it; a stray row-group end
		// does not end the form a browser opened without a table.
		{"<tbody><form>B</form>C", tableAndEmptyForm + "C"},
		{"<tbody><form>B</tbody>C", tableAndEmptyForm},
		// Tags, attributes, raw-text bodies and encoded markup cannot use
		// the retired output context to surface hostile text or markup.
		{"<tbody><form action=javascript:alert(1) onsubmit=alert(2)>" +
			"B<script>alert(3)</script><img src=x onerror=alert(4)>" +
			"&lt;img src=x onerror=alert(5)&gt;",
			tableAndEmptyForm},
		// A table the author supplied is a negative control: a browser pops
		// the form there too, so the foster-parented text is not form text.
		{"<table><tbody><form>B", tableAndEmptyForm + "B"},
	}
	for _, c := range cases {
		hstAssertRoundTripAndBalanced(t, p, c[0], c[1])
		hstAssertFalse(t, strings.Contains(p.Sanitize(c[0]), "alert"), c[0])
	}

	// disallowTextIn applies to a named input element even when the policy
	// drops that element itself.
	droppedForm := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tbody", "tr", "td").
		DisallowTextIn("form"))
	hstAssertRoundTripAndBalanced(t,
		droppedForm, "<tbody><form>B",
		"<table><tbody></tbody></table>")
	hstAssertRoundTripAndBalanced(t,
		droppedForm, "<tbody><form>B</form>C",
		"<table><tbody></tbody></table>C")

	var discarded []string
	listener := hstP6TagRecorder{discarded: &discarded}
	hstAssertEqual(t, tableAndEmptyForm, p.SanitizeWithListener("<tbody><form>B", listener, nil))
	if len(discarded) != 0 {
		t.Errorf("want nothing discarded, got %q", discarded)
	}
}

// TestRetiredImpliedTableFormUsesTheNearestOutputTextPolicy: kept descendants
// and template contents retain their own text policy.
func TestRetiredImpliedTableFormUsesTheNearestOutputTextPolicy(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(
			"table", "tbody", "tr", "td", "form", "template", "b",
			"div", "p", "select", "option", "object", "svg").
		DisallowTextIn("form"))
	prefix := "<table><tbody><form></form></tbody></table>"
	cases := [][2]string{
		{"<tbody><form><b>B</b>C", prefix + "<b>B</b>"},
		{"<tbody><form>B<b>x</b></form>C", prefix + "<b>x</b>C"},
		{"<tbody><form>B<b>x</form>y</b>C", prefix + "<b>xy</b>C"},
		// A retained template has a separate contents document: its text is
		// not direct text in the outer form, while C is.
		{"<tbody><form><template><b>B</b></template>C",
			"<table><tbody><form></form><template><b>B</b></template>" +
				"</tbody></table>"},
		{"<tbody><form><template><form>B</form>C</template>D",
			"<table><tbody><form></form><template><form></form>C</template>" +
				"</tbody></table>"},
		// An effective end tag may remove the form from the middle of the
		// logical policy stack without closing a retained descendant.
		{"<tbody><form><b>B</form>C</b>D", prefix + "<b>BC</b>D"},
		{"<tbody><form>B<svg></form></svg>D", prefix + "<svg></svg>D"},
		// A form end behind a real table or cell scope boundary is ignored;
		// later direct text therefore remains governed by the form.
		{"<tbody><form>A<table></form>B</table>C",
			prefix + "<table></table>"},
		{"<tbody><form>A<table><tr><td></form>B</td></tr></table>C",
			prefix + "<table><tbody><tr><td>B</td></tr></tbody></table>"},
		{"<tbody><form>A<my-widget><object></form>B</object>C",
			prefix + "<object>B</object>"},
		// Formatting around the implied table is still the nearest retained
		// output context for its text.  Its end exposes the form's gate for C.
		{"<b><tbody><form>B</b>C", "<b>" + prefix + "B</b>"},
		// In select and template modes the input form does not establish this
		// retired context, so their text is not removed by the form's rule.
		{"<select><tbody><form>B</select>C",
			"<select>" + prefix + "BC</select>"},
		{"<template><tbody><form>B</template>C",
			"<template>" + prefix + "B</template>C"},
		// Closing the real input ancestor ends the logical form too; the
		// later text must not stay behind a latched policy gate.
		{"<div><tbody><form>B</div>C</div>D",
			"<div>" + prefix + "</div>CD"},
	}
	for _, c := range cases {
		hstAssertRoundTripAndBalanced(t, p, c[0], c[1])
	}

	droppedTemplate := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tbody", "tr", "td", "form").
		DisallowTextIn("form"))
	hstAssertRoundTripAndBalanced(t,
		droppedTemplate, "<tbody><form><template>B</template>C", prefix)

	textAllowed := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tbody", "tr", "td", "form"))
	hstAssertRoundTripAndBalanced(t,
		textAllowed, "<tbody><form>B", prefix+"B")

	droppedAncestor := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tbody", "tr", "td", "form", "b").
		DisallowTextIn("form"))
	hstAssertRoundTripAndBalanced(t,
		droppedAncestor, "<b><div><tbody><form>A</div>B</b>C",
		"<b>"+prefix+"AB</b>C")
	hstAssertRoundTripAndBalanced(t,
		droppedAncestor, "<select><tbody><form>B</select>C",
		prefix+"BC")
	// The parser-context check is not a text gate: an explicit select end or
	// a select-exit start makes the following form effective again.
	hstAssertRoundTripAndBalanced(t,
		droppedAncestor, "<select><tbody></select><form>B</form>C",
		prefix+"C")
	hstAssertRoundTripAndBalanced(t,
		droppedAncestor, "<select><tbody><input><form>B</form>C",
		"<table><tbody></tbody></table><form></form>C")
	hstAssertRoundTripAndBalanced(t,
		droppedAncestor, "<select><tbody><select><form>B</form>C",
		"<table><tbody></tbody></table><form></form>C")
	hstAssertRoundTripAndBalanced(t,
		droppedAncestor, "<template><tbody><form>B</template>C",
		prefix+"BC")
}

// TestRetiredImpliedTableFormTextIsLinear: the retired form's ordinary stack
// gate makes each text run constant-time.
func TestRetiredImpliedTableFormTextIsLinear(t *testing.T) {
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("table", "tbody", "tr", "td", "form").
		DisallowTextIn("form"))
	const n = 600_000
	input := "<tbody><form>B" + strings.Repeat("<zz>t", n)
	hstAssertEqual(t,
		"<table><tbody><form></form></tbody></table>",
		hstCompletesWithin(t, 20*time.Second, func() string { return p.Sanitize(input) }))
}

// TestTablePartTextFollowsTheGateOfWhereItLands: a table part that produces
// no browser node, whether the policy suppresses it or it is serialized
// outside a physical table, sends its text to the nearest real output
// element.  Text the policy disallows there stays out.  The part's own
// explicit gate still applies, and a table renamed to a container that holds
// text keeps the text of its suppressed cells.
func TestTablePartTextFollowsTheGateOfWhereItLands(t *testing.T) {
	base := NewHTMLPolicyBuilder().
		AllowElements(
			"svg", "foreignObject", "desc", "math", "mtext",
			"form", "tbody", "tr", "td", "p", "b", "div")
	noTextInForms := hstFactory(t, base.DisallowTextIn("form"))
	issueInput := "<ul><mtext><option><Svg></select><FORM><td>hidden"
	cases := [][2]string{
		{issueInput,
			"<mtext><svg></svg><form><tbody><tr><td></td></tr></tbody>" +
				"</form></mtext>"},
		{"<form><td>hidden",
			"<form><tbody><tr><td></td></tr></tbody></form>"},
		{"<form><td><b>shown</b>hidden",
			"<form><tbody><tr><td><b>shown</b></td></tr></tbody></form>"},
		// A foreign element with the same local name is a real container.
		{"<form><svg><tbody>shown</tbody></svg>hidden",
			"<form><svg><tbody>shown</tbody></svg></form>"},
		{"<svg><foreignObject><table><form><tr><td>y",
			"<svg><foreignObject><form></form></foreignObject></svg>"},
		{"<svg><foreignObject><table><form><tr><td><p>y</p>z",
			"<svg><foreignObject><form><p>y</p></form></foreignObject></svg>"},
		{"<math><mtext><table><form><tr><td>y</td></tr></table>",
			"<math><mtext><form></form></mtext></math>"},
		{"<svg><foreignObject><table><form><tr><td><b>y</b>",
			"<svg><foreignObject><form><b>y</b></form></foreignObject></svg>"},
		// These tags are serialized, but a browser ignores them without a
		// physical table, so their text lands directly in the form.
		{"<div><table><form><tr><td>y",
			"<div><form><tbody><tr><td></td></tr></tbody></form></div>"},
		{"<form>y<b>z</b></form>", "<form><b>z</b></form>"},
		// Reduced probe cases: bare table parts must not move later text on a
		// second pass, whether its fixed point is outside the parts or in a
		// standalone HTML integration point.
		{"<th>tail", "<tbody><tr></tr></tbody>tail"},
		{"<tr><hr><foreignObject>tail",
			"<tbody><tr></tr></tbody><foreignObject>tail</foreignObject>"},
	}
	for _, c := range cases {
		hstAssertRoundTripAndBalanced(t, noTextInForms, c[0], c[1])
	}
	hstAssertEqual(t, "", hstTextOf(hstParseAsBrowser(t, noTextInForms.Sanitize(issueInput))))
	hstAssertEqual(t,
		"shown",
		hstTextOf(hstParseAsBrowser(t,
			noTextInForms.Sanitize("<form><td><b>shown</b>hidden"))))
	// So is a cell when the output has a physical table for it.
	physicalTable := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("form", "table", "tbody", "tr", "td").
		DisallowTextIn("form"))
	hstAssertRoundTripAndBalanced(t,
		physicalTable,
		"<form><table><td>shown</td></table>hidden",
		"<form><table><tbody><tr><td>shown</td></tr></tbody></table></form>")
	renamed := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("form", "tbody", "tr", "td", "div").
		AllowElementsWithPolicy(hstRenamingPolicy("div"), "table").
		AllowAttributes("id").OnElements("form"))
	hstAssertRoundTripAndBalanced(t,
		renamed, "<table><form id=a></form><tr><td>y</td></tr></table>",
		"<div><form id=\"a\"></form>y</div>")
	// A part that writes no tag still applies its own gate, as on main: the
	// author disallowed text in cells, and the text is in one in the input.
	noTextInCells := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements(
			"svg", "foreignObject", "form", "tbody", "tr", "td", "div").
		DisallowTextIn("td"))
	hstAssertRoundTripAndBalanced(t,
		noTextInCells, "<svg><foreignObject><table><form><tr><td>y",
		"<svg><foreignObject><form></form></foreignObject></svg>")
	hstAssertRoundTripAndBalanced(t,
		noTextInCells, "<div><table><form><tr><td>y",
		"<div><form><tbody><tr><td></td></tr></tbody></form></div>")
	hstAssertRoundTripAndBalanced(t,
		noTextInCells, "<template><form><tbody><form>tail",
		"<form><tbody></tbody>tail</form>")

	renamedPart := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("div").
		AllowElementsWithPolicy(hstRenamingPolicy("div"), "td"))
	hstAssertRoundTripAndBalanced(t,
		renamedPart, "<td>shown", "<div>shown</div>")
}

// TestQueuedFormattingIsForgottenByItsEndTagOrByANewLink: a formatting
// element closed with an earlier container is queued to resume around later
// content, as a browser reconstructs its active formatting elements.  A
// browser also drops such an element from that list when its own end tag
// arrives, and drops a link when the next link starts, so neither is
// reconstructed afterwards; the queue now forgets them too.  Before,
// <math><b>x</math></b><li>y</li> bolded y and
// <foo><a href=x>x</foo><li><a href=y>y</a>z linked z.
func TestQueuedFormattingIsForgottenByItsEndTagOrByANewLink(t *testing.T) {
	blocks := Blocks.And(Formatting)
	hstAssertRoundTripAndBalanced(t,
		blocks, "<math><b>x</math></b><li>y</li>",
		"<b>x</b><ul><li>y</li></ul>")
	hstAssertRoundTripAndBalanced(t,
		blocks, "<math><b>x</math><li>y</li></b>z",
		"<b>x</b><ul><li><b>y</b></li><li>z</li></ul>")
	p := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("foo", "b", "i", "div", "p", "ul", "li", "a").
		AllowAttributes("href").OnElements("a").
		AllowStandardURLProtocols())
	cases := [][2]string{
		{"<foo><b>x</foo></b>y", "<foo><b>x</b></foo>y"},
		{"<div><b>x</div></b><p>y</p>", "<div><b>x</b></div><p>y</p>"},
		{"<foo><a href=x>x</foo><li><a href=y>y</a>z",
			"<foo><a href=\"x\">x</a></foo><ul><li><a href=\"y\">y</a>z</li>" +
				"</ul>"},
		// An end tag for another element leaves the queue alone.
		{"<foo><b>x</foo></i>y", "<foo><b>x</b></foo><b>y</b>"},
	}
	for _, c := range cases {
		hstAssertRoundTripAndBalanced(t, p, c[0], c[1])
	}
	for _, input := range []string{
		"<foo><b>x</foo></b>y", "<div><b>x</div></b><p>y</p>"} {
		hstAssertEqual(t, hstParseAsBrowser(t, input), hstParseAsBrowser(t, p.Sanitize(input)),
			input)
	}
}
