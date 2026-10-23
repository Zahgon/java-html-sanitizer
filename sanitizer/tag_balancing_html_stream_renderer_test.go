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
// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/TagBalancingHtmlStreamRendererTest.java.

package sanitizer

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// tagBalancingTestFixture is a balancer over a renderer that counts the
// non-void elements it opens and the elements it closes.
type tagBalancingTestFixture struct {
	t                    *testing.T
	htmlOutputBuffer     strings.Builder
	balancer             *TagBalancingHTMLStreamEventReceiver
	emittedOpenElements  int
	emittedCloseElements int
}

func newTagBalancingTestFixture(t *testing.T) *tagBalancingTestFixture {
	f := &tagBalancingTestFixture{t: t}
	renderer := NewHTMLStreamRendererToBuilder(
		&f.htmlOutputBuffer,
		func(x string) { t.Errorf("Unexpected renderer error: %s", x) })
	f.balancer = NewTagBalancingHTMLStreamEventReceiver(&tagBalancingTestCountingReceiver{
		HTMLStreamEventReceiverWrapper: NewHTMLStreamEventReceiverWrapper(renderer),
		fixture:                        f,
	})
	return f
}

// setNestingLimit sets a limit the test expects to be accepted.
func (f *tagBalancingTestFixture) setNestingLimit(limit int) {
	f.t.Helper()
	if err := f.balancer.SetNestingLimit(limit); err != nil {
		f.t.Fatal(err)
	}
}

func (f *tagBalancingTestFixture) assertOutput(want string) {
	f.t.Helper()
	if got := f.htmlOutputBuffer.String(); got != want {
		f.t.Errorf("output\n got %q\nwant %q", got, want)
	}
}

func (f *tagBalancingTestFixture) assertBalanced() {
	f.t.Helper()
	if f.emittedOpenElements != f.emittedCloseElements {
		f.t.Errorf("%d elements opened but %d closed", f.emittedOpenElements, f.emittedCloseElements)
	}
}

type tagBalancingTestCountingReceiver struct {
	HTMLStreamEventReceiverWrapper
	fixture *tagBalancingTestFixture
}

func (r *tagBalancingTestCountingReceiver) OpenTag(elementName string, attrs []string) {
	r.HTMLStreamEventReceiverWrapper.OpenTag(elementName, attrs)
	if !IsVoidElement(htmlLexerCanonicalElementName(elementName)) {
		r.fixture.emittedOpenElements++
	}
}

func (r *tagBalancingTestCountingReceiver) CloseTag(elementName string) {
	r.HTMLStreamEventReceiverWrapper.CloseTag(elementName)
	r.fixture.emittedCloseElements++
}

func tagBalancingTestAssertEqual[T comparable](t *testing.T, want, got T, msg string) {
	t.Helper()
	if want != got {
		t.Errorf("%s: got %v, want %v", msg, got, want)
	}
}

func tagBalancingTestFactory(t *testing.T, b *HTMLPolicyBuilder) *PolicyFactory {
	t.Helper()
	factory, err := b.ToFactory()
	if err != nil {
		t.Fatal(err)
	}
	return factory
}

func tagBalancingTestRename(name string) ElementPolicy {
	return ElementPolicyFunc(func(string, *[]string) (string, bool) { return name, true })
}

// tagBalancingTestListener records discarded tags through discardedTag and
// fails t, if set, on discarded attributes.
type tagBalancingTestListener struct {
	NopHTMLChangeListener
	t            *testing.T
	discardedTag func(elementName string)
}

func (l *tagBalancingTestListener) DiscardedTag(_ any, elementName string) {
	if l.discardedTag != nil {
		l.discardedTag(elementName)
	}
}

func (l *tagBalancingTestListener) DiscardedAttributes(_ any, tagName string, _ ...string) {
	if l.t != nil {
		l.t.Errorf("Unexpected discarded attributes on %s", tagName)
	}
}

func TestTagBalancingTagBalancing(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	b.OpenDocument()
	b.OpenTag("html", nil)
	b.OpenTag("head", nil)
	b.OpenTag("title", nil)
	b.Text("Hello, <<World>>!")
	// TITLE closed with case-sensitively different name.
	b.CloseTag("TITLE")
	b.CloseTag("head")
	b.OpenTag("body", nil)
	b.OpenTag("p", []string{"id", "p'0"})
	b.Text("Hello,")
	b.OpenTag("Br", nil)
	b.Text("<<World>>!")
	// HTML, P, and BODY unclosed, but BR not.
	b.CloseDocument()

	f.assertOutput(
		"<html><head><title>Hello, &lt;&lt;World&gt;&gt;!</title></head>" +
			"<body><p id=\"p&#39;0\">Hello," +
			"<br />&lt;&lt;World&gt;&gt;!</p></body></html>")
}

func TestTagBalancingTagSoupIronedOut(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	b.OpenDocument()
	b.OpenTag("i", nil)
	b.Text("x")
	b.OpenTag("b", nil)
	b.Text("y")
	b.CloseTag("i")
	b.Text("z")
	b.CloseDocument()

	f.assertOutput("<i>x<b>y</b></i><b>z</b>")
}

func TestTagBalancingListInListDirectly(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	b.OpenDocument()
	b.OpenTag("ul", nil)
	b.OpenTag("li", nil)
	b.Text("foo")
	b.CloseTag("li")
	b.OpenTag("ul", nil)
	b.OpenTag("li", nil)
	b.Text("bar")
	b.CloseTag("li")
	b.CloseTag("ul")
	b.CloseTag("ul")
	b.CloseDocument()

	f.assertOutput("<ul><li>foo</li><li><ul><li>bar</li></ul></li></ul>")
}

func TestTagBalancingTextContent(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	b.OpenDocument()
	b.OpenTag("title", nil)
	b.Text("Hello, World!")
	b.CloseTag("title")
	b.Text("Hello, ")
	b.OpenTag("b", nil)
	b.Text("World!")
	b.CloseTag("b")
	b.OpenTag("p", nil)
	b.Text("Hello, ")
	b.OpenTag("textarea", nil)
	b.Text("World!")
	b.CloseTag("textarea")
	b.CloseTag("p")
	b.OpenTag("h1", nil)
	b.Text("Hello")
	b.OpenTag("style", []string{"type", "text/css"})
	b.Text("\n.World {\n  color: blue\n}\n")
	b.CloseTag("style")
	b.CloseTag("h1")
	b.OpenTag("ul", nil)
	b.Text("\n  ")
	b.OpenTag("li", nil)
	b.Text("Hello,")
	b.CloseTag("li")
	b.Text("\n  ")
	b.Text("World!")
	b.CloseDocument()

	f.assertOutput(
		// Text and only text allowed in title
		"<title>Hello, World!</title>" +
			// Text allowed at top level and in phrasing content
			"Hello, <b>World!</b>" +
			// Text allowed in block elements and in text areas.
			"<p>Hello, <textarea>World!</textarea></p>" +
			"<h1>Hello" +
			// Text allowed in special style tag.
			"<style type=\"text/css\">\n" +
			".World {\n  color: blue\n}\n" +
			"</style></h1>" +
			// Whitespace allowed inside <ul> but non-whitespace text nodes are
			// moved inside <li>.
			"<ul><li>Hello,</li><li>World!</li></ul>")
}

func TestTagBalancingMismatchedHeaders(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	b.OpenDocument()
	b.OpenTag("H1", nil)
	b.Text("header")
	b.CloseTag("h1")
	b.Text("body")
	b.OpenTag("H2", nil)
	b.Text("sub-header")
	b.CloseTag("h3")
	b.Text("sub-body")
	b.OpenTag("h3", nil)
	b.Text("sub-sub-")
	b.CloseTag("hr") // hr is not a header tag so does not close an h3.
	b.Text("header")
	// <h3> is not allowed in h3.
	b.OpenTag("h3", nil)
	b.CloseTag("h3")
	b.Text("sub-sub-body")
	b.CloseTag("H4")
	b.CloseTag("h2")
	b.CloseDocument()

	f.assertOutput(
		"<h1>header</h1>body" +
			"<h2>sub-header</h2>sub-body" +
			"<h3>sub-sub-header</h3><h3></h3>sub-sub-body")
}

func TestTagBalancingListNesting(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	b.OpenDocument()
	b.OpenTag("ul", nil)
	b.OpenTag("li", nil)
	b.OpenTag("ul", nil)
	b.OpenTag("li", nil)
	b.Text("foo")
	b.CloseTag("li")
	// Does not closes the second <ul> since only </ol> and </ul> can close a
	// <ul> based on the "has an element in list scope test" used by the HTML5
	// tree building algo.
	b.CloseTag("li")
	// This would append inside a list, not an item.  We insert an <li>.
	b.OpenTag("ul", nil)
	b.OpenTag("li", nil)
	b.Text("bar")
	b.CloseDocument()

	f.assertOutput(
		"<ul><li><ul><li>foo</li><li><ul><li>bar</li></ul></li></ul></li></ul>")
}

func TestTagBalancingTableNesting(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	b.OpenDocument()
	b.OpenTag("table", nil)
	b.OpenTag("tbody", nil)
	b.OpenTag("tr", nil)
	b.OpenTag("td", nil)
	b.Text("foo")
	b.CloseTag("td")
	// Chrome does not insert a td to contain this mis-nested table.
	// Instead, it ends one table and starts another.
	b.OpenTag("table", nil)
	b.OpenTag("tbody", nil)
	b.OpenTag("tr", nil)
	b.OpenTag("th", nil)
	b.Text("bar")
	b.CloseTag("table")
	b.CloseTag("table")
	b.CloseDocument()

	f.assertOutput(
		"<table><tbody><tr><td>foo</td></tr></tbody></table>" +
			"<table><tbody><tr><th>bar</th></tr></tbody></table>")
}

// TestTagBalancingContentPushedOutOfATableIsClosedWhenTheTableResumes checks
// foster parenting.  A browser puts content that cannot go inside a table in
// front of the table and keeps the table open, so that the next row pops the
// content and carries on in the same table (#342).  The output cannot put
// anything in front of a tag already written, so the table is closed there
// and written again for the row; the content is closed when the row comes,
// where it used to stay open and swallow the row and everything after.
func TestTagBalancingContentPushedOutOfATableIsClosedWhenTheTableResumes(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	b.OpenDocument()
	b.OpenTag("table", nil)
	b.OpenTag("div", nil)
	b.Text("x")
	b.OpenTag("tr", nil)
	b.OpenTag("td", nil)
	b.Text("y")
	b.CloseTag("td")
	b.CloseTag("tr")
	b.CloseTag("div") // Ignored: no div in table scope.
	b.CloseTag("table")
	b.Text("tail")
	b.CloseDocument()

	f.assertOutput(
		"<table></table><div>x</div>" +
			"<table><tbody><tr><td>y</td></tr></tbody></table>tail")
}

// TestTagBalancingPushedOutRowAndRowGroupReturnWithTheTable checks that the
// row group and row the content was pushed out of return as well.
func TestTagBalancingPushedOutRowAndRowGroupReturnWithTheTable(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	b.OpenDocument()
	b.OpenTag("table", nil)
	b.OpenTag("tbody", nil)
	b.OpenTag("tr", nil)
	b.OpenTag("td", nil)
	b.Text("a")
	b.CloseTag("td")
	b.OpenTag("div", nil)
	b.Text("x")
	b.OpenTag("td", nil)
	b.Text("b")
	b.CloseTag("td")
	b.CloseTag("tr")
	b.CloseTag("table")
	b.CloseDocument()

	f.assertOutput(
		"<table><tbody><tr><td>a</td></tr></tbody></table><div>x</div>" +
			"<table><tbody><tr><td>b</td></tr></tbody></table>")
}

// TestTagBalancingPushedOutTableEndsWithItsEndTag checks that the table's
// own end tag ends the content pushed out of it.
func TestTagBalancingPushedOutTableEndsWithItsEndTag(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	b.OpenDocument()
	b.OpenTag("table", nil)
	b.OpenTag("div", nil)
	b.Text("x")
	b.CloseTag("table")
	b.Text("tail")
	b.CloseDocument()

	f.assertOutput("<table></table><div>x</div>tail")
}

// TestTagBalancingPushedOutTableCountsTowardTheNestingLimit checks that a
// pushed-out table is closed in the output but still counts toward the
// nesting limit, which is a conservative reading of the limit.
func TestTagBalancingPushedOutTableCountsTowardTheNestingLimit(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	f.setNestingLimit(3)
	b.OpenDocument()
	b.OpenTag("table", nil)
	b.OpenTag("div", nil)
	b.OpenTag("p", nil)
	b.OpenTag("span", nil) // Past the limit.
	b.Text("x")
	b.CloseDocument()

	f.assertOutput("<table></table><div><p>x</p></div>")
}

// TestTagBalancingListItemSiblingAtNestingLimitKeepsNestedListStable checks
// that a sibling item keeps enough physical budget for its nested list item.
func TestTagBalancingListItemSiblingAtNestingLimitKeepsNestedListStable(t *testing.T) {
	tagBalancingTestAssertEqual(t,
		"<form><label><ul><li><span></span></li><li><table><tbody>"+
			"</tbody></table><ol><li>x</li></ol></li></ul></label></form>",
		tagBalancingTestRenderBalancedEvents(
			t, 7, "form", "label", "li", "span", "li", "tbody", "ol", "#x"),
		"output")
}

// TestTagBalancingDeferredFormattingKeepsDynamicNestingDepth checks that
// unemitted queued formatting retains the depth of a later limit change.
func TestTagBalancingDeferredFormattingKeepsDynamicNestingDepth(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	f.setNestingLimit(5)
	b.OpenDocument()
	b.OpenTag("table", nil)
	b.OpenTag("form", nil)
	b.OpenTag("b", nil)
	f.setNestingLimit(5)
	b.OpenTag("pre", nil)
	b.OpenTag("s", nil)
	b.OpenTag("col", nil)
	f.setNestingLimit(2)
	b.OpenTag("ul", nil)
	b.OpenTag("br", nil)
	b.Text("x")
	f.setNestingLimit(8)
	b.OpenTag("ul", nil)
	b.OpenTag("noscript", nil)
	b.Text("x")
	err := b.SetNestingLimit(5)
	if err == nil {
		t.Fatal("SetNestingLimit(5) succeeded")
	}
	tagBalancingTestAssertEqual(t,
		"Cannot set the nesting limit to 5: elements are already open 7 deep",
		err.Error(), "error")
	b.CloseDocument()
	f.assertBalanced()
}

// TestTagBalancingPushedOutTableImpliedElementsRespectSmallNestingLimits
// checks that implied table structure never opens past a small nesting
// limit.
func TestTagBalancingPushedOutTableImpliedElementsRespectSmallNestingLimits(t *testing.T) {
	expected := []string{
		"xytail",
		"<table></table>x<table></table>ytail",
		"<table></table><div>x</div>" +
			"<table><tbody></tbody></table>ytail",
		"<table></table><div>x</div>" +
			"<table><tbody><tr></tr></tbody></table>ytail",
	}
	for limit, want := range expected {
		var out strings.Builder
		limited := NewTagBalancingHTMLStreamEventReceiver(
			NewHTMLStreamRendererToBuilder(
				&out, func(x string) { t.Errorf("Unexpected renderer error: %s", x) }))
		if err := limited.SetNestingLimit(limit); err != nil {
			t.Fatal(err)
		}
		limited.OpenDocument()
		limited.OpenTag("table", nil)
		limited.OpenTag("div", nil)
		limited.Text("x")
		limited.OpenTag("tr", nil)
		limited.OpenTag("td", nil)
		limited.Text("y")
		limited.CloseTag("td")
		limited.CloseTag("tr")
		limited.CloseTag("table")
		limited.Text("tail")
		limited.CloseDocument()

		tagBalancingTestAssertEqual(t, want, out.String(), "limit "+strconv.Itoa(limit))
	}
}

// TestTagBalancingTableFormRespectsSmallNestingLimits checks that an empty
// table-mode form does not consume nesting depth.
func TestTagBalancingTableFormRespectsSmallNestingLimits(t *testing.T) {
	expected := []string{
		"xy",
		"<table></table>x<table></table>y",
		"<table><form></form></table>x<table><tbody></tbody></table>y",
		"<table><form></form></table>x" +
			"<table><tbody><tr></tr></tbody></table>y",
		"<table><form></form></table>x" +
			"<table><tbody><tr><td>y</td></tr></tbody></table>",
	}
	for limit, want := range expected {
		var out strings.Builder
		limited := NewTagBalancingHTMLStreamEventReceiver(
			NewHTMLStreamRendererToBuilder(
				&out, func(x string) { t.Errorf("Unexpected renderer error: %s", x) }))
		if err := limited.SetNestingLimit(limit); err != nil {
			t.Fatal(err)
		}
		limited.OpenDocument()
		limited.OpenTag("table", nil)
		limited.OpenTag("form", nil)
		limited.Text("x")
		limited.OpenTag("tr", nil)
		limited.OpenTag("td", nil)
		limited.Text("y")
		limited.CloseDocument()

		tagBalancingTestAssertEqual(t, want, out.String(), "limit "+strconv.Itoa(limit))
	}
}

// TestTagBalancingFormPointerResetPairRespectsTheNestingLimit checks that
// the form-pointer reset pair also stays within the nesting limit.
func TestTagBalancingFormPointerResetPairRespectsTheNestingLimit(t *testing.T) {
	tagBalancingTestAssertEqual(t,
		"<form><table><tbody></tbody></table></form>",
		tagBalancingTestRenderBalancedEvents(t, 3, "form", "table", "tbody", "/form"),
		"output")

	factory := tagBalancingTestFactory(t, NewHTMLPolicyBuilder().
		AllowElements("form", "table", "tbody").
		AllowTextIn("form", "table", "tbody").
		AllowWithoutAttributes("form", "table", "tbody"))
	var output strings.Builder
	var open []string
	var eventCounts [3]int
	limited := NewTagBalancingHTMLStreamEventReceiver(
		factory.Apply(tagBalancingTestStrictRenderer(t, &output, &open, &eventCounts)))
	if err := limited.SetNestingLimit(3); err != nil {
		t.Fatal(err)
	}
	limited.OpenDocument()
	limited.OpenTag("form", nil)
	limited.OpenTag("table", nil)
	limited.OpenTag("tbody", nil)
	limited.CloseTag("form")
	limited.CloseDocument()

	tagBalancingTestAssertEqual(t, "<form><table><tbody></tbody></table></form>", output.String(), "output")
	tagBalancingTestAssertEqual(t, eventCounts[0], eventCounts[1], "opens and closes")
	tagBalancingTestAssertEqual(t, 3, eventCounts[2], "depth")
}

// TestTagBalancingDeferredFormRetirementKeepsRawEventsBalanced checks that
// retiring a stale form closes every emitted descendant at a small limit.
func TestTagBalancingDeferredFormRetirementKeepsRawEventsBalanced(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	f.setNestingLimit(3)
	b.OpenDocument()
	b.OpenTag("form", nil)
	b.OpenTag("table", nil)
	b.OpenTag("form", nil)
	b.Text("x")
	b.CloseTag("form")
	b.OpenTag("tr", nil)
	b.OpenTag("td", nil)
	b.Text("y")
	b.CloseTag("td")
	b.CloseTag("tr")
	b.CloseTag("table")
	b.OpenTag("div", nil)
	b.OpenTag("form", nil)
	b.Text("z")
	b.CloseTag("form")
	b.CloseTag("div")
	b.CloseTag("form")
	b.CloseDocument()

	f.assertOutput(
		"<form><table></table>x<table><tbody></tbody></table>y" +
			"<div></div></form><form>z</form>")
	f.assertBalanced()
}

func TestTagBalancingNestingLimits(t *testing.T) {
	// Some browsers can be DoSed by deeply nested structures.
	// See Issue 3, "Deeply nested elements crash FF 8, Chrome 11"
	// @ https://github.com/OWASP/java-html-sanitizer/issues/3

	f := newTagBalancingTestFixture(t)
	b := f.balancer
	f.setNestingLimit(10)
	b.OpenDocument()
	var attrs []string
	for i := 0; i < 20000; i++ {
		b.OpenTag("div", attrs)
	}
	b.OpenTag("hr", attrs)
	b.CloseDocument()
	f.assertOutput(
		"<div><div><div><div><div><div><div><div><div><div>" +
			"</div></div></div></div></div></div></div></div></div></div>")
	f.assertBalanced()
}

// TestTagBalancingExplicitCloseAtNestingLimit checks that an explicit end
// tag closes an element written at the nesting limit.
func TestTagBalancingExplicitCloseAtNestingLimit(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	f.setNestingLimit(3)
	b.OpenDocument()
	b.OpenTag("div", nil)
	b.OpenTag("div", nil)
	b.OpenTag("span", nil)
	b.Text("x")
	b.CloseTag("span")
	b.OpenTag("p", nil)
	b.Text("y")
	b.CloseDocument()

	f.assertOutput("<div><div><span>x</span><p>y</p></div></div>")
	f.assertBalanced()
}

// TestTagBalancingImplicitCloseAtNestingLimit checks that a sibling
// implicitly closes an incompatible element at the limit.
func TestTagBalancingImplicitCloseAtNestingLimit(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	f.setNestingLimit(3)
	b.OpenDocument()
	b.OpenTag("div", nil)
	b.OpenTag("div", nil)
	b.OpenTag("textarea", nil)
	b.Text("x")
	b.OpenTag("p", nil)
	b.Text("y")
	b.CloseDocument()

	f.assertOutput("<div><div><textarea>x</textarea><p>y</p></div></div>")
	f.assertBalanced()
}

// TestTagBalancingAncestorCloseAtNestingLimit checks that closing an
// ancestor also closes descendants written at the limit.
func TestTagBalancingAncestorCloseAtNestingLimit(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	f.setNestingLimit(3)
	b.OpenDocument()
	b.OpenTag("div", nil)
	b.OpenTag("div", nil)
	b.OpenTag("span", nil)
	b.Text("x")
	b.CloseTag("div")
	b.CloseDocument()

	f.assertOutput("<div><div><span>x</span></div></div>")
	f.assertBalanced()
}

// TestTagBalancingRaisedLimitDoesNotCloseUnemittedResumedElement checks that
// raising the limit does not close a resumed element that was not written.
func TestTagBalancingRaisedLimitDoesNotCloseUnemittedResumedElement(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	f.setNestingLimit(3)
	b.OpenDocument()
	b.OpenTag("table", nil)
	b.OpenTag("caption", nil)
	b.OpenTag("strong", nil)
	b.CloseTag("caption")
	b.Text("x")
	b.OpenTag("strong", nil)
	b.OpenTag("caption", nil)
	b.CloseTag("caption")
	b.OpenTag("strong", nil)
	b.OpenTag("span", nil)
	f.setNestingLimit(4)
	b.CloseTag("table")
	b.CloseDocument()

	f.assertOutput(
		"<table><caption><strong></strong></caption></table>" +
			"x<strong></strong><table><caption></caption></table>" +
			"<strong><strong></strong></strong>")
	f.assertBalanced()
}

func TestTagBalancingTablesGuarded(t *testing.T) {
	// Derived from issue 12.
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	b.OpenDocument()
	b.OpenTag("html", nil)
	b.OpenTag("head", nil)
	b.OpenTag("meta", nil)
	b.CloseTag("head")
	b.OpenTag("body", nil)
	b.OpenTag("p", nil)
	b.Text("Hi")
	b.CloseTag("p")
	b.OpenTag("p", nil)
	b.Text("How are you")
	b.CloseTag("p")
	b.Text("\n")
	b.OpenTag("ul", nil)
	b.OpenTag("li", nil)
	b.OpenTag("table", nil)
	b.OpenTag("tbody", nil)
	b.OpenTag("tr", nil)
	for i := 0; i < 2; i++ {
		b.OpenTag("td", nil)
		b.OpenTag("b", nil)
		b.OpenTag("font", nil)
		b.OpenTag("font", nil)
		b.OpenTag("p", nil)
		b.Text("Cell")
		b.CloseTag("p")
		b.CloseTag("font")
		b.CloseTag("font")
		b.CloseTag("li")
		b.Text("\n")
		b.CloseTag("td")
	}
	b.CloseTag("tr")
	b.CloseTag("tbody")
	b.CloseTag("table")
	b.CloseTag("ul")
	b.Text("\n")
	b.OpenTag("p", nil)
	b.Text("x")
	b.CloseTag("p")
	b.CloseTag("body")
	b.CloseTag("html")
	b.CloseDocument()

	f.assertOutput(
		"<html><head><meta /></head><body><p>Hi</p><p>How are you</p>\n" +
			"<ul><li><table><tbody><tr>" +
			"<td><b><font><font><p>Cell</p></font></font>\n" +
			"</b></td>" +
			// The close </li> tag does not close the whole table.
			"<td><b><b><font><font><p>Cell</p></font></font>\n" +
			"</b></b></td>" +
			"</tr></tbody></table></li></ul>\n" +
			"<b><b><p>x</p></b></b></body></html>")
}

func TestTagBalancingIsInterElementWhitespace(t *testing.T) {
	for _, tc := range []struct {
		text string
		want bool
	}{
		{"foo", false},
		{"", true},
		{" ", true},
		{"\t", true},
		{"\n", true},
		{" \n", true},
		{"\r\n", true},
		{"\r", true},
		{" ", true},
		{" \t ", true},
		{" foo ", false},
		{" ", false},
		{"\u0000", false},
	} {
		if got := IsInterElementWhitespace(tc.text); got != tc.want {
			t.Errorf("IsInterElementWhitespace(%q) = %v, want %v", tc.text, got, tc.want)
		}
	}
}

func TestTagBalancingAnchorTransparentToBlock(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	hrefOnly := []string{"href", ""}
	b.OpenDocument()
	b.OpenTag("div", nil)
	b.OpenTag("a", hrefOnly)
	b.OpenTag("div", nil)
	b.Text("...")
	b.CloseTag("div")
	b.CloseTag("a")
	b.CloseTag("div")
	b.CloseDocument()

	f.assertOutput("<div><a href=\"\"><div>...</div></a></div>")
}

func TestTagBalancingAnchorTransparentToSpans(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	hrefOnly := []string{"href", ""}
	b.OpenDocument()
	b.OpenTag("span", nil)
	b.OpenTag("a", hrefOnly)
	b.OpenTag("span", nil)
	b.Text("...")
	b.CloseTag("span")
	b.CloseTag("a")
	b.CloseTag("span")
	b.CloseDocument()

	f.assertOutput("<span><a href=\"\"><span>...</span></a></span>")
}

func TestTagBalancingAnchorWithInlineInBlock(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	hrefOnly := []string{"href", ""}
	b.OpenDocument()
	b.OpenTag("div", nil)
	b.OpenTag("a", hrefOnly)
	b.OpenTag("span", nil)
	b.Text("...")
	b.CloseTag("span")
	b.CloseTag("a")
	b.CloseTag("div")
	b.CloseDocument()

	f.assertOutput("<div><a href=\"\"><span>...</span></a></div>")
}

func TestTagBalancingDirectlyNestedAnchor(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	hrefOnly := []string{"href", ""}
	b.OpenDocument()
	b.OpenTag("span", nil)
	b.OpenTag("a", hrefOnly)
	b.OpenTag("a", hrefOnly)
	b.Text("...")
	b.CloseTag("a")
	b.CloseTag("a")
	b.CloseTag("span")
	b.CloseDocument()

	f.assertOutput("<span><a href=\"\"></a><a href=\"\">...</a></span>")
}

func TestTagBalancingAnchorClosedWhenBlockInInline(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	hrefOnly := []string{"href", ""}
	b.OpenDocument()
	b.OpenTag("span", nil)
	b.OpenTag("a", hrefOnly)
	b.OpenTag("div", nil)
	b.Text("...")
	b.CloseTag("div")
	b.CloseTag("a")
	b.CloseTag("span")
	b.CloseDocument()

	// According to the spec, div is not nestable within span, but browsers
	// allow it.
	f.assertOutput("<span><a href=\"\"><div>...</div></a></span>")
}

func TestTagBalancingAnchorInAnchorIndirectly(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	hrefOnly := []string{"href", ""}
	b.OpenDocument()
	b.OpenTag("div", nil)
	b.OpenTag("a", hrefOnly)
	b.OpenTag("div", nil)
	b.OpenTag("a", hrefOnly)
	b.Text("...")
	b.CloseTag("a")
	b.CloseTag("div")
	b.CloseTag("a")
	b.CloseTag("div")
	b.CloseDocument()

	f.assertOutput("<div><a href=\"\"><div></div></a><a href=\"\">...</a></div>")
}

func TestTagBalancingInteractiveInAnchorIndirectly(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	hrefOnly := []string{"href", ""}
	b.OpenDocument()
	b.OpenTag("div", nil)
	b.OpenTag("a", hrefOnly)
	b.OpenTag("div", nil)
	b.OpenTag("video", nil)
	b.CloseTag("video")
	b.CloseTag("div")
	b.CloseTag("a")
	b.CloseTag("div")
	b.CloseDocument()
	f.assertOutput("<div><a href=\"\"><div><video></video></div></a></div>")
}

func TestTagBalancingAnchorWithBlockAtTopLevel(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	hrefOnly := []string{"href", ""}
	b.OpenDocument()
	b.OpenTag("a", hrefOnly)
	b.OpenTag("div", nil)
	b.Text("...")
	b.CloseTag("div")
	b.CloseTag("a")
	b.CloseDocument()
	f.assertOutput("<a href=\"\"><div>...</div></a>")
}

func TestTagBalancingResumedElementsAllowedWhereResumed(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	b.OpenDocument()
	b.OpenTag("a", nil)
	b.OpenTag("b", nil)
	b.Text("foo")
	b.OpenTag("i", nil)
	b.OpenTag("a", nil)
	b.Text("bar")
	b.CloseTag("a")
	b.CloseTag("i")
	b.CloseTag("b")
	b.CloseTag("a")
	b.CloseDocument()
	f.assertOutput("<a><b>foo<i></i></b></a><b><i><a>bar</a></i></b>")
}

// TestTagBalancingTemplateKeepsItsChildren checks that a template keeps its
// children.  <template> used to be tabled as unable to contain anything, so
// its children were hoisted out to be its siblings (#113).
func TestTagBalancingTemplateKeepsItsChildren(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	b.OpenDocument()
	b.OpenTag("template", []string{"id", "t"})
	b.OpenTag("b", nil)
	b.OpenTag("a", []string{"href", "https://example.com/"})
	b.Text("link")
	b.CloseTag("a")
	b.CloseTag("b")
	b.CloseTag("template")
	b.CloseDocument()
	f.assertOutput(
		"<template id=\"t\"><b><a href=\"https://example.com/\">link</a></b>" +
			"</template>")
}

func TestTagBalancingTemplateHoldsTextAndNestedTemplates(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	b.OpenDocument()
	b.OpenTag("template", nil)
	b.Text("outer ")
	b.OpenTag("template", nil)
	b.Text("inner")
	b.CloseTag("template")
	b.CloseTag("template")
	b.CloseDocument()
	f.assertOutput("<template>outer <template>inner</template></template>")
}

func TestTagBalancingUnclosedTemplateClosesAtEndOfDocument(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	b.OpenDocument()
	b.OpenTag("template", nil)
	b.OpenTag("b", nil)
	b.Text("x")
	b.CloseDocument()
	f.assertOutput("<template><b>x</b></template>")
}

// TestTagBalancingTablePartsInsideTemplateStayInsideIt checks table parts in
// a template.  A browser leaves table parts bare in template.content.  Here
// they stay inside the template, but get the implied <table><tbody> they get
// anywhere else: the balancer never emits a row or cell without a table on
// the stack, since it cannot know what the output is embedded in.
func TestTagBalancingTablePartsInsideTemplateStayInsideIt(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	b.OpenDocument()
	b.OpenTag("div", nil)
	b.OpenTag("template", nil)
	b.OpenTag("tr", nil)
	b.OpenTag("td", nil)
	b.Text("x")
	b.CloseTag("td")
	b.CloseTag("tr")
	b.CloseTag("template")
	b.CloseTag("div")
	b.CloseDocument()
	f.assertOutput(
		"<div><template><table><tbody><tr><td>x</td></tr></tbody></table>" +
			"</template></div>")
}

func TestTagBalancingMenuItemNesting(t *testing.T) {
	// issue 96
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	b.OpenDocument()
	b.OpenTag("div", nil)
	b.OpenTag("menu", nil)
	b.OpenTag("menuitem", nil)
	b.CloseTag("menuitem")
	b.OpenTag("menuitem", nil)
	b.CloseTag("menuitem")
	b.CloseTag("menu")
	b.CloseTag("div")
	f.assertOutput(
		"<div><menu><menuitem></menuitem><menuitem></menuitem></menu></div>")
}

// TestTagBalancingLinkInsideCellInsideLinkStaysNested checks formatting
// markers.  A browser clears its list of active formatting elements to a
// marker on entering a table cell, so an a opened inside the cell does not
// end an a open outside the table (#333).  The balancer used to close back
// to any open a, taking the cell, row and table with it.
func TestTagBalancingLinkInsideCellInsideLinkStaysNested(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	b.OpenDocument()
	b.OpenTag("a", []string{"href", "u"})
	b.OpenTag("table", nil)
	b.OpenTag("tr", nil)
	b.OpenTag("td", nil)
	b.OpenTag("a", []string{"href", "v"})
	b.Text("1")
	b.CloseTag("a")
	b.CloseTag("td")
	b.CloseTag("tr")
	b.CloseTag("table")
	b.CloseTag("a")
	b.CloseDocument()

	f.assertOutput(
		"<a href=\"u\"><table><tbody><tr><td><a href=\"v\">1</a></td></tr>" +
			"</tbody></table></a>")
}

// TestTagBalancingLinkInsideFormattingMarkerInsideLinkStaysNested checks
// that the other elements a browser puts a marker on entering do the same.
func TestTagBalancingLinkInsideFormattingMarkerInsideLinkStaysNested(t *testing.T) {
	for _, marker := range []string{"applet", "marquee", "object", "template"} {
		f := newTagBalancingTestFixture(t)
		b := f.balancer
		b.OpenDocument()
		b.OpenTag("a", []string{"href", "u"})
		b.OpenTag(marker, nil)
		b.OpenTag("a", []string{"href", "v"})
		b.Text("x")
		b.CloseTag("a")
		b.CloseTag(marker)
		b.CloseTag("a")
		b.CloseDocument()

		tagBalancingTestAssertEqual(t,
			"<a href=\"u\"><"+marker+"><a href=\"v\">x</a></"+marker+"></a>",
			f.htmlOutputBuffer.String(), marker)
	}
}

// TestTagBalancingLinkInsideLinkStillEndsIt checks that with no marker
// between them, a second a still ends the first.
func TestTagBalancingLinkInsideLinkStillEndsIt(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	b.OpenDocument()
	b.OpenTag("a", []string{"href", "u"})
	b.Text("x")
	b.OpenTag("a", []string{"href", "v"})
	b.Text("y")
	b.CloseTag("a")
	b.Text("z")
	b.CloseTag("a")
	b.CloseDocument()

	f.assertOutput("<a href=\"u\">x</a><a href=\"v\">y</a>z")
}

// TestTagBalancingTableContextChangesHaveBalancedReceiverEvents checks that
// table-context returns emit a properly nested stream of receiver events.
func TestTagBalancingTableContextChangesHaveBalancedReceiverEvents(t *testing.T) {
	for _, tc := range []struct {
		want   string
		events []string
	}{
		{
			"<table><tbody><tr><td><div>x</div></td></tr>" +
				"<tr><td>y</td></tr></tbody></table>z",
			[]string{"table", "tr", "td", "div", "#x", "tr", "td", "#y", "/table", "#z"},
		},
		{
			"<div><p>x</p><table><tbody><tr><td>y</td></tr></tbody></table></div>",
			[]string{"div", "p", "#x", "tr", "td", "#y"},
		},
		{
			"<table><colgroup><col /></colgroup><tbody><tr><td>y</td></tr>" +
				"</tbody></table>",
			[]string{"table", "col", "tr", "td", "#y"},
		},
		{
			"<template><table><tbody><tr><td><b>y</b></td></tr></tbody></table>" +
				"</template>z",
			[]string{"template", "tr", "td", "b", "#y", "/template", "#z"},
		},
	} {
		tagBalancingTestAssertEqual(t, tc.want,
			tagBalancingTestRenderBalancedEvents(t, 20, tc.events...),
			strings.Join(tc.events, " "))
	}
}

// TestTagBalancingTableContextReturnsRespectSmallNestingLimits checks that
// the return walk closes every emitted element, including at the limit.
func TestTagBalancingTableContextReturnsRespectSmallNestingLimits(t *testing.T) {
	expected := []string{
		"xy",
		"<table></table>x<table></table>y",
		"<table><tbody></tbody></table>x<table><tbody></tbody></table>y",
		"<table><tbody><tr></tr></tbody></table>x" +
			"<table><tbody><tr></tr></tbody></table>y",
		"<table><tbody><tr><td>x</td></tr><tr><td>y</td></tr></tbody></table>",
		"<table><tbody><tr><td><div>x</div></td></tr>" +
			"<tr><td>y</td></tr></tbody></table>",
	}
	for limit, want := range expected {
		tagBalancingTestAssertEqual(t, want,
			tagBalancingTestRenderBalancedEvents(t, limit,
				"table", "tr", "td", "div", "#x", "tr", "td", "#y"),
			"limit "+strconv.Itoa(limit))
	}
}

// TestTagBalancingMappedForeignSelectOptionsAtNestingLimitAreBoundedAndReported
// checks that a suppressed option run at the limit uses bounded policy
// state.
func TestTagBalancingMappedForeignSelectOptionsAtNestingLimitAreBoundedAndReported(t *testing.T) {
	const optionCount = 10_000
	for _, limit := range []int{2, 5} {
		optionPolicyCalls := 0
		var discarded [2]int
		factory := tagBalancingTestFactory(t, NewHTMLPolicyBuilder().
			AllowElements("svg", "table", "tbody", "tr", "td", "option", "span").
			AllowElementsWithPolicy(tagBalancingTestRename("select"), "table").
			AllowElementsWithPolicy(ElementPolicyFunc(func(string, *[]string) (string, bool) {
				optionPolicyCalls++
				return "option", true
			}), "option").
			AllowTextIn("svg", "table", "tbody", "tr", "td", "option", "span").
			AllowWithoutAttributes("svg", "table", "tbody", "tr", "td", "option", "span"))

		var output strings.Builder
		var open []string
		var eventCounts [3]int
		checked := tagBalancingTestStrictRenderer(t, &output, &open, &eventCounts)
		listener := &tagBalancingTestListener{
			t: t,
			discardedTag: func(elementName string) {
				if elementName == "option" {
					discarded[0]++
				} else {
					discarded[1]++
				}
			},
		}
		limited := NewTagBalancingHTMLStreamEventReceiver(
			factory.ApplyWithListener(checked, listener, nil))
		if err := limited.SetNestingLimit(limit); err != nil {
			t.Fatal(err)
		}
		limited.OpenDocument()
		limited.OpenTag("svg", nil)
		limited.OpenTag("table", nil)
		limited.OpenTag("tr", nil)
		limited.OpenTag("td", nil)
		for i := 0; i < optionCount; i++ {
			limited.OpenTag("option", nil)
		}

		// Re-applying the limit proves the untracked run did not grow the
		// balancer's effective stack depth.
		if err := limited.SetNestingLimit(limit); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < optionCount; i++ {
			limited.CloseTag("option")
		}
		limited.CloseTag("td")
		limited.CloseTag("tr")
		limited.CloseTag("table")
		limited.CloseTag("svg")
		limited.CloseDocument()

		msg := "limit " + strconv.Itoa(limit)
		tagBalancingTestAssertEqual(t, "<svg><select></select></svg>", output.String(), msg)
		wantCalls := 1
		if limit == 2 {
			wantCalls = 0
		}
		tagBalancingTestAssertEqual(t, wantCalls, optionPolicyCalls, msg)
		tagBalancingTestAssertEqual(t, optionCount, discarded[0], msg)
		tagBalancingTestAssertEqual(t, 2, discarded[1], msg)
		tagBalancingTestAssertEqual(t, eventCounts[0], eventCounts[1], msg)
		if eventCounts[2] > limit {
			t.Errorf("%s: depth %d", msg, eventCounts[2])
		}
	}
}

// TestTagBalancingMappedForeignSelectUnknownChildrenAreBoundedAndReported
// checks that suppressed unrecognized starts still count toward the nesting
// limit.
func TestTagBalancingMappedForeignSelectUnknownChildrenAreBoundedAndReported(t *testing.T) {
	const childCount = 10_000
	for _, limit := range []int{2, 3} {
		policyCalls := 0
		discarded := 0
		factory := tagBalancingTestFactory(t, NewHTMLPolicyBuilder().
			AllowElements("svg").
			AllowElementsWithPolicy(tagBalancingTestRename("select"), "table").
			AllowElementsWithPolicy(ElementPolicyFunc(func(string, *[]string) (string, bool) {
				policyCalls++
				return "foo", true
			}), "foo").
			AllowTextIn("svg", "table", "foo").
			AllowWithoutAttributes("svg", "table", "foo"))
		listener := &tagBalancingTestListener{
			t: t,
			discardedTag: func(elementName string) {
				tagBalancingTestAssertEqual(t, "foo", elementName, "discarded")
				discarded++
			},
		}
		var output strings.Builder
		var open []string
		var eventCounts [3]int
		limited := NewTagBalancingHTMLStreamEventReceiver(
			factory.ApplyWithListener(
				tagBalancingTestStrictRenderer(t, &output, &open, &eventCounts), listener, nil))
		if err := limited.SetNestingLimit(limit); err != nil {
			t.Fatal(err)
		}
		limited.OpenDocument()
		limited.OpenTag("svg", nil)
		limited.OpenTag("table", nil)
		for i := 0; i < childCount; i++ {
			limited.OpenTag("foo", nil)
		}
		if err := limited.SetNestingLimit(limit); err != nil {
			t.Fatal(err)
		}
		limited.CloseDocument()

		msg := "limit " + strconv.Itoa(limit)
		tagBalancingTestAssertEqual(t, "<svg><select></select></svg>", output.String(), msg)
		wantCalls := 1
		if limit == 2 {
			wantCalls = 0
		}
		tagBalancingTestAssertEqual(t, wantCalls, policyCalls, msg)
		tagBalancingTestAssertEqual(t, childCount, discarded, msg)
		tagBalancingTestAssertEqual(t, eventCounts[0], eventCounts[1], msg)
		if eventCounts[2] > limit {
			t.Errorf("%s: depth %d", msg, eventCounts[2])
		}
	}
}

// TestTagBalancingMappedForeignSelectShadowsNestedTablesAtTheLimit checks
// that a cap-dropped nested table end cannot close the suppression owner.
func TestTagBalancingMappedForeignSelectShadowsNestedTablesAtTheLimit(t *testing.T) {
	for _, tc := range []struct {
		want   string
		events []string
	}{
		{
			"<svg><select></select></svg>",
			[]string{"@2", "svg", "table", "table", "/table",
				"b", "#must-drop", "/b", "/table", "/svg"},
		},
		{
			"<svg><select></select></svg>",
			[]string{"@3", "svg", "table", "b", "table", "/table",
				"i", "#must-drop", "/i", "/b", "/table", "/svg"},
		},
		{
			"<template><svg><select></select></svg></template>",
			[]string{"@3", "template", "svg", "table", "b", "#must-drop", "/b",
				"/table", "/svg", "/template"},
		},
	} {
		tagBalancingTestAssertEqual(t, tc.want,
			tagBalancingTestRenderMappedSelectPolicyEvents(t, tc.events...),
			strings.Join(tc.events, " "))
	}
}

// TestTagBalancingSuppressedOptionAllowsNestingLimitToBeLoweredAfterClose
// checks that closing a suppressed option discards policy-only descendants.
func TestTagBalancingSuppressedOptionAllowsNestingLimitToBeLoweredAfterClose(t *testing.T) {
	factory := tagBalancingTestFactory(t, NewHTMLPolicyBuilder().
		AllowElements("svg", "table", "tbody", "tr", "td", "option", "span").
		AllowElementsWithPolicy(tagBalancingTestRename("select"), "table").
		AllowTextIn("svg", "table", "tbody", "tr", "td", "option", "span").
		AllowWithoutAttributes("svg", "table", "tbody", "tr", "td", "option", "span"))
	var output strings.Builder
	var open []string
	var eventCounts [3]int
	limited := NewTagBalancingHTMLStreamEventReceiver(
		factory.Apply(tagBalancingTestStrictRenderer(t, &output, &open, &eventCounts)))

	if err := limited.SetNestingLimit(5); err != nil {
		t.Fatal(err)
	}
	limited.OpenDocument()
	limited.OpenTag("svg", nil)
	limited.OpenTag("table", nil)
	limited.OpenTag("tr", nil)
	limited.OpenTag("td", nil)
	limited.OpenTag("option", nil)
	if err := limited.SetNestingLimit(100); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 90; i++ {
		limited.OpenTag("span", nil)
	}
	limited.CloseTag("option")

	// This fails if the descendants removed with the suppressed option
	// remain on either stack.
	if err := limited.SetNestingLimit(5); err != nil {
		t.Fatal(err)
	}
	limited.CloseDocument()

	tagBalancingTestAssertEqual(t, "<svg><select></select></svg>", output.String(), "output")
	tagBalancingTestAssertEqual(t, eventCounts[0], eventCounts[1], "opens and closes")
	tagBalancingTestAssertEqual(t, 2, eventCounts[2], "depth")
}

// TestTagBalancingSuppressedOptionDiscardsItsFormattingResumeEntries checks
// that formatting queued inside a suppressed option cannot resume after it.
func TestTagBalancingSuppressedOptionDiscardsItsFormattingResumeEntries(t *testing.T) {
	for _, events := range [][]string{
		{"@5", "svg", "table", "tr", "td", "option", "@30",
			"form", "a", "/form", "/option", "div", "#after", "/div"},

		// The policy may end the suppressed option implicitly.  The next
		// start observes that and must discard the same queued formatting
		// suffix.
		{"@5", "svg", "table", "tr", "td", "option", "@30",
			"i", "em", "/tbody", "div", "#after", "/div"},

		// A formatting entry queued before the virtual option still resumes.
		{"@5", "svg", "table", "tr", "td", "@30", "form", "a",
			"/form", "@5", "option", "/option", "@30", "div", "#after",
			"/div"},

		// If an ancestor end makes the policy end suppression first, the next
		// event also retires every logical descendant of the virtual option.
		{"@5", "svg", "table", "tr", "td", "option", "@30", "a",
			"em", "/svg", "@5"},

		// A template bounds the table-to-select lookup, so the inner option
		// is tracked normally and its end must not consume the outer option
		// counter.
		{"@2", "svg", "table", "option", "@10", "template", "option",
			"/option", "/template", "/option", "div", "#after", "/div"},
	} {
		tagBalancingTestAssertEqual(t, "<svg><select></select></svg>",
			tagBalancingTestRenderMappedSelectPolicyEvents(t, events...),
			strings.Join(events, " "))
	}
}

// tagBalancingTestReplay feeds events to receiver: "@n" sets the nesting
// limit, "#text" is text, "/name" an end tag and anything else a start tag.
func tagBalancingTestReplay(t *testing.T, receiver *TagBalancingHTMLStreamEventReceiver, events []string) {
	t.Helper()
	for _, event := range events {
		switch {
		case strings.HasPrefix(event, "@"):
			limit, err := strconv.Atoi(event[1:])
			if err != nil {
				t.Fatal(err)
			}
			if err := receiver.SetNestingLimit(limit); err != nil {
				t.Fatal(err)
			}
		case strings.HasPrefix(event, "#"):
			receiver.Text(event[1:])
		case strings.HasPrefix(event, "/"):
			receiver.CloseTag(event[1:])
		default:
			receiver.OpenTag(event, nil)
		}
	}
}

func tagBalancingTestRenderMappedSelectPolicyEvents(t *testing.T, events ...string) string {
	t.Helper()
	factory := tagBalancingTestFactory(t, NewHTMLPolicyBuilder().
		AllowElements(
			"svg", "table", "tbody", "tr", "td", "option", "form", "a",
			"div", "i", "em", "template").
		AllowElementsWithPolicy(tagBalancingTestRename("select"), "table").
		AllowTextIn(
			"svg", "table", "tbody", "tr", "td", "option", "form", "a",
			"div", "i", "em", "template").
		AllowWithoutAttributes(
			"svg", "table", "tbody", "tr", "td", "option", "form", "a",
			"div", "i", "em", "template"))
	var output strings.Builder
	var open []string
	var eventCounts [3]int
	receiver := NewTagBalancingHTMLStreamEventReceiver(
		factory.Apply(tagBalancingTestStrictRenderer(t, &output, &open, &eventCounts)))
	receiver.OpenDocument()
	tagBalancingTestReplay(t, receiver, events)
	receiver.CloseDocument()
	tagBalancingTestAssertEqual(t, eventCounts[0], eventCounts[1], "opens and closes")
	return output.String()
}

// tagBalancingTestStrictReceiver renders events, failing t if they are not
// balanced, and counts in counts the opens, the closes and the greatest
// depth.
type tagBalancingTestStrictReceiver struct {
	HTMLStreamEventReceiverWrapper
	t      *testing.T
	open   *[]string
	counts *[3]int
}

func tagBalancingTestStrictRenderer(
	t *testing.T, output *strings.Builder, open *[]string, counts *[3]int,
) HTMLStreamEventReceiver {
	return &tagBalancingTestStrictReceiver{
		HTMLStreamEventReceiverWrapper: NewHTMLStreamEventReceiverWrapper(
			NewHTMLStreamRendererToBuilder(output, func(x string) { t.Error(x) })),
		t:      t,
		open:   open,
		counts: counts,
	}
}

func (r *tagBalancingTestStrictReceiver) OpenTag(name string, attrs []string) {
	canonName := htmlLexerCanonicalElementName(name)
	if !IsVoidElement(canonName) {
		*r.open = append(*r.open, canonName)
		r.counts[0]++
		r.counts[2] = max(r.counts[2], len(*r.open))
	}
	r.HTMLStreamEventReceiverWrapper.OpenTag(name, attrs)
}

func (r *tagBalancingTestStrictReceiver) CloseTag(name string) {
	canonName := htmlLexerCanonicalElementName(name)
	if len(*r.open) == 0 {
		r.t.Fatalf("unmatched close %s", canonName)
	}
	last := (*r.open)[len(*r.open)-1]
	*r.open = (*r.open)[:len(*r.open)-1]
	tagBalancingTestAssertEqual(r.t, last, canonName, "close order")
	r.counts[1]++
	r.HTMLStreamEventReceiverWrapper.CloseTag(name)
}

func (r *tagBalancingTestStrictReceiver) CloseDocument() {
	if len(*r.open) != 0 {
		r.t.Errorf("unclosed elements %v", *r.open)
	}
	r.HTMLStreamEventReceiverWrapper.CloseDocument()
}

// TestTagBalancingForeignEndTagClosesPoppedEntriesForPlainReceiver checks
// that a foreign end tag closes the entries it pops before it is forwarded.
func TestTagBalancingForeignEndTagClosesPoppedEntriesForPlainReceiver(t *testing.T) {
	for _, tc := range []struct {
		want   string
		events []string
	}{
		{"<svg><noscript></noscript></svg>x", []string{"svg", "noscript", "/svg", "#x"}},
		{
			"<svg><noscript><noscript></noscript></noscript></svg>",
			[]string{"svg", "noscript", "noscript", "/svg"},
		},
		// The inner end tag closes only the inner element.
		{
			"<svg><noscript><noscript></noscript><path></path></noscript></svg>",
			[]string{"svg", "noscript", "noscript", "/noscript", "path", "/path", "/svg"},
		},
	} {
		tagBalancingTestAssertEqual(t, tc.want,
			tagBalancingTestRenderBalancedEvents(t, 256, tc.events...),
			strings.Join(tc.events, " "))
	}
}

// TestTagBalancingUnrecognizedElementsAreBalancedForPlainReceiver checks
// elements outside the containment metadata.  They are forwarded as written,
// so their end tags are balanced against what was forwarded: everything
// opened inside one closes first, a stray end tag closes nothing, and
// whatever is still open ends with the document.
func TestTagBalancingUnrecognizedElementsAreBalancedForPlainReceiver(t *testing.T) {
	for _, tc := range []struct {
		want   string
		events []string
	}{
		{"<foo><b>x</b></foo><b>y</b>", []string{"foo", "b", "#x", "/foo", "#y"}},
		{"<b>x</b>", []string{"/foo", "b", "#x"}},
		{"<foo><bar>x</bar></foo>", []string{"foo", "bar", "#x"}},
		{
			"<foo><foo><foo>x</foo></foo></foo>",
			[]string{"foo", "foo", "foo", "#x", "/foo", "/foo", "/foo"},
		},
		// A table part clears a browser's stack back to the table context.
		// The balancer does not foster-parent the unrecognized element out of
		// the table, so it is written inside the table rather than in front
		// of it.
		{
			"<table><foo></foo><tbody><tr><td>x</td></tr></tbody></table>",
			[]string{"table", "foo", "tr", "td", "#x"},
		},
		// Formatting closed with an integration point is not resumed while
		// content is inserted under SVG rules.
		{
			"<svg><desc><b>x</b></desc>y</svg><b>w</b>",
			[]string{"svg", "desc", "b", "#x", "/desc", "#y", "/svg", "#w"},
		},
		// A void breakout element adds no empty formatting element in front
		// of it; the text after it, now in HTML content, resumes the
		// formatting.
		{
			"<svg><desc><b>x</b></desc><hr /><b>y</b></svg>",
			[]string{"svg", "desc", "b", "#x", "/desc", "hr", "#y", "/svg"},
		},
	} {
		tagBalancingTestAssertEqual(t, tc.want,
			tagBalancingTestRenderBalancedEvents(t, 256, tc.events...),
			strings.Join(tc.events, " "))
	}
}

// TestTagBalancingForwardedElementsCountTowardTheNestingLimit checks the
// limit for forwarded elements.  With no policy to report what it emitted,
// every element forwarded without a stack entry reaches the receiver below
// and nests there, so it counts toward the nesting limit like any other open
// element.  Otherwise the limit is not a bound at all for unrecognized
// names.  Behind a policy the policy's own output depth covers the ones it
// emitted, and the ones it dropped nest nothing.
func TestTagBalancingForwardedElementsCountTowardTheNestingLimit(t *testing.T) {
	for _, tc := range []struct {
		want   string
		limit  int
		events []string
	}{
		{"<foo><foo>xy</foo></foo>", 2, []string{"foo", "foo", "foo", "#x", "b", "#y"}},
		{"<svg>x</svg>", 1, []string{"svg", "path", "#x", "/path", "/svg"}},
		// Closing a forwarded element frees its depth again.
		{"<foo></foo><bar></bar>", 1, []string{"foo", "bar", "/foo", "bar"}},
	} {
		tagBalancingTestAssertEqual(t, tc.want,
			tagBalancingTestRenderBalancedEvents(t, tc.limit, tc.events...),
			strings.Join(tc.events, " "))
	}
}

// TestTagBalancingDroppedForeignRootEndTagIsNotForwardedAfterLimitIncreases
// checks that a root dropped at the limit owns nothing below for its end tag
// to close.
func TestTagBalancingDroppedForeignRootEndTagIsNotForwardedAfterLimitIncreases(t *testing.T) {
	var output strings.Builder
	var open []string
	var eventCounts [3]int
	limited := NewTagBalancingHTMLStreamEventReceiver(
		tagBalancingTestStrictRenderer(t, &output, &open, &eventCounts))
	if err := limited.SetNestingLimit(0); err != nil {
		t.Fatal(err)
	}
	limited.OpenDocument()
	limited.OpenTag("svg", nil)
	if err := limited.SetNestingLimit(2); err != nil {
		t.Fatal(err)
	}
	limited.OpenTag("noscript", nil)
	limited.CloseTag("svg")
	limited.OpenTag("path", nil)
	limited.CloseTag("path")
	limited.CloseDocument()

	tagBalancingTestAssertEqual(t, "<noscript></noscript><path></path>", output.String(), "output")
	tagBalancingTestAssertEqual(t, eventCounts[0], eventCounts[1], "opens and closes")

	factory := tagBalancingTestFactory(t, NewHTMLPolicyBuilder().
		AllowElements("svg", "path", "select").
		AllowElementsWithPolicy(tagBalancingTestRename("select"), "noscript").
		AllowWithoutAttributes("svg", "path", "select", "noscript"))
	tagBalancingTestAssertEqual(t,
		"<select></select><path></path>",
		tagBalancingTestRenderPolicyEvents(t,
			factory, "@0", "svg", "@2", "noscript", "/svg", "path", "/path"),
		"policy output")
}

// TestTagBalancingDroppedForeignElementDoesNotAliasOlderElementAtNestingLimit
// checks that a node dropped at the limit cannot alias an older node with
// its name.
func TestTagBalancingDroppedForeignElementDoesNotAliasOlderElementAtNestingLimit(t *testing.T) {
	renamed := tagBalancingTestFactory(t, NewHTMLPolicyBuilder().
		AllowElements("svg", "g", "path", "select").
		AllowElementsWithPolicy(tagBalancingTestRename("select"), "noscript").
		AllowWithoutAttributes("svg", "g", "path", "select", "noscript"))
	tagBalancingTestAssertEqual(t,
		"<svg><select><g></g></select><path></path></svg>",
		tagBalancingTestRenderPolicyEvents(t,
			renamed, "@3", "svg", "noscript", "g", "noscript", "/g",
			"/noscript", "path", "/path", "/svg"),
		"renamed")

	// Without a rename, the limit drops the inner noscript.  Its end tag
	// must leave the outer one open for the path once the limit allows it.
	keep := tagBalancingTestFactory(t, NewHTMLPolicyBuilder().
		AllowElements("svg", "noscript", "path").
		AllowWithoutAttributes("svg", "noscript", "path"))
	tagBalancingTestAssertEqual(t,
		"<svg><noscript><path></path></noscript></svg>",
		tagBalancingTestRenderPolicyEvents(t,
			keep, "@2", "svg", "noscript", "noscript", "/noscript", "@3",
			"path", "/path", "/svg"),
		"kept, limit 2")
	tagBalancingTestAssertEqual(t,
		"<svg><noscript><noscript></noscript><path></path></noscript></svg>",
		tagBalancingTestRenderPolicyEvents(t,
			keep, "@3", "svg", "noscript", "noscript", "/noscript", "path",
			"/path", "/svg"),
		"kept, limit 3")
}

// TestTagBalancingNestingLimitCannotBeSetBelowTheOpenDepth checks that the
// limit cannot be set below what is open.  With no policy below to count its
// own output, the elements outside the containment metadata that were
// forwarded count too, since each nests the output.
func TestTagBalancingNestingLimitCannotBeSetBelowTheOpenDepth(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	b.OpenDocument()
	b.OpenTag("foo", nil)
	b.OpenTag("div", nil)
	err := b.SetNestingLimit(1)
	if err == nil {
		t.Fatal("SetNestingLimit(1) succeeded")
	}
	tagBalancingTestAssertEqual(t,
		"Cannot set the nesting limit to 1: elements are already open 2 deep",
		err.Error(), "error")
	f.setNestingLimit(2)
	b.OpenTag("p", nil)
	b.Text("x")
	b.CloseDocument()

	f.assertOutput("<foo><div>x</div></foo>")
	f.assertBalanced()
}

// tagBalancingTestUpperCaser hands the receiver below every tag name in
// upper case.
type tagBalancingTestUpperCaser struct {
	HTMLStreamEventReceiverWrapper
}

func (r *tagBalancingTestUpperCaser) OpenTag(elementName string, attrs []string) {
	r.Underlying.OpenTag(strings.ToUpper(elementName), attrs)
}

func (r *tagBalancingTestUpperCaser) CloseTag(elementName string) {
	r.Underlying.CloseTag(strings.ToUpper(elementName))
}

// TestTagBalancingDroppedTagsAreReportedUnderTheCanonicalName checks
// reporting of dropped tags.  A pre-processor can hand the balancer a name
// in a case the lexer would not.  Every start tag is forwarded under its
// canonical name, so a tag the policy drops is reported to the listener
// under that name.  The tags the balancer drops itself, a form ignored while
// the form element pointer is set and a tag past the nesting limit, are
// reported the same way, whether or not the element is in the containment
// metadata.
func TestTagBalancingDroppedTagsAreReportedUnderTheCanonicalName(t *testing.T) {
	var discarded []string
	listener := &tagBalancingTestListener{
		t:            t,
		discardedTag: func(elementName string) { discarded = append(discarded, elementName) },
	}
	factory := tagBalancingTestFactory(t, NewHTMLPolicyBuilder().
		AllowElements("form", "div", "foo").
		WithPreprocessor(HTMLStreamEventProcessorFunc(
			func(r HTMLStreamEventReceiver) HTMLStreamEventReceiver {
				return &tagBalancingTestUpperCaser{NewHTMLStreamEventReceiverWrapper(r)}
			})))

	// The second form start is ignored under the form element pointer rule
	// before it reaches the policy; the b is dropped by the policy.
	tagBalancingTestAssertEqual(t,
		"<form></form>",
		factory.SanitizeWithListener("<form><form></form></form><b></b>", listener, nil),
		"output")
	if !slices.Equal(discarded, []string{"form", "b"}) {
		t.Errorf("discarded %v, want [form b]", discarded)
	}

	// One start past the limit Sanitize sets, for an element in
	// the containment metadata and for one outside it.
	const limit = 256
	for _, name := range []string{"div", "foo"} {
		discarded = nil
		var input, expected strings.Builder
		for i := 0; i <= limit; i++ {
			fmt.Fprintf(&input, "<%s>", name)
			if i < limit {
				fmt.Fprintf(&expected, "<%s>", name)
			}
		}
		input.WriteByte('x')
		expected.WriteByte('x')
		for i := 0; i <= limit; i++ {
			fmt.Fprintf(&input, "</%s>", name)
			if i < limit {
				fmt.Fprintf(&expected, "</%s>", name)
			}
		}
		tagBalancingTestAssertEqual(t,
			expected.String(),
			factory.SanitizeWithListener(input.String(), listener, nil), name)
		if !slices.Equal(discarded, []string{name}) {
			t.Errorf("%s: discarded %v", name, discarded)
		}
	}
}

// TestTagBalancingBalancerStartsEachDocumentClean checks that a balancer can
// be reused for another document.  The first leaves a dropped element whose
// text is suppressed, the form element pointer set, and a foreign root open;
// the next document starts with none of that.
// TestTagBalancingOpenDocumentResetsWhatAThrowingReceiverLeftOpen covers the
// same reset when the first document ends in a panic instead.
func TestTagBalancingBalancerStartsEachDocumentClean(t *testing.T) {
	f := newTagBalancingTestFixture(t)
	b := f.balancer
	f.setNestingLimit(2)
	b.OpenDocument()
	b.OpenTag("form", nil)
	b.OpenTag("svg", nil)
	b.OpenTag("script", nil)
	b.Text("alert(1)")
	b.CloseDocument()
	f.assertOutput("<form><svg></svg></form>")
	f.assertBalanced()

	f.htmlOutputBuffer.Reset()
	b.OpenDocument()
	b.Text("x")
	b.OpenTag("form", nil)
	b.OpenTag("p", nil)
	b.Text("y")
	b.CloseDocument()
	f.assertOutput("x<form><p>y</p></form>")
	f.assertBalanced()
}

// tagBalancingTestFailingReceiver records events itself, and panics on a tr
// end tag.
type tagBalancingTestFailingReceiver struct {
	events *strings.Builder
}

func (r *tagBalancingTestFailingReceiver) OpenDocument()  { r.events.WriteString("[open]") }
func (r *tagBalancingTestFailingReceiver) CloseDocument() { r.events.WriteString("[close]") }
func (r *tagBalancingTestFailingReceiver) OpenTag(elementName string, _ []string) {
	r.events.WriteString("<" + elementName + ">")
}
func (r *tagBalancingTestFailingReceiver) CloseTag(elementName string) {
	if elementName == "tr" {
		panic(errors.New("receiver failed"))
	}
	r.events.WriteString("</" + elementName + ">")
}
func (r *tagBalancingTestFailingReceiver) Text(text string) { r.events.WriteString(text) }

// TestTagBalancingOpenDocumentResetsWhatAThrowingReceiverLeftOpen is item 4
// of #492.  A receiver that panics leaves the document without its
// CloseDocument.  OpenDocument used to start the next document with the
// previous document's open elements, so that document's output began with
// the previous document's close tags.  Both lifecycle calls now reset the
// document state: here the first document leaves an HTML form with the
// pointer set, a forwarded custom element, table structure, and a
// formatting element queued to resume; the next document starts with none
// of it.  TestTagBalancingBalancerStartsEachDocumentClean is the same reset
// through CloseDocument.  The receiver records events itself, since the
// renderer refuses a second document while one is open.
func TestTagBalancingOpenDocumentResetsWhatAThrowingReceiverLeftOpen(t *testing.T) {
	var events strings.Builder
	b := NewTagBalancingHTMLStreamEventReceiver(&tagBalancingTestFailingReceiver{&events})
	b.OpenDocument()
	b.OpenTag("form", nil)
	b.OpenTag("foo", nil)
	b.OpenTag("table", nil)
	b.OpenTag("tr", nil)
	b.OpenTag("td", nil)
	b.OpenTag("b", nil)
	b.Text("x")
	// Closing the cell pops the b, which is queued to resume; the row's
	// close is where the receiver fails.
	b.CloseTag("td")
	func() {
		defer func() {
			err, _ := recover().(error)
			if err == nil || err.Error() != "receiver failed" {
				t.Errorf("CloseTag(tr) panicked with %v, want receiver failed", err)
			}
		}()
		b.CloseTag("tr")
	}()
	tagBalancingTestAssertEqual(t,
		"[open]<form><foo><table><tbody><tr><td><b>x</b></td>",
		events.String(), "first document")
	events.Reset()

	// The next document starts clean: the text is not wrapped in the queued
	// b, the form is not ignored for a pointer the last document set, no
	// close tag comes for the custom element or the table, and the nesting
	// limit, set once the new document is open, applies from depth zero.
	b.OpenDocument()
	if err := b.SetNestingLimit(3); err != nil {
		t.Fatal(err)
	}
	b.Text("y")
	b.OpenTag("form", nil)
	b.OpenTag("p", nil)
	b.OpenTag("span", nil)
	b.OpenTag("span", nil)
	b.Text("z")
	b.CloseDocument()
	tagBalancingTestAssertEqual(t,
		"[open]y<form><p><span>z</span></p></form>[close]",
		events.String(), "second document")
}

// TestTagBalancingSuppressedOptionAtLimitIsForwardedUnderTheCanonicalName
// checks an option suppressed at the limit inside a table mapped to a
// foreign select.  It owns a policy entry.  That entry is opened under the
// canonical name, like every other start tag, so the end tag the balancer
// sends under that name closes it, and the listener hears the same name a
// pre-processor's recasing cannot change.
func TestTagBalancingSuppressedOptionAtLimitIsForwardedUnderTheCanonicalName(t *testing.T) {
	var discarded []string
	listener := &tagBalancingTestListener{
		t:            t,
		discardedTag: func(elementName string) { discarded = append(discarded, elementName) },
	}
	factory := tagBalancingTestFactory(t, NewHTMLPolicyBuilder().
		AllowElements("svg", "table", "option").
		AllowElementsWithPolicy(tagBalancingTestRename("select"), "table").
		AllowTextIn("svg", "table", "option").
		AllowWithoutAttributes("svg", "table", "option"))
	var output strings.Builder
	var open []string
	var eventCounts [3]int
	limited := NewTagBalancingHTMLStreamEventReceiver(
		factory.ApplyWithListener(
			tagBalancingTestStrictRenderer(t, &output, &open, &eventCounts), listener, nil))
	if err := limited.SetNestingLimit(2); err != nil {
		t.Fatal(err)
	}
	limited.OpenDocument()
	limited.OpenTag("svg", nil)
	limited.OpenTag("table", nil)
	limited.OpenTag("OPTION", nil)
	limited.Text("dropped")
	limited.CloseTag("OPTION")
	limited.CloseTag("table")
	limited.CloseTag("svg")
	limited.CloseDocument()

	tagBalancingTestAssertEqual(t, "<svg><select></select></svg>", output.String(), "output")
	if !slices.Equal(discarded, []string{"option"}) {
		t.Errorf("discarded %v, want [option]", discarded)
	}
	tagBalancingTestAssertEqual(t, eventCounts[0], eventCounts[1], "opens and closes")
}

// tagBalancingTestRenderPolicyEvents runs events through a balancer over the
// policy, both directly and through the change reporter, checking that the
// emitted events stay balanced.
func tagBalancingTestRenderPolicyEvents(t *testing.T, factory *PolicyFactory, events ...string) string {
	t.Helper()
	var direct string
	for _, reported := range []bool{false, true} {
		var output strings.Builder
		var open []string
		var eventCounts [3]int
		checked := tagBalancingTestStrictRenderer(t, &output, &open, &eventCounts)
		// Output through the reporter decorator is under test.
		ignore := &tagBalancingTestListener{}
		var policy HTMLSanitizerPolicy
		if reported {
			policy = factory.ApplyWithListener(checked, ignore, nil)
		} else {
			policy = factory.Apply(checked)
		}
		receiver := NewTagBalancingHTMLStreamEventReceiver(policy)
		receiver.OpenDocument()
		tagBalancingTestReplay(t, receiver, events)
		receiver.CloseDocument()
		tagBalancingTestAssertEqual(t, eventCounts[0], eventCounts[1], "opens and closes")
		if reported {
			tagBalancingTestAssertEqual(t, direct, output.String(), "reporter parity")
		} else {
			direct = output.String()
		}
	}
	return direct
}

// tagBalancingTestBalancedReceiver renders events, failing t if they are
// not balanced or nest deeper than limit.  It checks events themselves,
// since the renderer can hide missing closes.
type tagBalancingTestBalancedReceiver struct {
	HTMLStreamEventReceiverWrapper
	t     *testing.T
	limit int
	open  []string
}

func (r *tagBalancingTestBalancedReceiver) OpenTag(name string, attrs []string) {
	if !IsVoidElement(name) {
		r.open = append(r.open, name)
	}
	if len(r.open) > r.limit {
		r.t.Error("nesting limit")
	}
	r.HTMLStreamEventReceiverWrapper.OpenTag(name, attrs)
}

func (r *tagBalancingTestBalancedReceiver) CloseTag(name string) {
	if len(r.open) == 0 {
		r.t.Fatalf("unmatched close %s", name)
	}
	last := r.open[len(r.open)-1]
	r.open = r.open[:len(r.open)-1]
	tagBalancingTestAssertEqual(r.t, last, name, "close order")
	r.HTMLStreamEventReceiverWrapper.CloseTag(name)
}

func (r *tagBalancingTestBalancedReceiver) CloseDocument() {
	if len(r.open) != 0 {
		r.t.Errorf("unclosed elements %v", r.open)
	}
	r.HTMLStreamEventReceiverWrapper.CloseDocument()
}

func tagBalancingTestRenderBalancedEvents(t *testing.T, limit int, events ...string) string {
	t.Helper()
	var output strings.Builder
	checked := &tagBalancingTestBalancedReceiver{
		HTMLStreamEventReceiverWrapper: NewHTMLStreamEventReceiverWrapper(
			NewHTMLStreamRendererToBuilder(&output, func(x string) { t.Error(x) })),
		t:     t,
		limit: limit,
	}
	receiver := NewTagBalancingHTMLStreamEventReceiver(checked)
	if err := receiver.SetNestingLimit(limit); err != nil {
		t.Fatal(err)
	}
	receiver.OpenDocument()
	tagBalancingTestReplay(t, receiver, events)
	receiver.CloseDocument()
	return output.String()
}
