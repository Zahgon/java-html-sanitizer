// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause
// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/HtmlElementTablesTest.java.

package sanitizer

import (
	"slices"
	"testing"
)

func htmlElementTablesTestIx(nm string) int {
	return htmlElementTablesGet().IndexForName(nm)
}

func TestHTMLElementTablesElementNames(t *testing.T) {
	tables := htmlElementTablesGet()
	if tables.IndexForName("a") == tables.IndexForName("b") {
		t.Error("a and b share an index")
	}
	if tables.IndexForName("p") == tables.IndexForName("q") {
		t.Error("p and q share an index")
	}
	if tables.IndexForName("customclass") < 0 {
		t.Error("customclass has a negative index")
	}

	// The original advances twice per iteration, so it checks every other
	// element.
	for ei, nei := 0, tables.NElementTypes(); ei < nei; ei += 2 {
		s := tables.CanonNameForIndex(ei)
		if got := tables.IndexForName(s); got != ei {
			t.Errorf("IndexForName(%q) = %d, want %d", s, got, ei)
		}
	}
}

func TestHTMLElementTablesCanAppearIn(t *testing.T) {
	tables := htmlElementTablesGet()
	ix := htmlElementTablesTestIx
	for _, tc := range []struct {
		parent, child string
		want          bool
	}{
		{"a", "a", false},
		{"p", "p", false},
		{"a", "p", true},
		{"a", "p", true},

		{"span", "div", true},
		{"div", "span", true},
		{"span", "span", true},

		{"tr", "td", true},
		{"span", "td", false},
		{"div", "td", false},

		{"html", "body", true},
		{"html", "head", true},
		{"body", "html", false},
		{"body", "p", true},
	} {
		if got := tables.CanContain(ix(tc.parent), ix(tc.child)); got != tc.want {
			t.Errorf("CanContain(%s, %s) = %v, want %v", tc.parent, tc.child, got, tc.want)
		}
	}
}

func TestHTMLElementTablesCanBodyContain(t *testing.T) {
	tables := htmlElementTablesGet()
	ix := htmlElementTablesTestIx
	for _, tc := range []struct {
		child string
		want  bool
	}{
		{"a", true},
		{"p", true},
		{"table", true},
		{"tr", false},
		{"html", false},
	} {
		if got := tables.CanContain(ix("body"), ix(tc.child)); got != tc.want {
			t.Errorf("CanContain(body, %s) = %v, want %v", tc.child, got, tc.want)
		}
	}
}

// TestHTMLElementTablesTemplateContainment checks the template content
// model.  The browser probe that generates the tables cannot see into
// template.content, so it used to record <template> as holding nothing, and
// the balancer hoisted every child out to be a sibling (#113).  Its content
// model is that of flow content plus the table parts the "in template"
// insertion mode accepts.
func TestHTMLElementTablesTemplateContainment(t *testing.T) {
	tables := htmlElementTablesGet()
	ix := htmlElementTablesTestIx
	template := ix("template")
	for _, child := range []string{
		"a", "b", "div", "p", "span", "table", "template",
		"caption", "colgroup", "col", "thead", "tbody", "tr", "td", "th",
		"script", "style", "ul", "li",
	} {
		if !tables.CanContain(template, ix(child)) {
			t.Error(child)
		}
	}
	for _, child := range []string{"html", "head", "body", "frameset", "frame"} {
		if tables.CanContain(template, ix(child)) {
			t.Error(child)
		}
	}
	if !tables.CanContainText(template) {
		t.Error("template cannot contain text")
	}
	if !tables.canContainComment(template) {
		t.Error("template cannot contain comments")
	}
	if !tables.CanContainPlainText(template) {
		t.Error("template cannot contain plain text")
	}
	if tables.isTextContentRaw(template) {
		t.Error("template content is raw")
	}

	for _, parent := range []string{"div", "body", "table"} {
		if !tables.CanContain(ix(parent), template) {
			t.Errorf("%s cannot contain template", parent)
		}
	}
}

func TestHTMLElementTablesExplicitClosers(t *testing.T) {
	tables := htmlElementTablesGet()
	ix := htmlElementTablesTestIx
	h1, h2, h3, h4, h5, h6 := ix("h1"), ix("h2"), ix("h3"), ix("h4"), ix("h5"), ix("h6")
	for i, n := 0, tables.NElementTypes(); i < n; i++ {
		want := i == h2 || i == h3 || i == h4 || i == h5 || i == h6
		if got := tables.isAlternateCloserFor(i, h1); got != want {
			t.Errorf("isAlternateCloserFor(%s, h1) = %v, want %v", tables.CanonNameForIndex(i), got, want)
		}
		if tables.isAlternateCloserFor(i, ix("template")) {
			t.Errorf("%s closes template", tables.CanonNameForIndex(i))
		}
	}
}

func TestHTMLElementTablesImpliedElements(t *testing.T) {
	tables := htmlElementTablesGet()
	ix := htmlElementTablesTestIx
	for _, tc := range []struct {
		anc, desc string
		want      []string
	}{
		{"table", "td", []string{"table", "tbody", "tr"}},
		{"table", "th", []string{"table", "tbody", "tr"}},
		{"table", "tr", []string{"table", "tbody"}},
		{"table", "thead", nil},
		{"ol", "span", []string{"li"}},
		{"ul", "span", []string{"li"}},
		{"table", "tr", []string{"table", "tbody"}},
		{"td", "td", nil},
		// The select and list wrappers apply under a container past the end
		// of the wrapper's set of allowed containers too (#492, item 9).
		{"ul", "option", []string{"select"}},
		{"span", "optgroup", []string{"select"}},
		{"td", "option", []string{"select"}},
		{"var", "li", []string{"ul"}},
		// A table part keeps the old reading past the end of its set: the
		// balancer returns it to a table in scope first.
		{"ul", "td", []string{"li"}},
		// The containers that hold the element directly imply nothing.
		{"select", "option", nil},
		{"ul", "li", nil},
	} {
		want := []int{}
		for _, name := range tc.want {
			want = append(want, ix(name))
		}
		if got := tables.impliedElements(ix(tc.anc), ix(tc.desc)); !slices.Equal(got, want) {
			t.Errorf("impliedElements(%s, %s) = %v, want %v", tc.anc, tc.desc, got, want)
		}
	}
}

func TestHTMLElementTablesTextContentModel(t *testing.T) {
	tables := htmlElementTablesGet()
	ix := htmlElementTablesTestIx
	for _, tc := range []struct {
		name string
		test func(int) bool
		el   string
		want bool
	}{
		{"canContainComment", tables.canContainComment, "p", true},
		{"canContainComment", tables.canContainComment, "script", false},

		{"canContainCharacterReference", tables.canContainCharacterReference, "p", true},
		{"canContainCharacterReference", tables.canContainCharacterReference, "textarea", true},
		{"canContainCharacterReference", tables.canContainCharacterReference, "script", false},

		{"CanContainText", tables.CanContainText, "p", true},
		{"CanContainText", tables.CanContainText, "script", true},
		{"CanContainText", tables.CanContainText, "br", false},

		{"isTextContentRaw", tables.isTextContentRaw, "script", true},
		{"isTextContentRaw", tables.isTextContentRaw, "iframe", true},
		{"isTextContentRaw", tables.isTextContentRaw, "textarea", true},
		{"isTextContentRaw", tables.isTextContentRaw, "p", false},

		{"isUnended", tables.isUnended, "plaintext", true},
		{"isUnended", tables.isUnended, "script", false},
	} {
		if got := tc.test(ix(tc.el)); got != tc.want {
			t.Errorf("%s(%s) = %v, want %v", tc.name, tc.el, got, tc.want)
		}
	}
}
