// Copyright (c) 2013, Mike Samuel
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
// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/CssSchemaTest.java.

package sanitizer

import (
	"slices"
	"sort"
	"strings"
	"testing"
)

func cssSchemaTestHas[V any](m map[string]V, key string) bool {
	_, ok := m[key]
	return ok
}

func TestCSSSchemaDangerousProperties(t *testing.T) {
	for _, key := range []string{
		// May allow escaping informal visual containment when embedders are
		// not particular about establishing a clipping region.
		"display",
		"float",
		"clear",
		"left",
		"right",
		// May ease trusted path violations by allowing links to impersonate
		// controls in the embedding page.
		"cursor",
		// Allows code execution.
		"-moz-binding",
		// Prefix corner cases.
		"-",
		"-moz-",
		"-ms-",
		"-o-",
		"-webkit-",
	} {
		if DefaultCSSSchema.forKey(key) != cssSchemaDisallowed {
			t.Error(key)
		}
	}
}

func TestCSSSchemaDangerousTokens(t *testing.T) {
	for _, propName := range cssSchemaDefaultWhitelist {
		property := DefaultCSSSchema.forKey(propName)
		if cssSchemaTestHas(property.literals, "expression") ||
			cssSchemaTestHas(property.fnKeys, "expression(") ||
			cssSchemaTestHas(property.literals, "url") ||
			cssSchemaTestHas(property.fnKeys, "url(") {
			t.Error(propName)
		}
	}
}

func TestCSSSchemaCalcIsScopedToSizingProperties(t *testing.T) {
	var withCalc []string
	for name, property := range cssSchemaDefinitions {
		if cssSchemaTestHas(property.fnKeys, "calc(") {
			withCalc = append(withCalc, name)
		}
	}
	sort.Strings(withCalc)
	want := []string{
		// Sizing properties, which are in DEFAULT.
		"height", "max-height", "max-width",
		"min-height", "min-width", "width",
		// Grid track sizing, where calc() is equally valid CSS.  These are
		// definitions only -- none of them is in the default whitelist -- so
		// this does not widen what the default schema accepts.
		"grid", "grid-auto-columns", "grid-auto-rows", "grid-template",
		"grid-template-columns", "grid-template-rows", "repeat()",
	}
	sort.Strings(want)
	if !slices.Equal(want, withCalc) {
		t.Errorf("got %q, want %q", withCalc, want)
	}
	if !slices.Contains(cssSchemaDefaultWhitelist, "calc()") {
		t.Error("calc() not in the default whitelist")
	}
	calc := DefaultCSSSchema.forKey("calc()")
	if calc == cssSchemaDisallowed {
		t.Fatal("calc() disallowed")
	}
	// Operands are quantities only: no strings, URLs, colors, words or
	// nested functions.
	if calc.bits != CSSSchemaBitQuantity|CSSSchemaBitNegative {
		t.Errorf("bits = %d", calc.bits)
	}
	if len(calc.fnKeys) != 0 {
		t.Errorf("fnKeys = %v", calc.fnKeys)
	}
}

func TestCSSSchemaCSSWideKeywordsAllowedOnEveryProperty(t *testing.T) {
	for key, property := range cssSchemaDefinitions {
		// Keys ending in "()" describe a function's arguments rather than a
		// property, and must not pick the keywords up: "initial" is a value
		// for "color", not for a channel of "rgb(...)".
		isFunction := strings.HasSuffix(key, "()")
		for _, keyword := range cssSchemaCSSWideKeywords {
			if cssSchemaTestHas(property.literals, keyword) == isFunction {
				not := ""
				if isFunction {
					not = " not"
				}
				t.Errorf("%s should%s allow %s", key, not, keyword)
			}
		}
	}
}

// TestCSSSchemaDefaultGrantsNoLayoutControl: the default schema withholds
// every property that changes how an element takes part in page layout, so
// that a style attribute can restyle content but cannot reposition it,
// overlay something else, or hide it.  Adding the modern layout families to
// the definitions must not erode that.
func TestCSSSchemaDefaultGrantsNoLayoutControl(t *testing.T) {
	layoutProperties := []string{
		"display", "position", "float", "clear", "overflow", "overflow-x",
		"overflow-y", "z-index", "opacity", "visibility", "top", "left",
		"right", "bottom", "transform", "transform-origin",
		"grid", "grid-area", "grid-auto-flow", "grid-column", "grid-row",
		"grid-template", "grid-template-areas", "grid-template-columns",
		"grid-template-rows", "grid-auto-columns", "grid-auto-rows",
		"grid-column-start", "grid-column-end", "grid-row-start",
		"grid-row-end", "gap", "row-gap", "column-gap",
		"grid-gap", "grid-row-gap", "grid-column-gap",
		"flex", "flex-basis", "flex-direction", "flex-flow", "flex-grow",
		"flex-shrink", "flex-wrap", "order",
		"align-content", "align-items", "align-self", "justify-content",
		"justify-items", "justify-self", "place-content", "place-items",
		"place-self",
	}
	for _, propName := range layoutProperties {
		if slices.Contains(cssSchemaDefaultWhitelist, propName) {
			t.Errorf("%s must not be in DEFAULT", propName)
		}
		if DefaultCSSSchema.forKey(propName) != cssSchemaDisallowed {
			t.Errorf("%s must be disallowed by DEFAULT", propName)
		}
	}
}

// TestCSSSchemaFixedPositioningIsWithheldEvenWhenOptingIn: position:fixed
// and position:sticky escape a scrolling container, so they are withheld
// even from a policy that opts into layout.  That floor lives in the literal
// set rather than the whitelist, so opting in must not reach it.
func TestCSSSchemaFixedPositioningIsWithheldEvenWhenOptingIn(t *testing.T) {
	position := cssSchemaDefinitions["position"]
	for literal, want := range map[string]bool{
		"absolute": true, "relative": true, "static": true,
		"fixed": false, "sticky": false,
	} {
		if cssSchemaTestHas(position.literals, literal) != want {
			t.Errorf("position allows %s: want %v", literal, want)
		}
	}
}

// TestCSSSchemaLayoutFamiliesAreDefinedForOptIn: the layout families are
// defined, so a caller can union them into the default schema.
func TestCSSSchemaLayoutFamiliesAreDefinedForOptIn(t *testing.T) {
	for _, propName := range []string{
		"grid-template-columns", "grid-column", "gap", "flex",
		"flex-direction", "order", "justify-content", "align-items",
		"transform", "repeat()", "minmax()", "fit-content()",
	} {
		if cssSchemaDefinitions[propName] == cssSchemaDisallowed {
			t.Error(propName)
		}
	}
	display := cssSchemaDefinitions["display"]
	if !cssSchemaTestHas(display.literals, "flex") {
		t.Error("display:flex")
	}
	if !cssSchemaTestHas(display.literals, "grid") {
		t.Error("display:grid")
	}
}

// TestCSSSchemaDecorativeAdditionsAreInDefaultAndTakeNoURL: the decorative
// additions do go into the default schema, but stroke must not become a URL
// vector: "stroke: url(#paintserver)" is valid CSS we deliberately decline
// to support.
func TestCSSSchemaDecorativeAdditionsAreInDefaultAndTakeNoURL(t *testing.T) {
	for _, propName := range []string{
		"text-decoration-line", "text-decoration-style", "text-decoration-color",
		"text-decoration-thickness", "stroke", "stroke-width",
		"conic-gradient()", "repeating-conic-gradient()",
	} {
		if !slices.Contains(cssSchemaDefaultWhitelist, propName) {
			t.Errorf("%s not in the default whitelist", propName)
		}
		if DefaultCSSSchema.forKey(propName) == cssSchemaDisallowed {
			t.Errorf("%s disallowed", propName)
		}
	}
	stroke := DefaultCSSSchema.forKey("stroke")
	if stroke.bits&CSSSchemaBitURL != 0 {
		t.Error("stroke takes a URL")
	}
	if cssSchemaTestHas(stroke.fnKeys, "url(") {
		t.Error("stroke takes url(")
	}
}

// TestCSSSchemaWithOverridesCanWidenADefaultProperty: #380 item 4: a
// default property can be widened without rebuilding.
func TestCSSSchemaWithOverridesCanWidenADefaultProperty(t *testing.T) {
	style := DefaultCSSSchema.Property("text-decoration-style")
	if cssSchemaTestHas(style.Literals(), "zigzag") {
		t.Fatal("zigzag already allowed")
	}
	widened, err := DefaultCSSSchema.WithOverrides([]CSSSchemaNamedProperty{
		{Name: "text-decoration-style", Property: style.WithLiterals("zigzag")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cssSchemaTestHas(widened.Property("text-decoration-style").Literals(), "zigzag") {
		t.Error("zigzag not added")
	}
	// The schema it was derived from is untouched.
	if cssSchemaTestHas(DefaultCSSSchema.Property("text-decoration-style").Literals(), "zigzag") {
		t.Error("default schema changed")
	}
	// Everything else came along.
	if !slices.Contains(widened.AllowedProperties(), "color") {
		t.Error("color lost")
	}
}

// TestCSSSchemaWithOverridesCanNarrowADefaultProperty: #380 item 4: and
// narrowed, which is the safe direction.
func TestCSSSchemaWithOverridesCanNarrowADefaultProperty(t *testing.T) {
	narrowed, err := DefaultCSSSchema.WithOverrides([]CSSSchemaNamedProperty{
		{Name: "color", Property: DefaultCSSSchema.Property("color").WithoutLiterals("red")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cssSchemaTestHas(narrowed.Property("color").Literals(), "red") {
		t.Error("red still allowed")
	}
	if !cssSchemaTestHas(narrowed.Property("color").Literals(), "blue") {
		t.Error("blue lost")
	}
	if !cssSchemaTestHas(DefaultCSSSchema.Property("color").Literals(), "red") {
		t.Error("default schema changed")
	}
}

// TestCSSSchemaWithOverridesResolvesFunctionKeysAgainstTheBase: #380 item 5:
// an override may name a function the base schema already defines, without
// the caller supplying that definition again.
func TestCSSSchemaWithOverridesResolvesFunctionKeysAgainstTheBase(t *testing.T) {
	borderColor := DefaultCSSSchema.Property("border-top-color")
	extended, err := DefaultCSSSchema.WithOverrides([]CSSSchemaNamedProperty{
		{Name: "border-top-color", Property: borderColor.WithFunctions(map[string]string{
			"linear-gradient(": "linear-gradient()"})},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cssSchemaTestHas(extended.Property("border-top-color").FnKeys(), "linear-gradient(") {
		t.Error("linear-gradient( not added")
	}
	// Building the same property standalone still fails, because there the
	// function really would be unreachable.
	standalone := []CSSSchemaNamedProperty{
		{Name: "border-top-color", Property: borderColor.WithFunctions(map[string]string{
			"linear-gradient(": "linear-gradient()"})},
	}
	_, err = CSSSchemaWithPropertyMap(standalone)
	if err == nil {
		t.Fatal("expected a self-containment failure")
	}
	// It names the property and whichever function key it reached first --
	// border-top-color already refers to rgb(), hsl() and friends.
	if !strings.Contains(err.Error(), "border-top-color") {
		t.Error(err)
	}
	if !strings.Contains(err.Error(), "withOverrides") {
		t.Error(err)
	}
}

// TestCSSSchemaWithOverridesRejectsADanglingFunctionKey: a dangling function
// key in an override is still an error.
func TestCSSSchemaWithOverridesRejectsADanglingFunctionKey(t *testing.T) {
	_, err := DefaultCSSSchema.WithOverrides([]CSSSchemaNamedProperty{
		{Name: "color", Property: NewCSSSchemaProperty(
			0, map[string]struct{}{}, map[string]string{"nope(": "nope()"})},
	})
	if err == nil {
		t.Fatal("expected a dangling function key to be rejected")
	}
	if !strings.Contains(err.Error(), "nope()") {
		t.Error(err)
	}
}

// TestCSSSchemaUnionStillRefusesToReconcile: union still refuses to pick a
// winner; that is what WithOverrides is for.
func TestCSSSchemaUnionStillRefusesToReconcile(t *testing.T) {
	narrowed, err := DefaultCSSSchema.WithOverrides([]CSSSchemaNamedProperty{
		{Name: "color", Property: DefaultCSSSchema.Property("color").WithoutLiterals("red")},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = CSSSchemaUnion(DefaultCSSSchema, narrowed)
	if err == nil {
		t.Fatal("expected union to refuse")
	}
	if !strings.Contains(err.Error(), "color") {
		t.Error(err)
	}
}

// TestCSSSchemaPropertyAccessor: a property this schema does not allow reads
// as nil, not as the disallowed property.
func TestCSSSchemaPropertyAccessor(t *testing.T) {
	if DefaultCSSSchema.Property("color") == nil {
		t.Error("color is nil")
	}
	if p := DefaultCSSSchema.Property("position"); p != nil {
		t.Errorf("position = %v", p)
	}
	if p := DefaultCSSSchema.Property("no-such-property"); p != nil {
		t.Errorf("no-such-property = %v", p)
	}
	// Case-insensitive, like forKey.
	if !DefaultCSSSchema.Property("color").Equals(DefaultCSSSchema.Property("COLOR")) {
		t.Error("COLOR differs from color")
	}
}

// TestCSSSchemaPropertyLiteralsAreCanonicalized: literals are matched against
// a lower-cased token, so a literal that is not lower case could never
// match.  Canonicalizing in the constructor keeps a hand-built property from
// silently allowing nothing -- and, more to the point, keeps
// WithoutLiterals("RED") from silently removing nothing and leaving a caller
// believing they narrowed the schema.
func TestCSSSchemaPropertyLiteralsAreCanonicalized(t *testing.T) {
	p := NewCSSSchemaProperty(
		0, map[string]struct{}{"ZigZag": {}}, map[string]string{"RGB(": "rgb()"})
	if !cssSchemaTestHas(p.Literals(), "zigzag") {
		t.Error("zigzag missing")
	}
	if cssSchemaTestHas(p.Literals(), "ZigZag") {
		t.Error("ZigZag present")
	}
	if !cssSchemaTestHas(p.FnKeys(), "rgb(") {
		t.Error("rgb( missing")
	}

	widened := DefaultCSSSchema.Property("text-decoration-style").WithLiterals("ZigZag")
	if !cssSchemaTestHas(widened.Literals(), "zigzag") {
		t.Error("widened zigzag missing")
	}

	narrowed := DefaultCSSSchema.Property("color").WithoutLiterals("RED")
	if cssSchemaTestHas(narrowed.Literals(), "red") {
		t.Error("RED should remove red")
	}
	if !cssSchemaTestHas(narrowed.Literals(), "blue") {
		t.Error("blue missing")
	}
}

// TestCSSSchemaIntersection: #423: combining policies must narrow, never
// widen.
func TestCSSSchemaIntersection(t *testing.T) {
	color := cssSchemaMustWithProperties([]string{"color"})
	width := cssSchemaMustWithProperties([]string{"width"})
	both := cssSchemaMustWithProperties([]string{"color", "width"})

	for _, test := range []struct {
		schemas []*CSSSchema
		want    []string
	}{
		{[]*CSSSchema{color, width}, []string{}},
		{[]*CSSSchema{both, color}, []string{"color"}},
		{[]*CSSSchema{color, both}, []string{"color"}},
	} {
		intersection, err := CSSSchemaIntersection(test.schemas...)
		if err != nil {
			t.Fatal(err)
		}
		if got := intersection.AllowedProperties(); !slices.Equal(got, test.want) {
			t.Errorf("got %q, want %q", got, test.want)
		}
	}
	// A single schema intersects to itself; none of them is an error rather
	// than the universal schema.
	if self, err := CSSSchemaIntersection(color); err != nil || self != color {
		t.Errorf("intersection of one = %v, %v", self, err)
	}
	if _, err := CSSSchemaIntersection(); err == nil {
		t.Error("expected intersecting nothing to be rejected")
	}
}

// TestCSSSchemaIntersectionNarrowsAConflictingProperty: where two schemas
// define the same property differently, the definitions intersect too, so
// the result is never wider than either input.
func TestCSSSchemaIntersectionNarrowsAConflictingProperty(t *testing.T) {
	colorProp := DefaultCSSSchema.Property("color")
	noRed, err := DefaultCSSSchema.WithOverrides([]CSSSchemaNamedProperty{
		{Name: "color", Property: colorProp.WithoutLiterals("red")}})
	if err != nil {
		t.Fatal(err)
	}
	noBlue, err := DefaultCSSSchema.WithOverrides([]CSSSchemaNamedProperty{
		{Name: "color", Property: colorProp.WithoutLiterals("blue")}})
	if err != nil {
		t.Fatal(err)
	}

	intersection, err := CSSSchemaIntersection(noRed, noBlue)
	if err != nil {
		t.Fatal(err)
	}
	merged := intersection.Property("color")
	if cssSchemaTestHas(merged.Literals(), "red") || cssSchemaTestHas(merged.Literals(), "blue") {
		t.Error("red or blue survived")
	}
	if !cssSchemaTestHas(merged.Literals(), "green") {
		t.Error("green lost")
	}

	// A function survives only where both sides agree on its argument schema.
	noRgb, err := DefaultCSSSchema.WithOverrides([]CSSSchemaNamedProperty{
		{Name: "color", Property: NewCSSSchemaProperty(
			colorProp.Bits(), colorProp.Literals(), map[string]string{})},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cssSchemaTestHas(DefaultCSSSchema.Property("color").FnKeys(), "rgb(") {
		t.Error("default color lacks rgb(")
	}
	withoutRgb, err := CSSSchemaIntersection(DefaultCSSSchema, noRgb)
	if err != nil {
		t.Fatal(err)
	}
	if cssSchemaTestHas(withoutRgb.Property("color").FnKeys(), "rgb(") {
		t.Error("rgb( survived")
	}
}

func TestCSSSchemaCustom(t *testing.T) {
	custom, err := CSSSchemaUnion(
		DefaultCSSSchema,
		cssSchemaMustWithProperties([]string{"float"}),
	)
	if err != nil {
		t.Fatal(err)
	}
	for key := range cssSchemaDefinitions {
		if key != "float" {
			if custom.forKey(key) != DefaultCSSSchema.forKey(key) {
				t.Error(key)
			}
		}
	}
	cssFloat := custom.forKey("float")
	if !cssSchemaTestHas(cssFloat.literals, "left") {
		t.Error("left in float")
	}
}
