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
// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/CssSchema.java.

package sanitizer

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// CSSSchema describes the kinds of tokens a CSS property's value can safely
// contain.
//
// A CSSSchema is immutable.  Its properties are kept in hash-table order
// (see hashOrderedSet), which is the order AllowedProperties reports.
type CSSSchema struct {
	// names lists the keys of properties in iteration order.
	names      []string
	properties map[string]*CSSSchemaProperty
}

// CSSSchemaProperty describes how CSS interprets tokens after the ":" for a
// property.  For example, if the property name "color" maps to this, then it
// should record that '#' literals are innocuous colors, and that functions
// like "rgb", "rgba", "hsl", etc. are allowed functions.
//
// A CSSSchemaProperty is immutable.
type CSSSchemaProperty struct {
	// bits is a bitfield of CSSSchemaBit* constants describing groups of
	// allowed tokens.
	bits int
	// literals holds specific allowed values.
	literals map[string]struct{}
	// fnKeys maps lower-case function tokens to the schema key for their
	// parameters.
	fnKeys map[string]string
}

// NewCSSSchemaProperty returns a property definition.
//
// bits is a bitfield of CSSSchemaBit* constants describing groups of allowed
// tokens.  literals holds specific allowed values; they are converted to
// lower case, since values are matched against a lower-cased token, and a
// literal that was not lower case could never match.  fnKeys maps lower-case
// function tokens to the schema key for their parameters; the function tokens
// are converted to lower case for the same reason.
func NewCSSSchemaProperty(
	bits int, literals map[string]struct{}, fnKeys map[string]string,
) *CSSSchemaProperty {
	literalsBuilder := make(map[string]struct{}, len(literals))
	for literal := range literals {
		literalsBuilder[stringsToLowerCase(literal)] = struct{}{}
	}
	// Go maps have no order, so two keys that differ only in case are
	// resolved in a fixed order: the last in sorted order wins.
	return cssSchemaPropertyFromOrderedFns(bits, literalsBuilder, cssSchemaSortedKeys(fnKeys), fnKeys)
}

// cssSchemaPropertyFromOrderedFns builds a property whose function tokens are
// lower-cased in the order given by fnOrder: of two tokens that differ only in
// case, the later one's schema key wins.  literals must already be lower case.
func cssSchemaPropertyFromOrderedFns(
	bits int, literals map[string]struct{}, fnOrder []string, fnKeys map[string]string,
) *CSSSchemaProperty {
	fnKeysBuilder := make(map[string]string, len(fnKeys))
	for _, fn := range fnOrder {
		fnKeysBuilder[stringsToLowerCase(fn)] = fnKeys[fn]
	}
	return &CSSSchemaProperty{bits: bits, literals: literals, fnKeys: fnKeysBuilder}
}

// cssSchemaNewProperty is NewCSSSchemaProperty for a literal list.
func cssSchemaNewProperty(
	bits int, literals []string, fnKeys map[string]string,
) *CSSSchemaProperty {
	return NewCSSSchemaProperty(bits, cssSchemaSetOf(literals), fnKeys)
}

// Bits returns a bitfield of CSSSchemaBit* constants describing groups of
// allowed tokens.
func (p *CSSSchemaProperty) Bits() int { return p.bits }

// Literals returns the specific values this property allows, as a new set.
func (p *CSSSchemaProperty) Literals() map[string]struct{} {
	return cssSchemaCopySet(p.literals)
}

// FnKeys returns a new map from lower-case function tokens such as "rgb(" to
// the schema key describing their arguments.
//
// A key named here must also be present in the schema, or the function
// resolves to the disallowed property and its values are dropped.
func (p *CSSSchemaProperty) FnKeys() map[string]string {
	fnKeys := make(map[string]string, len(p.fnKeys))
	for fn, key := range p.fnKeys {
		fnKeys[fn] = key
	}
	return fnKeys
}

// WithLiterals returns this property, also allowing the given values, which
// are converted to lower case.  This property is unchanged.
//
// This widens what the property accepts.  Prefer naming the exact values you
// need over reaching for a broader CSSSchemaBit* bit.
func (p *CSSSchemaProperty) WithLiterals(extraLiterals ...string) *CSSSchemaProperty {
	widened := cssSchemaCopySet(p.literals)
	for _, literal := range extraLiterals {
		widened[literal] = struct{}{}
	}
	return NewCSSSchemaProperty(p.bits, widened, p.fnKeys)
}

// WithoutLiterals returns this property, no longer allowing the given values,
// which are matched case-insensitively.  This property is unchanged.
//
// Values not currently allowed are ignored, so this is safe to use against a
// schema whose exact contents you have not pinned down.
func (p *CSSSchemaProperty) WithoutLiterals(unwantedLiterals ...string) *CSSSchemaProperty {
	narrowed := cssSchemaCopySet(p.literals)
	for _, unwanted := range unwantedLiterals {
		delete(narrowed, stringsToLowerCase(unwanted))
	}
	return NewCSSSchemaProperty(p.bits, narrowed, p.fnKeys)
}

// WithFunctions returns this property, also allowing the given functions.
// extraFnKeys maps a lower-case function token such as "rgb(" to the schema
// key for its arguments.  This property is unchanged.
//
// The schema must also define the keys these map to, or the functions resolve
// to the disallowed property.  WithOverrides checks that for you.
func (p *CSSSchemaProperty) WithFunctions(extraFnKeys map[string]string) *CSSSchemaProperty {
	// The functions are combined in a hash map whose iteration order decides
	// which of two tokens differing only in case wins.
	widened := newHashOrderedMapFrom(cssSchemaFnEntries(p.fnKeys))
	widened.putAll(cssSchemaFnEntries(extraFnKeys))
	fnKeys := make(map[string]string, widened.size())
	for _, e := range widened.entries() {
		fnKeys[e.key] = e.value
	}
	return cssSchemaPropertyFromOrderedFns(p.bits, cssSchemaCopySet(p.literals), widened.keys(), fnKeys)
}

// cssSchemaFnEntries lists a function map's entries in sorted order of their
// tokens.
func cssSchemaFnEntries(fnKeys map[string]string) []hashOrderedEntry[string] {
	entries := make([]hashOrderedEntry[string], 0, len(fnKeys))
	for _, fn := range cssSchemaSortedKeys(fnKeys) {
		entries = append(entries, hashOrderedEntry[string]{key: fn, value: fnKeys[fn]})
	}
	return entries
}

// String describes the property for debugging, with its literals and
// functions sorted.
func (p *CSSSchemaProperty) String() string {
	return fmt.Sprintf("[CSS property bits=%d literals=%s fns=%s]",
		p.bits, cssSchemaSortedList(p.literals), cssSchemaSortedList(p.fnKeys))
}

// Equals reports whether two properties allow the same bits, literals and
// functions.
func (p *CSSSchemaProperty) Equals(other *CSSSchemaProperty) bool {
	if p == other {
		return true
	}
	if p == nil || other == nil {
		return false
	}
	if p.bits != other.bits || len(p.fnKeys) != len(other.fnKeys) ||
		len(p.literals) != len(other.literals) {
		return false
	}
	for fn, key := range p.fnKeys {
		if otherKey, ok := other.fnKeys[fn]; !ok || otherKey != key {
			return false
		}
	}
	for literal := range p.literals {
		if _, ok := other.literals[literal]; !ok {
			return false
		}
	}
	return true
}

// These describe the token groups a property's value may contain.  The
// property constructor is public and takes them, so they are public too.
const (
	// CSSSchemaBitQuantity allows a number, with or without a unit: 4, 2px,
	// 50%.
	CSSSchemaBitQuantity = 1
	// CSSSchemaBitHashValue allows a hash colour value: #f00.
	CSSSchemaBitHashValue = 2
	// CSSSchemaBitNegative allows a negative quantity: -1px.  Independent of
	// CSSSchemaBitQuantity.
	CSSSchemaBitNegative = 4
	// CSSSchemaBitString allows a quoted string: "foo".
	CSSSchemaBitString = 8
	// CSSSchemaBitURL allows a url(...) value.  Set this only deliberately:
	// CSS URLs are fetched without user interaction, so a property that
	// accepts one is a loading vector.
	CSSSchemaBitURL = 16
	// CSSSchemaBitUnreservedWord allows a bare word not in the literal set,
	// emitted as a quoted string.
	CSSSchemaBitUnreservedWord = 64
	// CSSSchemaBitUnicodeRange allows a unicode range: U+0-7F.
	CSSSchemaBitUnicodeRange = 128
)

// cssSchemaDisallowed is the property of everything a schema does not allow.
var cssSchemaDisallowed = cssSchemaNewProperty(0, nil, nil)

func newCSSSchema(names []string, properties map[string]*CSSSchemaProperty) *CSSSchema {
	return &CSSSchema{names: names, properties: properties}
}

// CSSSchemaWithProperties returns a schema that includes all and only the
// named properties.
//
// propertyNames is a series of lower-case CSS property names that appear in
// the built-in CSS definitions.  It is an error to mention an unknown
// property name; the error message is that name.
func CSSSchemaWithProperties(propertyNames []string) (*CSSSchema, error) {
	order := newHashOrderedSet()
	properties := map[string]*CSSSchemaProperty{}
	for _, propertyName := range propertyNames {
		prop, ok := cssSchemaDefinitions[propertyName]
		if !ok {
			return nil, errors.New(propertyName)
		}
		order.add(propertyName)
		properties[propertyName] = prop
	}
	return newCSSSchema(order.items(), properties), nil
}

// CSSSchemaWithPropertyMap returns a schema that includes all and only the
// given properties.
//
// properties pairs lower-case CSS property names with property objects, in
// order; a repeated name keeps its first position and takes its last
// definition.  Every function key the properties use must be defined among
// them.  The properties are checked in order, so a missing function key is
// reported for the first property that uses one.
func CSSSchemaWithPropertyMap(properties []CSSSchemaNamedProperty) (*CSSSchema, error) {
	names, byName := cssSchemaOrderedProperties(properties)
	order := newHashOrderedSet()
	propertyMapBuilder := map[string]*CSSSchemaProperty{}
	// check that all fnKeys are defined in properties.
	for _, name := range names {
		property := byName[name]
		if property == nil {
			return nil, fmt.Errorf("property %q is nil", name)
		}
		for _, fn := range cssSchemaSortedKeys(property.fnKeys) {
			fnKey := property.fnKeys[fn]
			if _, ok := byName[fnKey]; !ok {
				return nil, errors.New(
					"Property map is not self contained: \"" + name +
						"\" uses the function key \"" + fnKey +
						"\" which the map does not define." +
						"  Add it to the map, or build on a schema that already has" +
						" it with CssSchema.withOverrides.")
			}
		}
		order.add(name)
		propertyMapBuilder[name] = property
	}
	return newCSSSchema(order.items(), propertyMapBuilder), nil
}

// CSSSchemaUnion returns a schema that allows all and only CSS properties
// that are allowed by at least one of the inputs.
//
// Two schemas that define the same property differently cannot be reconciled
// automatically -- silently picking a winner would hand the caller a policy
// they did not write -- so this returns an error instead.  To extend or narrow
// a property that a schema already defines, say which one wins with
// WithOverrides.
func CSSSchemaUnion(cssSchemas ...*CSSSchema) (*CSSSchema, error) {
	if len(cssSchemas) == 1 {
		return cssSchemas[0], nil
	}
	var names []string
	properties := map[string]*CSSSchemaProperty{}
	for _, cssSchema := range cssSchemas {
		for _, name := range cssSchema.names {
			newProp := cssSchema.properties[name]
			oldProp, ok := properties[name]
			if !ok {
				names = append(names, name)
			}
			properties[name] = newProp
			if ok && !oldProp.Equals(newProp) {
				return nil, errors.New(
					"Duplicate irreconcilable definitions for " + name)
			}
		}
	}
	return newCSSSchema(names, properties), nil
}

// CSSSchemaIntersection returns a schema that allows a CSS property only if
// all of the inputs do.
//
// Where the inputs define the same property differently, the definitions are
// themselves intersected: a token group is kept only if every input allows
// it, a value only if every input lists it, and a function only if every
// input maps it to the same argument schema.  So the result is never wider
// than any input, whatever the inputs disagree about -- unlike CSSSchemaUnion,
// which refuses to reconcile a disagreement at all.
//
// This is what combining two policies needs: combining narrows what either
// allows on its own.
//
// Intersecting no schemas is meaningless rather than universal, so at least
// one is required.
func CSSSchemaIntersection(cssSchemas ...*CSSSchema) (*CSSSchema, error) {
	if len(cssSchemas) == 0 {
		return nil, errors.New("No schemas to intersect")
	}
	if len(cssSchemas) == 1 {
		return cssSchemas[0], nil
	}
	names := slices.Clone(cssSchemas[0].names)
	properties := make(map[string]*CSSSchemaProperty, len(names))
	for name, prop := range cssSchemas[0].properties {
		properties[name] = prop
	}
	for _, other := range cssSchemas[1:] {
		kept := names[:0]
		for _, name := range names {
			narrower, ok := other.properties[name]
			if !ok {
				delete(properties, name)
				continue
			}
			properties[name] = cssSchemaIntersectProperties(properties[name], narrower)
			kept = append(kept, name)
		}
		names = kept
	}
	return newCSSSchema(names, properties), nil
}

// cssSchemaIntersectProperties returns the definition allowing only what both
// of the inputs allow.
func cssSchemaIntersectProperties(a, b *CSSSchemaProperty) *CSSSchemaProperty {
	if a.Equals(b) {
		return a
	}
	literals := map[string]struct{}{}
	for literal := range a.literals {
		if _, ok := b.literals[literal]; ok {
			literals[literal] = struct{}{}
		}
	}
	fnKeys := map[string]string{}
	for fn, key := range a.fnKeys {
		// Keep a function only where both sides send its arguments to the
		// same schema key; two different argument schemas cannot be reconciled
		// here without inventing a third, so drop it.
		if otherKey, ok := b.fnKeys[fn]; ok && otherKey == key {
			fnKeys[fn] = key
		}
	}
	return NewCSSSchemaProperty(a.bits&b.bits, literals, fnKeys)
}

// AllowedProperties returns the names of the CSS properties allowed by this
// schema, as a new slice.
func (s *CSSSchema) AllowedProperties() []string {
	return slices.Clone(s.names)
}

// Property returns the definition this schema uses for a property, so that
// it can be used as the basis of a modified one.
//
// propertyName is a CSS property name, or a schema key for a function's
// arguments such as "rgb()", and is matched case-insensitively.  Property
// returns nil if this schema does not allow the property.
func (s *CSSSchema) Property(propertyName string) *CSSSchemaProperty {
	return s.properties[stringsToLowerCase(propertyName)]
}

// WithOverrides returns this schema with the named properties replaced or
// added.  This schema is unchanged.
//
// CSSSchemaUnion refuses to reconcile two definitions of the same property;
// this is how you say which one wins.  Use it to extend, narrow or replace
// what a schema -- typically DefaultCSSSchema -- allows for a property,
// without rebuilding the schema from scratch:
//
//	schema, err := DefaultCSSSchema.WithOverrides([]CSSSchemaNamedProperty{{
//		Name:     "cursor",
//		Property: DefaultCSSSchema.Property("cursor").WithLiterals("zoom-in"),
//	}})
//
// Function keys are resolved against the combined schema, so a property may
// refer to a function this schema already defines without the caller having
// to supply that definition again:
//
//	// "linear-gradient()" is already in the default schema, so naming it is
//	// enough.
//	schema, err := DefaultCSSSchema.WithOverrides([]CSSSchemaNamedProperty{{
//		Name: "background-image",
//		Property: DefaultCSSSchema.Property("background-image").
//			WithFunctions(map[string]string{
//				"linear-gradient(": "linear-gradient()"}),
//	}})
//
// This can widen what the schema accepts, which is the point, but it means
// the result is only as safe as the definitions you supply.  Adding
// CSSSchemaBitURL to a property, or wiring in a function key the schema
// resolves loosely, opens whatever that implies.
//
// overrides maps lower-case property names to their new definitions.  A name
// this schema does not have is added.  WithOverrides returns an error if an
// override names a function key that neither it nor this schema defines.
// Overrides are applied, and checked, in the order given; a repeated name
// keeps its first position and takes its last definition.
func (s *CSSSchema) WithOverrides(overrides []CSSSchemaNamedProperty) (*CSSSchema, error) {
	overrideNames, byName := cssSchemaOrderedProperties(overrides)
	var order *hashOrderedSet
	if n := len(s.names); n == 0 {
		order = newHashOrderedSet()
	} else {
		// Sized for n entries at the load factor, plus one; the table size
		// decides the order.
		order = newHashOrderedSetWithCapacity(int(float32(n)/0.75 + 1))
	}
	merged := make(map[string]*CSSSchemaProperty, len(s.properties)+len(overrides))
	for _, name := range s.names {
		order.add(name)
		merged[name] = s.properties[name]
	}
	for _, name := range overrideNames {
		property := byName[name]
		if property == nil {
			return nil, fmt.Errorf("override for %q is nil", name)
		}
		canonName := stringsToLowerCase(name)
		order.add(canonName)
		merged[canonName] = property
	}
	// Only the overrides can introduce a dangling function key; the schema we
	// started from was checked when it was built.
	for _, name := range overrideNames {
		property := byName[name]
		for _, fn := range cssSchemaSortedKeys(property.fnKeys) {
			fnKey := property.fnKeys[fn]
			if _, ok := merged[fnKey]; !ok {
				return nil, errors.New(
					"Override for \"" + name + "\" uses the function key \"" +
						fnKey + "\" which neither the override nor the schema" +
						" defines.  Add a definition for it to the overrides.")
			}
		}
	}
	return newCSSSchema(order.items(), merged), nil
}

// ToAttributePolicy returns an AttributePolicy that sanitizes a style
// attribute value against this schema, passing the content of each url(...)
// value through urlRewriter, or dropping every url(...) value if urlRewriter
// is nil.
//
// urlRewriter receives the decoded content of a url(...) value and returns
// the URL to use, or the empty string to drop it.  It is never passed the
// empty string.
//
// This is the per-element counterpart of HTMLPolicyBuilder.AllowStyling,
// which applies one schema to the style attribute of every element.  Passing
// the result to HTMLPolicyBuilderAttributeBuilder.Matching lets different
// elements allow different CSS properties.
//
// Security note: a policy built this way is not wired to
// HTMLPolicyBuilder.AllowURLsInStyles or HTMLPolicyBuilder.AllowURLProtocols.
// That wiring happens only inside the style attribute guard that
// HTMLPolicyBuilder.AllowStyling installs, and it cannot see a policy handed
// to Matching, so vetting URLs is entirely the caller's job.  URLs in CSS are
// typically loaded without user interaction, the way <img src=...> is, so a
// greater degree of scrutiny is warranted than for a link.  If in doubt, pass
// nil, which drops them.  To vet URLs by protocol the way HTMLPolicyBuilder
// does, reuse a FilterURLByProtocolAttributePolicy; it ignores the element
// and attribute names it is given, so any will do.
//
// If an element also gets a style policy from HTMLPolicyBuilder.AllowStyling,
// the two are joined, and joining narrows: the schemas intersect, and both
// rewriters run in turn, so either one can drop a URL.  A policy attached
// here therefore restricts the element it is attached to; it cannot grant it
// a property the global schema withholds.
func (s *CSSSchema) ToAttributePolicy(urlRewriter func(url string) string) AttributePolicy {
	if urlRewriter == nil {
		return newStylingPolicy(s, cssSchemaRejectAllURLs)
	}
	return newStylingPolicy(s, stylingPolicyURLRewriterFunc(urlRewriter))
}

// cssSchemaRejectAllURLsRewriter drops every URL it is given.
type cssSchemaRejectAllURLsRewriter struct{}

func (cssSchemaRejectAllURLsRewriter) apply(string) string { return "" }

// cssSchemaRejectAllURLs drops every URL it is given.
var cssSchemaRejectAllURLs stylingPolicyURLRewriter = cssSchemaRejectAllURLsRewriter{}

// forKey returns the schema for the named property or function key.
func (s *CSSSchema) forKey(propertyName string) *CSSSchemaProperty {
	propertyNameCanon := stringsToLowerCase(propertyName)
	if property, ok := s.properties[propertyNameCanon]; ok {
		return property
	}
	if propertyNameCanon != "" && propertyNameCanon[0] == '-' {
		barePropertyNameCanon, ok := cssSchemaStripVendorPrefix(propertyNameCanon)
		if !ok {
			return cssSchemaDisallowed
		}
		if property, ok := s.properties[barePropertyNameCanon]; ok {
			return property
		}
	}
	return cssSchemaDisallowed
}

// cssSchemaStripVendorPrefix turns "-moz-foo" into "foo".  It reports false
// if there is no vendor prefix.
func cssSchemaStripVendorPrefix(cssKeyword string) (string, bool) {
	prefixLen := 0
	if len(cssKeyword) >= 2 {
		switch cssKeyword[1] {
		case 'm':
			if strings.HasPrefix(cssKeyword, "-ms-") {
				prefixLen = 4
			} else if strings.HasPrefix(cssKeyword, "-moz-") {
				prefixLen = 5
			}
		case 'o':
			if strings.HasPrefix(cssKeyword, "-o-") {
				prefixLen = 3
			}
		case 'w':
			if strings.HasPrefix(cssKeyword, "-webkit-") {
				prefixLen = 8
			}
		}
	}
	if prefixLen == 0 {
		return "", false
	}
	return cssKeyword[prefixLen:], true
}

// cssSchemaCSSWideKeywords are the CSS-wide keywords, which every CSS
// property accepts as its entire value.  They only ever reset a property to a
// value the cascade already chose, so they carry no attacker-controlled
// content.  See https://www.w3.org/TR/css-cascade-4/#defaulting-keywords
var cssSchemaCSSWideKeywords = []string{
	"inherit", "initial", "revert", "revert-layer", "unset"}

// cssSchemaDefinitions maps lower-cased CSS property names to information
// about them.
var cssSchemaDefinitions = cssSchemaBuildDefinitions()

func cssSchemaBuildDefinitions() map[string]*CSSSchemaProperty {
	var zeroFns map[string]string
	builder := map[string]*CSSSchemaProperty{}
	prop := cssSchemaNewProperty
	mozBorderRadiusLiterals0 := []string{"/"}
	mozOpacityLiterals0 := []string{"inherit"}
	mozOutlineLiterals0 := []string{
		"aliceblue", "antiquewhite", "aqua", "aquamarine", "azure", "beige",
		"bisque", "black", "blanchedalmond", "blue", "blueviolet", "brown",
		"burlywood", "cadetblue", "chartreuse", "chocolate", "coral",
		"cornflowerblue", "cornsilk", "crimson", "cyan", "darkblue", "darkcyan",
		"darkgoldenrod", "darkgray", "darkgreen", "darkkhaki", "darkmagenta",
		"darkolivegreen", "darkorange", "darkorchid", "darkred", "darksalmon",
		"darkseagreen", "darkslateblue", "darkslategray", "darkturquoise",
		"darkviolet", "deeppink", "deepskyblue", "dimgray", "dodgerblue",
		"firebrick", "floralwhite", "forestgreen", "fuchsia", "gainsboro",
		"ghostwhite", "gold", "goldenrod", "gray", "green", "greenyellow",
		"honeydew", "hotpink", "indianred", "indigo", "ivory", "khaki",
		"lavender", "lavenderblush", "lawngreen", "lemonchiffon", "lightblue",
		"lightcoral", "lightcyan", "lightgoldenrodyellow", "lightgreen",
		"lightgrey", "lightpink", "lightsalmon", "lightseagreen",
		"lightskyblue", "lightslategray", "lightsteelblue", "lightyellow",
		"lime", "limegreen", "linen", "magenta", "maroon", "mediumaquamarine",
		"mediumblue", "mediumorchid", "mediumpurple", "mediumseagreen",
		"mediumslateblue", "mediumspringgreen", "mediumturquoise",
		"mediumvioletred", "midnightblue", "mintcream", "mistyrose",
		"moccasin", "navajowhite", "navy", "oldlace", "olive", "olivedrab",
		"orange", "orangered", "orchid", "palegoldenrod", "palegreen",
		"paleturquoise", "palevioletred", "papayawhip", "peachpuff", "peru",
		"pink", "plum", "powderblue", "purple", "red", "rosybrown", "royalblue",
		"saddlebrown", "salmon", "sandybrown", "seagreen", "seashell", "sienna",
		"silver", "skyblue", "slateblue", "slategray", "snow", "springgreen",
		"steelblue", "tan", "teal", "thistle", "tomato", "turquoise", "violet",
		"wheat", "white", "whitesmoke", "yellow", "yellowgreen"}
	mozOutlineLiterals1 := []string{
		"dashed", "dotted", "double", "groove", "outset", "ridge", "solid"}
	mozOutlineLiterals2 := []string{"thick", "thin"}
	mozOutlineLiterals3 := []string{
		"hidden", "inherit", "inset", "invert", "medium", "none"}
	mozOutlineFunctions := map[string]string{
		"rgb(": "rgb()", "rgba(": "rgba()",
		"hsl(": "hsl()", "hsla(": "hsla()"}
	mozOutlineColorLiterals0 := []string{"inherit", "invert"}
	mozOutlineStyleLiterals0 := []string{"hidden", "inherit", "inset", "none"}
	mozOutlineWidthLiterals0 := []string{"inherit", "medium"}
	oTextOverflowLiterals0 := []string{"clip", "ellipsis"}
	azimuthLiterals0 := []string{
		"behind", "center-left", "center-right", "far-left", "far-right",
		"left-side", "leftwards", "right-side", "rightwards"}
	azimuthLiterals1 := []string{"left", "right"}
	azimuthLiterals2 := []string{"center", "inherit"}
	backgroundLiterals0 := []string{
		"border-box", "contain", "content-box", "cover", "padding-box"}
	backgroundLiterals1 := []string{"no-repeat", "repeat-x", "repeat-y", "round", "space"}
	backgroundLiterals2 := []string{"bottom", "top"}
	backgroundLiterals3 := []string{
		",", "/", "auto", "center", "fixed", "inherit", "local", "none",
		"repeat", "scroll", "transparent"}
	backgroundFunctions := map[string]string{
		"image(":                     "image()",
		"linear-gradient(":           "linear-gradient()",
		"radial-gradient(":           "radial-gradient()",
		"repeating-linear-gradient(": "repeating-linear-gradient()",
		"repeating-radial-gradient(": "repeating-radial-gradient()",
		"conic-gradient(":            "conic-gradient()",
		"repeating-conic-gradient(":  "repeating-conic-gradient()",
		"rgb(":                       "rgb()", "rgba(": "rgba()",
		"hsl(": "hsl()", "hsla(": "hsla()"}
	backgroundAttachmentLiterals0 := []string{",", "fixed", "local", "scroll"}
	backgroundColorLiterals0 := []string{"inherit", "transparent"}
	backgroundImageLiterals0 := []string{",", "none"}
	backgroundImageFunctions := map[string]string{
		"image(":                     "image()",
		"linear-gradient(":           "linear-gradient()",
		"radial-gradient(":           "radial-gradient()",
		"repeating-linear-gradient(": "repeating-linear-gradient()",
		"repeating-radial-gradient(": "repeating-radial-gradient()",
		"conic-gradient(":            "conic-gradient()",
		"repeating-conic-gradient(":  "repeating-conic-gradient()"}
	backgroundPositionLiterals0 := []string{
		",", "center"}
	backgroundRepeatLiterals0 := []string{
		",", "repeat"}
	borderLiterals0 := []string{
		"hidden", "inherit", "inset", "medium", "none", "transparent"}
	borderCollapseLiterals0 := []string{
		"collapse", "inherit", "separate"}
	bottomLiterals0 := []string{"auto", "inherit"}
	boxShadowLiterals0 := []string{
		",", "inset", "none"}
	// Arithmetic inside calc().  Operands are limited to numbers, dimensions
	// and percentages, so nested functions such as var(), attr() and url()
	// are stripped.  A bare "-" lexes as an identifier rather than as
	// punctuation, but both paths consult this literal set.
	calcFunLiterals0 := []string{
		"+", "-", "*", "/", "(", ")"}
	calcFunctions := map[string]string{
		"calc(": "calc()"}
	clearLiterals0 := []string{
		"both", "inherit", "none"}
	clipFunctions := map[string]string{"rect(": "rect()"}
	contentLiterals0 := []string{"none", "normal"}
	cueLiterals0 := []string{"inherit", "none"}
	cursorLiterals0 := []string{
		"all-scroll", "col-resize", "crosshair", "default", "e-resize",
		"hand", "help", "move", "n-resize", "ne-resize", "no-drop",
		"not-allowed", "nw-resize", "pointer", "progress", "row-resize",
		"s-resize", "se-resize", "sw-resize", "text", "vertical-text",
		"w-resize", "wait"}
	cursorLiterals1 := []string{
		",", "auto", "inherit"}
	directionLiterals0 := []string{"ltr", "rtl"}
	displayLiterals0 := []string{
		"-moz-inline-box", "-moz-inline-stack", "block", "inline",
		"inline-block", "inline-table", "list-item", "run-in", "table",
		"table-caption", "table-cell", "table-column", "table-column-group",
		"table-footer-group", "table-header-group", "table-row",
		"table-row-group",
		// Flexbox and grid formatting contexts.  "display" is not in
		// DEFAULT_WHITELIST, so these only take effect for a policy that
		// opts into layout; see the note above GRID/FLEX below.
		"flex", "inline-flex", "grid", "inline-grid", "flow-root"}
	elevationLiterals0 := []string{
		"above", "below", "higher", "level", "lower"}
	emptyCellsLiterals0 := []string{"hide", "show"}
	fontLiterals0 := []string{
		"100", "200", "300", "400", "500", "600", "700", "800", "900", "bold",
		"bolder", "lighter"}
	fontLiterals1 := []string{
		"large", "larger", "small", "smaller", "x-large", "x-small",
		"xx-large", "xx-small", "xxx-large", "medium"}
	fontLiterals2 := []string{
		"caption", "icon", "menu", "message-box", "small-caption",
		"status-bar"}
	fontLiterals3 := []string{
		"cursive", "fantasy", "monospace", "sans-serif", "serif",
		// The rest of the generic families from CSS Fonts.  A generic family
		// is a keyword, so it must not be quoted; without these they fell
		// through to the quoted-name path and stopped working.
		"system-ui", "ui-serif", "ui-sans-serif", "ui-monospace", "ui-rounded",
		"math", "emoji", "fangsong",
		// Not in the spec, but keyword-like in practice and broken by
		// quoting, so treated the same way.
		"-apple-system"}
	fontLiterals4 := []string{"italic", "oblique"}
	fontLiterals5 := []string{
		",", "/", "inherit", "medium", "normal", "small-caps"}
	fontFamilyLiterals0 := []string{",", "inherit"}
	fontStretchLiterals0 := []string{
		"condensed", "expanded", "extra-condensed", "extra-expanded",
		"narrower", "semi-condensed", "semi-expanded", "ultra-condensed",
		"ultra-expanded", "wider"}
	fontStretchLiterals1 := []string{"normal"}
	fontStyleLiterals0 := []string{
		"inherit", "normal"}
	fontVariantLiterals0 := []string{
		"inherit", "normal", "small-caps"}
	listStyleLiterals0 := []string{
		"armenian", "cjk-decimal", "decimal", "decimal-leading-zero", "disc",
		"disclosure-closed", "disclosure-open", "ethiopic-numeric", "georgian",
		"hebrew", "hiragana", "hiragana-iroha", "japanese-formal",
		"japanese-informal", "katakana", "katakana-iroha",
		"korean-hangul-formal", "korean-hanja-formal",
		"korean-hanja-informal", "lower-alpha", "lower-greek", "lower-latin",
		"lower-roman", "simp-chinese-formal", "simp-chinese-informal",
		"square", "trad-chinese-formal", "trad-chinese-informal",
		"upper-alpha", "upper-latin", "upper-roman"}
	listStyleLiterals1 := []string{
		"inside", "outside"}
	listStyleLiterals2 := []string{
		"circle", "inherit", "none"}
	maxHeightLiterals0 := []string{
		"auto", "inherit", "none"}
	overflowLiterals0 := []string{
		"auto", "hidden", "inherit", "scroll", "visible"}
	overflowWrapLiterals0 := []string{
		"normal", "break-word", "anywhere", "inherit"}
	overflowXLiterals0 := []string{
		"no-content", "no-display"}
	overflowXLiterals1 := []string{
		"auto", "hidden", "scroll", "visible"}
	pageBreakAfterLiterals0 := []string{
		"always", "auto", "avoid", "inherit"}
	pageBreakInsideLiterals0 := []string{
		"auto", "avoid", "inherit"}
	pitchLiterals0 := []string{
		"high", "low", "x-high", "x-low"}
	playDuringLiterals0 := []string{
		"auto", "inherit", "mix", "none", "repeat"}
	positionLiterals0 := []string{
		"absolute", "relative", "static"}
	speakLiterals0 := []string{
		"inherit", "none", "normal", "spell-out"}
	speakHeaderLiterals0 := []string{
		"always", "inherit", "once"}
	speakNumeralLiterals0 := []string{
		"continuous", "digits"}
	speakPunctuationLiterals0 := []string{
		"code", "inherit", "none"}
	speechRateLiterals0 := []string{
		"fast", "faster", "slow", "slower", "x-fast", "x-slow"}
	tableLayoutLiterals0 := []string{
		"auto", "fixed", "inherit"}
	textAlignLiterals0 := []string{
		"center", "end", "inherit", "justify", "justify-all", "match-parent",
		"start", "left", "right", "initial", "revert", "revert-layer", "unset"}
	textDecorationLiterals0 := []string{
		"blink", "line-through", "overline", "underline"}
	textDecorationStyleLiterals0 := []string{
		"dashed", "dotted", "double", "solid", "wavy"}
	textDecorationLineLiterals0 := []string{
		"blink", "grammar-error", "line-through", "none", "overline",
		"spelling-error", "underline"}
	textDecorationThicknessLiterals0 := []string{
		"auto", "from-font"}
	textTransformLiterals0 := []string{
		"capitalize", "lowercase", "uppercase"}
	textWrapLiterals0 := []string{
		"suppress", "unrestricted"}
	unicodeBidiLiterals0 := []string{
		"bidi-override", "embed"}
	verticalAlignLiterals0 := []string{
		"baseline", "middle", "sub", "super", "text-bottom", "text-top"}
	visibilityLiterals0 := []string{
		"collapse", "hidden", "inherit", "visible"}
	voiceFamilyLiterals0 := []string{
		"child", "female", "male"}
	volumeLiterals0 := []string{
		"loud", "silent", "soft", "x-loud", "x-soft"}
	whiteSpaceLiterals0 := []string{
		"-moz-pre-wrap", "-o-pre-wrap", "-pre-wrap", "nowrap", "pre",
		"pre-line", "pre-wrap"}
	wordBreakLiterals0 := []string{
		"break-all", "break-word", "keep-all", "normal"}
	wordWrapLiterals0 := []string{
		"anywhere", "break-word", "normal"}
	rgbFunLiterals0 := []string{","}
	linearGradientFunLiterals0 := []string{
		",", "to"}
	radialGradientFunLiterals0 := []string{
		"at", "closest-corner", "closest-side", "ellipse", "farthest-corner",
		"farthest-side"}
	radialGradientFunLiterals1 := []string{
		",", "center", "circle"}
	rectFunLiterals0 := []string{",", "auto"}
	mozBorderRadius := prop(5, mozBorderRadiusLiterals0, zeroFns)
	builder["-moz-border-radius"] = mozBorderRadius
	mozBorderRadiusBottomleft := prop(5, []string{}, zeroFns)
	builder["-moz-border-radius-bottomleft"] = mozBorderRadiusBottomleft
	mozOpacity := prop(1, mozOpacityLiterals0, zeroFns)
	builder["-moz-opacity"] = mozOpacity
	mozOutline := prop(
		7,
		cssSchemaUnionLiterals(mozOutlineLiterals0, mozOutlineLiterals1, mozOutlineLiterals2,
			mozOutlineLiterals3),
		mozOutlineFunctions)
	builder["-moz-outline"] = mozOutline
	mozOutlineColor := prop(
		2, cssSchemaUnionLiterals(mozOutlineColorLiterals0, mozOutlineLiterals0),
		mozOutlineFunctions)
	builder["-moz-outline-color"] = mozOutlineColor
	mozOutlineStyle := prop(
		0, cssSchemaUnionLiterals(mozOutlineLiterals1, mozOutlineStyleLiterals0), zeroFns)
	builder["-moz-outline-style"] = mozOutlineStyle
	mozOutlineWidth := prop(
		5, cssSchemaUnionLiterals(mozOutlineLiterals2, mozOutlineWidthLiterals0), zeroFns)
	builder["-moz-outline-width"] = mozOutlineWidth
	oTextOverflow := prop(0, oTextOverflowLiterals0, zeroFns)
	builder["-o-text-overflow"] = oTextOverflow
	azimuth := prop(
		5, cssSchemaUnionLiterals(azimuthLiterals0, azimuthLiterals1, azimuthLiterals2),
		zeroFns)
	builder["azimuth"] = azimuth
	background := prop(
		23,
		cssSchemaUnionLiterals(azimuthLiterals1, backgroundLiterals0, backgroundLiterals1,
			backgroundLiterals2, backgroundLiterals3, mozOutlineLiterals0),
		backgroundFunctions)
	builder["background"] = background
	builder["background-attachment"] = prop(0, backgroundAttachmentLiterals0, zeroFns)
	backgroundColor := prop(
		258, cssSchemaUnionLiterals(backgroundColorLiterals0, mozOutlineLiterals0),
		mozOutlineFunctions)
	builder["background-color"] = backgroundColor
	builder["background-image"] = prop(16, backgroundImageLiterals0,
		backgroundImageFunctions)
	backgroundPosition := prop(
		5,
		cssSchemaUnionLiterals(azimuthLiterals1, backgroundLiterals2,
			backgroundPositionLiterals0),
		zeroFns)
	builder["background-position"] = backgroundPosition
	backgroundRepeat := prop(
		0, cssSchemaUnionLiterals(backgroundLiterals1, backgroundRepeatLiterals0), zeroFns)
	builder["background-repeat"] = backgroundRepeat
	border := prop(
		7,
		cssSchemaUnionLiterals(borderLiterals0, mozOutlineLiterals0, mozOutlineLiterals1,
			mozOutlineLiterals2),
		mozOutlineFunctions)
	builder["border"] = border
	borderBottomColor := prop(
		2, cssSchemaUnionLiterals(backgroundColorLiterals0, mozOutlineLiterals0),
		mozOutlineFunctions)
	builder["border-bottom-color"] = borderBottomColor
	builder["border-collapse"] = prop(0, borderCollapseLiterals0, zeroFns)
	borderSpacing := prop(5, mozOpacityLiterals0, zeroFns)
	builder["border-spacing"] = borderSpacing
	bottom := prop(5, bottomLiterals0, zeroFns)
	builder["bottom"] = bottom
	boxShadow := prop(
		7, cssSchemaUnionLiterals(boxShadowLiterals0, mozOutlineLiterals0), mozOutlineFunctions)
	builder["box-shadow"] = boxShadow
	captionSide := prop(
		0, cssSchemaUnionLiterals(backgroundLiterals2, mozOpacityLiterals0), zeroFns)
	builder["caption-side"] = captionSide
	clear := prop(
		0, cssSchemaUnionLiterals(azimuthLiterals1, clearLiterals0), zeroFns)
	builder["clear"] = clear
	builder["clip"] = prop(0, bottomLiterals0, clipFunctions)
	color := prop(
		258, cssSchemaUnionLiterals(mozOpacityLiterals0, mozOutlineLiterals0),
		mozOutlineFunctions)
	builder["color"] = color
	builder["content"] = prop(8, contentLiterals0, zeroFns)
	cue := prop(16, cueLiterals0, zeroFns)
	builder["cue"] = cue
	cursor := prop(
		272, cssSchemaUnionLiterals(cursorLiterals0, cursorLiterals1), zeroFns)
	builder["cursor"] = cursor
	direction := prop(
		0, cssSchemaUnionLiterals(directionLiterals0, mozOpacityLiterals0), zeroFns)
	builder["direction"] = direction
	display := prop(
		0, cssSchemaUnionLiterals(cueLiterals0, displayLiterals0), zeroFns)
	builder["display"] = display
	elevation := prop(
		5, cssSchemaUnionLiterals(elevationLiterals0, mozOpacityLiterals0), zeroFns)
	builder["elevation"] = elevation
	emptyCells := prop(
		0, cssSchemaUnionLiterals(emptyCellsLiterals0, mozOpacityLiterals0), zeroFns)
	builder["empty-cells"] = emptyCells
	cssFloat := prop(
		0, cssSchemaUnionLiterals(azimuthLiterals1, cueLiterals0), zeroFns)
	builder["float"] = cssFloat
	font := prop(
		73,
		cssSchemaUnionLiterals(fontLiterals0, fontLiterals1, fontLiterals2, fontLiterals3,
			fontLiterals4, fontLiterals5),
		zeroFns)
	builder["font"] = font
	fontFamily := prop(
		72, cssSchemaUnionLiterals(fontFamilyLiterals0, fontLiterals3), zeroFns)
	builder["font-family"] = fontFamily
	fontSize := prop(
		1, cssSchemaUnionLiterals(fontLiterals1, mozOutlineWidthLiterals0), zeroFns)
	builder["font-size"] = fontSize
	fontStretch := prop(
		0, cssSchemaUnionLiterals(fontStretchLiterals0, fontStretchLiterals1), zeroFns)
	builder["font-stretch"] = fontStretch
	fontStyle := prop(
		0, cssSchemaUnionLiterals(fontLiterals4, fontStyleLiterals0), zeroFns)
	builder["font-style"] = fontStyle
	builder["font-variant"] = prop(
		0, fontVariantLiterals0, zeroFns)
	fontWeight := prop(
		0, cssSchemaUnionLiterals(fontLiterals0, fontStyleLiterals0), zeroFns)
	builder["font-weight"] = fontWeight
	height := prop(5, bottomLiterals0, calcFunctions)
	builder["height"] = height
	// top, left and right take the same values as height but are not on the
	// default white-list and do not admit calc().
	offset := prop(5, bottomLiterals0, zeroFns)
	letterSpacing := prop(5, fontStyleLiterals0, zeroFns)
	builder["letter-spacing"] = letterSpacing
	builder["line-height"] = prop(1, fontStyleLiterals0, zeroFns)
	listStyle := prop(
		16,
		cssSchemaUnionLiterals(listStyleLiterals0, listStyleLiterals1, listStyleLiterals2),
		backgroundImageFunctions)
	builder["list-style"] = listStyle
	builder["list-style-image"] = prop(
		16, cueLiterals0, backgroundImageFunctions)
	listStylePosition := prop(
		0, cssSchemaUnionLiterals(listStyleLiterals1, mozOpacityLiterals0), zeroFns)
	builder["list-style-position"] = listStylePosition
	listStyleType := prop(
		0, cssSchemaUnionLiterals(listStyleLiterals0, listStyleLiterals2), zeroFns)
	builder["list-style-type"] = listStyleType
	margin := prop(1, bottomLiterals0, zeroFns)
	builder["margin"] = margin
	// width, min-width and min-height take the same values as margin but
	// also admit calc().
	width := prop(1, bottomLiterals0, calcFunctions)
	maxHeight := prop(1, maxHeightLiterals0, calcFunctions)
	builder["max-height"] = maxHeight
	opacity := prop(1, mozOpacityLiterals0, zeroFns)
	builder["opacity"] = opacity
	builder["overflow"] = prop(0, overflowLiterals0, zeroFns)
	builder["overflow-wrap"] = prop(0, overflowWrapLiterals0, zeroFns)
	overflowX := prop(
		0, cssSchemaUnionLiterals(overflowXLiterals0, overflowXLiterals1), zeroFns)
	builder["overflow-x"] = overflowX
	padding := prop(1, mozOpacityLiterals0, zeroFns)
	builder["padding"] = padding
	pageBreakAfter := prop(
		0, cssSchemaUnionLiterals(azimuthLiterals1, pageBreakAfterLiterals0), zeroFns)
	builder["page-break-after"] = pageBreakAfter
	builder["page-break-inside"] = prop(
		0, pageBreakInsideLiterals0, zeroFns)
	pitch := prop(
		5, cssSchemaUnionLiterals(mozOutlineWidthLiterals0, pitchLiterals0), zeroFns)
	builder["pitch"] = pitch
	builder["play-during"] = prop(
		16, playDuringLiterals0, zeroFns)
	position := prop(
		0, cssSchemaUnionLiterals(mozOpacityLiterals0, positionLiterals0), zeroFns)
	builder["position"] = position
	builder["quotes"] = prop(8, cueLiterals0, zeroFns)
	builder["speak"] = prop(0, speakLiterals0, zeroFns)
	builder["speak-header"] = prop(
		0, speakHeaderLiterals0, zeroFns)
	speakNumeral := prop(
		0, cssSchemaUnionLiterals(mozOpacityLiterals0, speakNumeralLiterals0), zeroFns)
	builder["speak-numeral"] = speakNumeral
	builder["speak-punctuation"] = prop(
		0, speakPunctuationLiterals0, zeroFns)
	speechRate := prop(
		5, cssSchemaUnionLiterals(mozOutlineWidthLiterals0, speechRateLiterals0), zeroFns)
	builder["speech-rate"] = speechRate
	builder["table-layout"] = prop(
		0, tableLayoutLiterals0, zeroFns)
	textAlign := prop(
		0, cssSchemaUnionLiterals(azimuthLiterals1, textAlignLiterals0), zeroFns)
	builder["text-align"] = textAlign
	// The shorthand takes a line, a style and a colour in any order, so it
	// admits everything the three longhands below do.
	textDecoration := prop(
		2,
		cssSchemaUnionLiterals(cueLiterals0, textDecorationLiterals0,
			textDecorationStyleLiterals0, mozOutlineLiterals0),
		mozOutlineFunctions)
	builder["text-decoration"] = textDecoration
	textTransform := prop(
		0, cssSchemaUnionLiterals(cueLiterals0, textTransformLiterals0), zeroFns)
	builder["text-transform"] = textTransform
	textWrap := prop(
		0, cssSchemaUnionLiterals(contentLiterals0, textWrapLiterals0), zeroFns)
	builder["text-wrap"] = textWrap
	unicodeBidi := prop(
		0, cssSchemaUnionLiterals(fontStyleLiterals0, unicodeBidiLiterals0), zeroFns)
	builder["unicode-bidi"] = unicodeBidi
	verticalAlign := prop(
		5,
		cssSchemaUnionLiterals(backgroundLiterals2, mozOpacityLiterals0, verticalAlignLiterals0),
		zeroFns)
	builder["vertical-align"] = verticalAlign
	builder["visibility"] = prop(0, visibilityLiterals0, zeroFns)
	voiceFamily := prop(
		8, cssSchemaUnionLiterals(fontFamilyLiterals0, voiceFamilyLiterals0), zeroFns)
	builder["voice-family"] = voiceFamily
	volume := prop(
		1, cssSchemaUnionLiterals(mozOutlineWidthLiterals0, volumeLiterals0), zeroFns)
	builder["volume"] = volume
	whiteSpace := prop(
		0, cssSchemaUnionLiterals(fontStyleLiterals0, whiteSpaceLiterals0), zeroFns)
	builder["white-space"] = whiteSpace
	builder["word-break"] = prop(0, wordBreakLiterals0, zeroFns)
	builder["word-wrap"] = prop(0, wordWrapLiterals0, zeroFns)
	builder["zoom"] = prop(1, fontStretchLiterals1, zeroFns)
	rgbFun := prop(1, rgbFunLiterals0, zeroFns)
	builder["rgb()"] = rgbFun
	builder["rgba()"] = rgbFun
	builder["hsl()"] = rgbFun
	builder["hsla()"] = rgbFun
	builder["calc()"] = prop(5, calcFunLiterals0, zeroFns)
	imageFun := prop(
		18, cssSchemaUnionLiterals(mozOutlineLiterals0, rgbFunLiterals0), mozOutlineFunctions)
	builder["image()"] = imageFun
	linearGradientFun := prop(
		7,
		cssSchemaUnionLiterals(azimuthLiterals1, backgroundLiterals2,
			linearGradientFunLiterals0, mozOutlineLiterals0),
		mozOutlineFunctions)
	builder["linear-gradient()"] = linearGradientFun
	radialGradientFun := prop(
		7,
		cssSchemaUnionLiterals(azimuthLiterals1, backgroundLiterals2, mozOutlineLiterals0,
			radialGradientFunLiterals0, radialGradientFunLiterals1),
		mozOutlineFunctions)
	builder["radial-gradient()"] = radialGradientFun
	builder["rect()"] = prop(5, rectFunLiterals0, zeroFns)
	builder["-moz-border-radius-bottomright"] = mozBorderRadiusBottomleft
	builder["-moz-border-radius-topleft"] = mozBorderRadiusBottomleft
	builder["-moz-border-radius-topright"] = mozBorderRadiusBottomleft
	builder["-moz-box-shadow"] = boxShadow
	builder["-webkit-border-bottom-left-radius"] = mozBorderRadiusBottomleft
	builder["-webkit-border-bottom-right-radius"] = mozBorderRadiusBottomleft
	builder["-webkit-border-radius"] = mozBorderRadius
	builder["-webkit-border-radius-bottom-left"] = mozBorderRadiusBottomleft
	builder["-webkit-border-radius-bottom-right"] = mozBorderRadiusBottomleft
	builder["-webkit-border-radius-top-left"] = mozBorderRadiusBottomleft
	builder["-webkit-border-radius-top-right"] = mozBorderRadiusBottomleft
	builder["-webkit-border-top-left-radius"] = mozBorderRadiusBottomleft
	builder["-webkit-border-top-right-radius"] = mozBorderRadiusBottomleft
	builder["-webkit-box-shadow"] = boxShadow
	builder["border-bottom"] = border
	builder["border-bottom-left-radius"] = mozBorderRadiusBottomleft
	builder["border-bottom-right-radius"] = mozBorderRadiusBottomleft
	builder["border-bottom-style"] = mozOutlineStyle
	builder["border-bottom-width"] = mozOutlineWidth
	builder["border-color"] = borderBottomColor
	builder["border-left"] = border
	builder["border-left-color"] = borderBottomColor
	builder["border-left-style"] = mozOutlineStyle
	builder["border-left-width"] = mozOutlineWidth
	builder["border-radius"] = mozBorderRadius
	builder["border-right"] = border
	builder["border-right-color"] = borderBottomColor
	builder["border-right-style"] = mozOutlineStyle
	builder["border-right-width"] = mozOutlineWidth
	builder["border-style"] = mozOutlineStyle
	builder["border-top"] = border
	builder["border-top-color"] = borderBottomColor
	builder["border-top-left-radius"] = mozBorderRadiusBottomleft
	builder["border-top-right-radius"] = mozBorderRadiusBottomleft
	builder["border-top-style"] = mozOutlineStyle
	builder["border-top-width"] = mozOutlineWidth
	builder["border-width"] = mozOutlineWidth
	builder["cue-after"] = cue
	builder["cue-before"] = cue
	builder["left"] = offset
	builder["margin-bottom"] = margin
	builder["margin-left"] = margin
	builder["margin-right"] = margin
	builder["margin-top"] = margin
	builder["max-width"] = maxHeight
	builder["min-height"] = width
	builder["min-width"] = width
	builder["outline"] = mozOutline
	builder["outline-color"] = mozOutlineColor
	builder["outline-style"] = mozOutlineStyle
	builder["outline-width"] = mozOutlineWidth
	builder["overflow-y"] = overflowX
	builder["padding-bottom"] = padding
	builder["padding-left"] = padding
	builder["padding-right"] = padding
	builder["padding-top"] = padding
	builder["page-break-before"] = pageBreakAfter
	builder["pause"] = borderSpacing
	builder["pause-after"] = borderSpacing
	builder["pause-before"] = borderSpacing
	builder["pitch-range"] = borderSpacing
	builder["richness"] = borderSpacing
	builder["right"] = offset
	builder["stress"] = borderSpacing
	builder["text-indent"] = borderSpacing
	builder["text-overflow"] = oTextOverflow
	builder["text-shadow"] = boxShadow
	builder["top"] = offset
	builder["width"] = width
	builder["word-spacing"] = letterSpacing
	builder["z-index"] = bottom
	builder["repeating-linear-gradient()"] = linearGradientFun
	builder["repeating-radial-gradient()"] = radialGradientFun
	// ---- Decorative additions (safe for DEFAULT) -------------------------
	// These only change how an element paints itself.  They cannot move it,
	// hide it, or change how it participates in layout, so they go in
	// DEFAULT_WHITELIST alongside the properties they complement.

	builder["text-decoration-line"] = prop(0, textDecorationLineLiterals0, zeroFns)
	builder["text-decoration-style"] = prop(0, textDecorationStyleLiterals0, zeroFns)
	// Same shape as "color": a hash value, a named colour, or rgb()/hsl().
	builder["text-decoration-color"] = color
	builder["text-decoration-thickness"] = prop(1, textDecorationThicknessLiterals0, zeroFns)
	// SVG paint.  BIT_URL is deliberately not set: "stroke: url(#gradient)"
	// would be a URL vector, and a paint server reference is not worth one.
	strokeLiterals0 := cssSchemaUnionLiterals(
		mozOutlineLiterals0, []string{"currentcolor", "none", "transparent"})
	builder["stroke"] = prop(2, strokeLiterals0, mozOutlineFunctions)
	builder["stroke-width"] = prop(1, []string{}, zeroFns)
	// conic-gradient is an <image> like its linear and radial siblings, so it
	// takes the same shape as radial-gradient().
	conicGradientFun := prop(
		7,
		cssSchemaUnionLiterals(azimuthLiterals1, backgroundLiterals2, mozOutlineLiterals0,
			[]string{",", "at", "from"}),
		mozOutlineFunctions)
	builder["conic-gradient()"] = conicGradientFun
	builder["repeating-conic-gradient()"] = conicGradientFun
	// ---- Layout and transforms (definitions only, NOT in DEFAULT) --------
	// DEFAULT deliberately withholds every property that changes how an
	// element takes part in page layout -- display, position, float, clear,
	// overflow, z-index, opacity, visibility and the offsets -- so that a
	// style attribute can restyle content but cannot reposition it, overlay
	// something else, or hide it.  The families below are the modern
	// equivalents and are withheld on the same grounds.
	//
	// They are defined here so that a policy that wants them can opt in:
	//
	//   layout, _ := CSSSchemaWithProperties([]string{
	//       "display", "grid-template-columns", "gap", "repeat()", "minmax()"})
	//   schema, _ := CSSSchemaUnion(DefaultCSSSchema, layout)
	//
	// Note the "repeat()" and "minmax()" entries: a function is reached
	// through a schema key, and a key the schema does not contain resolves to
	// DISALLOWED, so a property must be opted into together with the
	// functions its values use.

	gridTrackLiterals0 := []string{
		",", "/", "auto", "auto-fill", "auto-fit", "max-content", "min-content",
		"none", "span", "masonry", "subgrid"}
	gridTrackFunctions := map[string]string{
		"repeat(":      "repeat()",
		"minmax(":      "minmax()",
		"fit-content(": "fit-content()",
		"calc(":        "calc()"}
	minmaxFun := prop(1, gridTrackLiterals0, zeroFns)
	builder["minmax()"] = minmaxFun
	builder["fit-content()"] = prop(1, []string{","}, zeroFns)
	// repeat() may nest minmax() and fit-content().
	builder["repeat()"] = prop(1, gridTrackLiterals0, gridTrackFunctions)
	gridTemplate := prop(1, gridTrackLiterals0, gridTrackFunctions)
	for _, name := range []string{
		"grid", "grid-template", "grid-template-columns", "grid-template-rows",
		"grid-auto-columns", "grid-auto-rows"} {
		builder[name] = gridTemplate
	}
	// Area names are quoted strings; they are never rendered as text.
	builder["grid-template-areas"] = prop(8, []string{"none"}, zeroFns)
	builder["grid-auto-flow"] = prop(0, []string{"column", "dense", "row"}, zeroFns)
	// Line-based placement: integers (which may be negative), "span", "auto"
	// and the "/" that separates start from end.
	gridLine := prop(
		5, []string{",", "/", "auto", "span"}, zeroFns)
	for _, name := range []string{
		"grid-area", "grid-column", "grid-column-end", "grid-column-start",
		"grid-row", "grid-row-end", "grid-row-start"} {
		builder[name] = gridLine
	}
	gap := prop(1, []string{"normal"}, zeroFns)
	for _, name := range []string{
		"gap", "row-gap", "column-gap",
		"grid-gap", "grid-row-gap", "grid-column-gap"} {
		builder[name] = gap
	}

	flexWrapLiterals0 := []string{
		"nowrap", "wrap", "wrap-reverse"}
	flexDirectionLiterals0 := []string{
		"column", "column-reverse", "row", "row-reverse"}
	flexBasisLiterals0 := []string{
		"auto", "content", "fit-content", "max-content", "min-content"}
	builder["flex-direction"] = prop(0, flexDirectionLiterals0, zeroFns)
	builder["flex-wrap"] = prop(0, flexWrapLiterals0, zeroFns)
	flexFlow := prop(
		0, cssSchemaUnionLiterals(flexDirectionLiterals0, flexWrapLiterals0), zeroFns)
	builder["flex-flow"] = flexFlow
	builder["flex-grow"] = prop(1, []string{}, zeroFns)
	builder["flex-shrink"] = prop(1, []string{}, zeroFns)
	flexBasis := prop(
		1, cssSchemaUnionLiterals(flexBasisLiterals0, []string{"none"}), zeroFns)
	builder["flex-basis"] = flexBasis
	flex := prop(
		1, cssSchemaUnionLiterals(flexBasisLiterals0, []string{"none", "initial"}), zeroFns)
	builder["flex"] = flex
	// "order" is one of the few layout properties that takes a negative.
	builder["order"] = prop(5, []string{}, zeroFns)
	alignmentLiterals0 := []string{
		"baseline", "center", "end", "first", "flex-end", "flex-start", "last",
		"left", "normal", "right", "safe", "self-end", "self-start",
		"space-around", "space-between", "space-evenly", "start", "stretch",
		"unsafe"}
	alignment := prop(0, alignmentLiterals0, zeroFns)
	alignmentOrAuto := prop(
		0, cssSchemaUnionLiterals(alignmentLiterals0, []string{"auto"}), zeroFns)
	for _, name := range []string{
		"align-content", "align-items", "justify-content", "justify-items",
		"place-content", "place-items"} {
		builder[name] = alignment
	}
	for _, name := range []string{
		"align-self", "justify-self", "place-self"} {
		builder[name] = alignmentOrAuto
	}

	// Transforms can move, scale and rotate an element, which is why they are
	// withheld from DEFAULT for the same reason "position" is.
	transformFun := prop(5, []string{","}, zeroFns)
	builder["transform-function()"] = transformFun
	transformFunctions := map[string]string{}
	for _, fn := range []string{
		"translate", "translatex", "translatey", "translatez", "translate3d",
		"rotate", "rotatex", "rotatey", "rotatez", "rotate3d",
		"scale", "scalex", "scaley", "scalez", "scale3d",
		"skew", "skewx", "skewy",
		"matrix", "matrix3d", "perspective"} {
		transformFunctions[fn+"("] = "transform-function()"
	}
	builder["transform"] = prop(0, []string{"none"}, transformFunctions)
	builder["transform-origin"] = prop(
		5,
		[]string{"bottom", "center", "left", "right", "top"},
		zeroFns)

	// Fold the CSS-wide keywords into every property, rather than repeating
	// them in each literal set above.  Keys ending in "()" describe the
	// arguments of a function, not a property, and are left alone: "initial"
	// is a value for "color", not for the red channel of "rgb(...)".
	// Definitions are shared between properties -- "pause-after" and
	// "richness" are the same object -- so widen each distinct one once and
	// keep the sharing.
	widened := map[*CSSSchemaProperty]*CSSSchemaProperty{}
	for name, narrow := range builder {
		if strings.HasSuffix(name, "()") {
			continue
		}
		wide, ok := widened[narrow]
		if !ok {
			literals := cssSchemaCopySet(narrow.literals)
			for _, keyword := range cssSchemaCSSWideKeywords {
				literals[keyword] = struct{}{}
			}
			wide = NewCSSSchemaProperty(narrow.bits, literals, narrow.fnKeys)
			widened[narrow] = wide
		}
		builder[name] = wide
	}
	return builder
}

// cssSchemaUnionLiterals concatenates literal lists.
func cssSchemaUnionLiterals(subsets ...[]string) []string {
	var all []string
	for _, subset := range subsets {
		all = append(all, subset...)
	}
	return all
}

// cssSchemaDefaultWhitelist names the properties in DefaultCSSSchema.
var cssSchemaDefaultWhitelist = []string{
	"-moz-border-radius",
	"-moz-border-radius-bottomleft",
	"-moz-border-radius-bottomright",
	"-moz-border-radius-topleft",
	"-moz-border-radius-topright",
	"-moz-box-shadow",
	"-moz-outline",
	"-moz-outline-color",
	"-moz-outline-style",
	"-moz-outline-width",
	"-o-text-overflow",
	"-webkit-border-bottom-left-radius",
	"-webkit-border-bottom-right-radius",
	"-webkit-border-radius",
	"-webkit-border-radius-bottom-left",
	"-webkit-border-radius-bottom-right",
	"-webkit-border-radius-top-left",
	"-webkit-border-radius-top-right",
	"-webkit-border-top-left-radius",
	"-webkit-border-top-right-radius",
	"-webkit-box-shadow",
	"azimuth",
	"background",
	"background-attachment",
	"background-color",
	"background-image",
	"background-position",
	"background-repeat",
	"border",
	"border-bottom",
	"border-bottom-color",
	"border-bottom-left-radius",
	"border-bottom-right-radius",
	"border-bottom-style",
	"border-bottom-width",
	"border-collapse",
	"border-color",
	"border-left",
	"border-left-color",
	"border-left-style",
	"border-left-width",
	"border-radius",
	"border-right",
	"border-right-color",
	"border-right-style",
	"border-right-width",
	"border-spacing",
	"border-style",
	"border-top",
	"border-top-color",
	"border-top-left-radius",
	"border-top-right-radius",
	"border-top-style",
	"border-top-width",
	"border-width",
	"box-shadow",
	"calc()",
	"caption-side",
	"color",
	"cue",
	"cue-after",
	"cue-before",
	"direction",
	"elevation",
	"empty-cells",
	"font",
	"font-family",
	"font-size",
	"font-stretch",
	"font-style",
	"font-variant",
	"font-weight",
	"height",
	"image()",
	"letter-spacing",
	"line-height",
	"linear-gradient()",
	"list-style",
	"list-style-image",
	"list-style-position",
	"list-style-type",
	"margin",
	"margin-bottom",
	"margin-left",
	"margin-right",
	"margin-top",
	"max-height",
	"max-width",
	"min-height",
	"min-width",
	"outline",
	"outline-color",
	"outline-style",
	"outline-width",
	"padding",
	"padding-bottom",
	"padding-left",
	"padding-right",
	"padding-top",
	"pause",
	"pause-after",
	"pause-before",
	"pitch",
	"pitch-range",
	"quotes",
	"radial-gradient()",
	"conic-gradient()",
	"repeating-conic-gradient()",
	"rect()",
	"repeating-linear-gradient()",
	"repeating-radial-gradient()",
	"rgb()",
	"rgba()",
	"hsl()",
	"hsla()",
	"richness",
	"speak",
	"speak-header",
	"speak-numeral",
	"speak-punctuation",
	"speech-rate",
	"stress",
	"stroke",
	"stroke-width",
	"table-layout",
	"text-align",
	"text-decoration",
	"text-decoration-color",
	"text-decoration-line",
	"text-decoration-style",
	"text-decoration-thickness",
	"text-indent",
	"text-overflow",
	"text-shadow",
	"text-transform",
	"text-wrap",
	"unicode-bidi",
	"vertical-align",
	"voice-family",
	"volume",
	"white-space",
	"width",
	"word-spacing",
	"word-wrap",
}

// DefaultCSSSchema is a schema that includes only those properties on the
// default schema white-list.
//
// It withholds every property that changes how an element takes part in page
// layout -- display, position, float, clear, overflow, z-index, opacity,
// visibility and the offsets, and the modern flex, grid and transform
// families -- so that a style attribute can restyle content but cannot
// reposition it, overlay something else, or hide it.  Those properties are
// defined, so a policy that wants them can opt in with CSSSchemaUnion.
var DefaultCSSSchema = cssSchemaMustWithProperties(cssSchemaDefaultWhitelist)

// cssSchemaMustWithProperties is CSSSchemaWithProperties for names known to
// be defined.
func cssSchemaMustWithProperties(propertyNames []string) *CSSSchema {
	schema, err := CSSSchemaWithProperties(propertyNames)
	if err != nil {
		panic("undefined CSS property " + err.Error())
	}
	return schema
}

// cssSchemaSetOf makes a set of strings.
func cssSchemaSetOf(items []string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, item := range items {
		set[item] = struct{}{}
	}
	return set
}

// cssSchemaCopySet copies a set of strings.
func cssSchemaCopySet(set map[string]struct{}) map[string]struct{} {
	copied := make(map[string]struct{}, len(set))
	for item := range set {
		copied[item] = struct{}{}
	}
	return copied
}

// CSSSchemaNamedProperty pairs a CSS property name with its definition.  A
// slice of them is an ordered property map, the form CSSSchemaWithPropertyMap
// and WithOverrides take, since the order decides which problem is reported
// first.
type CSSSchemaNamedProperty struct {
	// Name is the lower-case CSS property name.
	Name string
	// Property is the definition of the property.
	Property *CSSSchemaProperty
}

// cssSchemaOrderedProperties folds an ordered property list into names in
// order of first appearance and a map by name: a repeated name keeps its
// first position and takes its last definition.
func cssSchemaOrderedProperties(properties []CSSSchemaNamedProperty) ([]string, map[string]*CSSSchemaProperty) {
	names := make([]string, 0, len(properties))
	byName := make(map[string]*CSSSchemaProperty, len(properties))
	for _, p := range properties {
		if _, seen := byName[p.Name]; !seen {
			names = append(names, p.Name)
		}
		byName[p.Name] = p.Property
	}
	return names, byName
}

// cssSchemaSortedKeys returns the keys of m in byte order.
func cssSchemaSortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// cssSchemaSortedList formats the keys of m for an error message: sorted by
// UTF-16 code unit, comma-separated, in square brackets.
func cssSchemaSortedList[V any](m map[string]V) string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return slices.Compare(utf16Units(keys[i]), utf16Units(keys[j])) < 0
	})
	return "[" + strings.Join(keys, ", ") + "]"
}
