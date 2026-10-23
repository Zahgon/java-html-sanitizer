// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/OWASP/java-html-sanitizer/sanitizer"
)

// object is a JSON object that keeps its members in file order; a repeated
// key keeps its first position and takes its last value.
type object struct {
	keys   []string
	values map[string]any
}

// has reports whether o has a member named key.
func (o *object) has(key string) bool {
	_, ok := o.values[key]
	return ok
}

// parseJSON reads one JSON document whose numbers are all integers.  Objects
// become *object, arrays []any, numbers int64.
func parseJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing text")
	}
	return v, nil
}

// parseValue reads one JSON value from dec, as parseJSON describes.
func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			o := &object{values: map[string]any{}}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key := keyTok.(string)
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				if !o.has(key) {
					o.keys = append(o.keys, key)
				}
				o.values[key] = v
			}
			_, err := dec.Token()
			return o, err
		case '[':
			list := []any{}
			for dec.More() {
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				list = append(list, v)
			}
			_, err := dec.Token()
			return list, err
		}
		return nil, errors.New("unexpected delimiter")
	case json.Number:
		if strings.ContainsAny(string(t), ".eE") {
			return nil, errors.New("number is not an integer")
		}
		return strconv.ParseInt(string(t), 10, 64)
	default:
		return tok, nil // string, bool or nil
	}
}

// policyFromFile builds the policy that the policy file at path describes.
func policyFromFile(path string) (*sanitizer.PolicyFactory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, usagef("cannot read %s", filepath.Base(path))
	}
	doc, err := parseJSON(data)
	if err != nil {
		return nil, usagef("policy file is not valid JSON")
	}
	steps, ok := doc.([]any)
	if !ok {
		return nil, usagef("policy file must be a JSON array of steps")
	}
	b := sanitizer.NewHTMLPolicyBuilder()
	for _, step := range steps {
		if err := applyStep(b, step); err != nil {
			return nil, err
		}
		// The builder records its first error; stop there, as later steps
		// are never reached.
		if err := b.Err(); err != nil {
			return nil, err
		}
	}
	return b.ToFactory()
}

// builderMethods are the keys that name the builder method of a step.
var builderMethods = map[string]bool{
	"allowElements": true, "disallowElements": true, "allowCommonInlineFormattingElements": true,
	"allowCommonBlockElements": true, "allowTextIn": true, "disallowTextIn": true,
	"allowWithoutAttributes": true, "disallowWithoutAttributes": true, "allowAttributes": true,
	"disallowAttributes": true, "requireRelNofollowOnLinks": true, "requireRelsOnLinks": true,
	"skipRelsOnLinks": true, "allowUrlProtocols": true, "disallowUrlProtocols": true,
	"allowStandardUrlProtocols": true, "allowOnlyRelativeUrls": true, "allowStyling": true,
	"allowUrlsInStyles": true,
}

// renamePolicy maps every element it is given to one name.
type renamePolicy string

// Apply returns the new name.
func (p renamePolicy) Apply(string, *[]string) (string, bool) { return string(p), true }

// applyStep applies one policy-file step to b.
func applyStep(b *sanitizer.HTMLPolicyBuilder, step any) error {
	m, ok := step.(*object)
	if !ok {
		return usagef("a policy step must be a JSON object")
	}
	method := ""
	for _, k := range m.keys {
		if builderMethods[k] {
			if method != "" {
				return usagef("a policy step names more than one builder method")
			}
			method = k
		}
	}
	if method == "" {
		return usagef("a policy step names no builder method")
	}
	var extra []string
	for _, k := range m.keys {
		if k != method {
			extra = append(extra, k)
		}
	}
	arg := m.values[method]
	switch method {
	case "allowElements":
		if err := allowExtra(extra, "renameTo"); err != nil {
			return err
		}
		if m.has("renameTo") {
			to, err := str(m.values["renameTo"])
			if err != nil {
				return err
			}
			names, err := strs(arg)
			if err != nil {
				return err
			}
			b.AllowElementsWithPolicy(renamePolicy(to), names...)
			return nil
		}
		names, err := strs(arg)
		if err != nil {
			return err
		}
		b.AllowElements(names...)
		return nil
	case "allowAttributes", "disallowAttributes":
		return applyAttributeStep(b, method, m, arg, extra)
	case "allowStyling":
		if err := allowExtra(extra); err != nil {
			return err
		}
		if arg == true {
			b.AllowStyling()
			return nil
		}
		s, err := schema(arg)
		if err != nil {
			return err
		}
		b.AllowStylingWithSchema(s)
		return nil
	case "allowUrlsInStyles":
		if err := allowExtra(extra); err != nil {
			return err
		}
		p, err := attributePolicy(arg)
		if err != nil {
			return err
		}
		b.AllowURLsInStyles(p)
		return nil
	}
	if err := allowExtra(extra); err != nil {
		return err
	}
	switch method {
	case "allowCommonInlineFormattingElements", "allowCommonBlockElements", "requireRelNofollowOnLinks",
		"allowStandardUrlProtocols", "allowOnlyRelativeUrls":
		if arg != true {
			return usagef("this step takes true")
		}
		switch method {
		case "allowCommonInlineFormattingElements":
			b.AllowCommonInlineFormattingElements()
		case "allowCommonBlockElements":
			b.AllowCommonBlockElements()
		case "requireRelNofollowOnLinks":
			b.RequireRelNofollowOnLinks()
		case "allowStandardUrlProtocols":
			b.AllowStandardURLProtocols()
		default:
			b.AllowOnlyRelativeURLs()
		}
		return nil
	}
	names, err := strs(arg)
	if err != nil {
		return err
	}
	switch method {
	case "disallowElements":
		b.DisallowElements(names...)
	case "allowTextIn":
		b.AllowTextIn(names...)
	case "disallowTextIn":
		b.DisallowTextIn(names...)
	case "allowWithoutAttributes":
		b.AllowWithoutAttributes(names...)
	case "disallowWithoutAttributes":
		b.DisallowWithoutAttributes(names...)
	case "requireRelsOnLinks":
		b.RequireRelsOnLinks(names...)
	case "skipRelsOnLinks":
		b.SkipRelsOnLinks(names...)
	case "allowUrlProtocols":
		b.AllowURLProtocols(names...)
	case "disallowUrlProtocols":
		b.DisallowURLProtocols(names...)
	}
	return nil
}

// applyAttributeStep applies an allowAttributes or disallowAttributes step,
// with its matchers and its globally or onElements target, to b.
func applyAttributeStep(b *sanitizer.HTMLPolicyBuilder, method string, m *object, arg any, extra []string) error {
	if err := allowExtra(extra, "matching", "globally", "onElements"); err != nil {
		return err
	}
	names, err := strs(arg)
	if err != nil {
		return err
	}
	var ab *sanitizer.HTMLPolicyBuilderAttributeBuilder
	if method == "allowAttributes" {
		ab = b.AllowAttributes(names...)
	} else {
		ab = b.DisallowAttributes(names...)
	}
	if m.has("matching") {
		matchers, err := list(m.values["matching"])
		if err != nil {
			return err
		}
		for _, matcher := range matchers {
			if mm, ok := matcher.(*object); ok {
				for _, k := range mm.keys {
					if k != "values" && k != "ignoreCase" {
						return usagef("unknown matcher key %s", k)
					}
				}
				ignoreCase := false
				if mm.has("ignoreCase") {
					v, ok := mm.values["ignoreCase"].(bool)
					if !ok {
						return usagef("expected true or false")
					}
					ignoreCase = v
				}
				values, err := strs(mm.values["values"])
				if err != nil {
					return err
				}
				ab.MatchingValues(ignoreCase, values...)
			} else {
				p, err := attributePolicy(matcher)
				if err != nil {
					return err
				}
				ab.Matching(p)
			}
		}
	}
	if m.has("globally") == m.has("onElements") {
		return usagef("an attribute step needs exactly one of globally and onElements")
	}
	if m.has("globally") {
		if v, ok := m.values["globally"].(bool); !ok || !v {
			return usagef("globally must be true")
		}
		ab.Globally()
		return nil
	}
	elements, err := strs(m.values["onElements"])
	if err != nil {
		return err
	}
	ab.OnElements(elements...)
	return nil
}

// allowExtra returns a usage error if extra holds a key not in allowed.
func allowExtra(extra []string, allowed ...string) error {
	for _, k := range extra {
		ok := false
		for _, a := range allowed {
			ok = ok || k == a
		}
		if !ok {
			return usagef("unexpected key %s", k)
		}
	}
	return nil
}

// attributePolicy returns the attribute policy that "identity" or "reject"
// names.
func attributePolicy(v any) (sanitizer.AttributePolicy, error) {
	switch v {
	case "identity":
		return sanitizer.IdentityAttributePolicy, nil
	case "reject":
		return sanitizer.RejectAllAttributePolicy, nil
	}
	return nil, usagef("unknown attribute policy")
}

// schema builds the CSS schema that a SCHEMA value describes.
func schema(v any) (*sanitizer.CSSSchema, error) {
	if v == "default" {
		return sanitizer.DefaultCSSSchema, nil
	}
	m, ok := v.(*object)
	if !ok || len(m.keys) == 0 {
		return nil, usagef(`a schema must be "default" or a JSON object`)
	}
	if m.has("base") || m.has("overrides") {
		if len(m.keys) != 2 || !m.has("base") || !m.has("overrides") {
			return nil, usagef("an override schema needs exactly base and overrides")
		}
		base, err := schema(m.values["base"])
		if err != nil {
			return nil, err
		}
		overrides, err := properties(m.values["overrides"])
		if err != nil {
			return nil, err
		}
		return base.WithOverrides(overrides)
	}
	if len(m.keys) != 1 {
		return nil, usagef("a schema object has exactly one key")
	}
	k := m.keys[0]
	switch k {
	case "properties":
		names, err := strs(m.values[k])
		if err != nil {
			return nil, err
		}
		return sanitizer.CSSSchemaWithProperties(names)
	case "define":
		props, err := properties(m.values[k])
		if err != nil {
			return nil, err
		}
		return sanitizer.CSSSchemaWithPropertyMap(props)
	case "union", "intersection":
		parts, err := list(m.values[k])
		if err != nil {
			return nil, err
		}
		schemas := make([]*sanitizer.CSSSchema, len(parts))
		for i, p := range parts {
			if schemas[i], err = schema(p); err != nil {
				return nil, err
			}
		}
		if k == "union" {
			return sanitizer.CSSSchemaUnion(schemas...)
		}
		return sanitizer.CSSSchemaIntersection(schemas...)
	}
	return nil, usagef("unknown schema key %s", k)
}

// properties converts an object of PROPERTY values into an ordered property
// list.
func properties(v any) ([]sanitizer.CSSSchemaNamedProperty, error) {
	m, ok := v.(*object)
	if !ok {
		return nil, usagef("expected a JSON object")
	}
	out := make([]sanitizer.CSSSchemaNamedProperty, 0, len(m.keys))
	for _, k := range m.keys {
		p, err := property(m.values[k])
		if err != nil {
			return nil, err
		}
		out = append(out, sanitizer.CSSSchemaNamedProperty{Name: k, Property: p})
	}
	return out, nil
}

// property builds the CSS property that a PROPERTY value describes.
func property(v any) (*sanitizer.CSSSchemaProperty, error) {
	m, ok := v.(*object)
	if !ok {
		return nil, usagef("expected a JSON object")
	}
	if m.has("like") {
		if err := allowExtra(m.keys, "like", "withLiterals", "withoutLiterals", "withFunctions"); err != nil {
			return nil, err
		}
		name, err := str(m.values["like"])
		if err != nil {
			return nil, err
		}
		p := sanitizer.DefaultCSSSchema.Property(name)
		if p == nil {
			return nil, errors.New("unknown property " + name)
		}
		if m.has("withLiterals") {
			lits, err := strs(m.values["withLiterals"])
			if err != nil {
				return nil, err
			}
			p = p.WithLiterals(lits...)
		}
		if m.has("withoutLiterals") {
			lits, err := strs(m.values["withoutLiterals"])
			if err != nil {
				return nil, err
			}
			p = p.WithoutLiterals(lits...)
		}
		if m.has("withFunctions") {
			fns, err := strMap(m.values["withFunctions"])
			if err != nil {
				return nil, err
			}
			p = p.WithFunctions(fns)
		}
		return p, nil
	}
	if err := allowExtra(m.keys, "bits", "literals", "functions"); err != nil {
		return nil, err
	}
	bits, ok := m.values["bits"].(int64)
	if !ok {
		return nil, usagef("bits must be an integer")
	}
	literals := map[string]struct{}{}
	if m.has("literals") {
		lits, err := strs(m.values["literals"])
		if err != nil {
			return nil, err
		}
		for _, l := range lits {
			literals[l] = struct{}{}
		}
	}
	fns := map[string]string{}
	if m.has("functions") {
		var err error
		if fns, err = strMap(m.values["functions"]); err != nil {
			return nil, err
		}
	}
	// The bit set is 32 bits wide; wider values wrap.
	return sanitizer.NewCSSSchemaProperty(int(int32(bits)), literals, fns), nil
}

// list returns v as a JSON array.
func list(v any) ([]any, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, usagef("expected a JSON array")
	}
	return l, nil
}

// str returns v as a JSON string.
func str(v any) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", usagef("expected a JSON string")
	}
	return s, nil
}

// strs returns v as a JSON array of strings.
func strs(v any) ([]string, error) {
	l, err := list(v)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(l))
	for i, e := range l {
		if out[i], err = str(e); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// strMap returns v as a JSON object whose values are strings.
func strMap(v any) (map[string]string, error) {
	m, ok := v.(*object)
	if !ok {
		return nil, usagef("expected a JSON object")
	}
	out := make(map[string]string, len(m.keys))
	for _, k := range m.keys {
		s, err := str(m.values[k])
		if err != nil {
			return nil, err
		}
		out[k] = s
	}
	return out, nil
}
