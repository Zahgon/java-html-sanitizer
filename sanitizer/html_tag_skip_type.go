// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/HtmlTagSkipType.java.

package sanitizer

import "strconv"

// HTMLTagSkipType says whether an element that the policy allows is dropped
// when it has no attributes, and whether that choice was made explicitly or
// is a default.
type HTMLTagSkipType int

const (
	// HTMLTagSkipTypeSkip skips the element, as explicitly requested.
	HTMLTagSkipTypeSkip HTMLTagSkipType = iota
	// HTMLTagSkipTypeSkipByDefault skips the element by default.
	HTMLTagSkipTypeSkipByDefault
	// HTMLTagSkipTypeDoNotSkip keeps the element, as explicitly requested.
	HTMLTagSkipTypeDoNotSkip
	// HTMLTagSkipTypeDoNotSkipByDefault keeps the element by default.
	HTMLTagSkipTypeDoNotSkipByDefault
)

// And combines two skip types: an explicit choice wins over a default, and
// when both are explicit and differ, the element is kept.
func (t HTMLTagSkipType) And(s HTMLTagSkipType) HTMLTagSkipType {
	if t == s || s == HTMLTagSkipTypeSkipByDefault {
		return t
	}

	if s == HTMLTagSkipTypeDoNotSkip {
		return s
	}

	if s == HTMLTagSkipTypeDoNotSkipByDefault {
		return t
	}

	return HTMLTagSkipTypeSkip
}

// SkipAvailability reports whether an element of this skip type is dropped
// when it has no attributes.
func (t HTMLTagSkipType) SkipAvailability() bool {
	return t == HTMLTagSkipTypeSkip || t == HTMLTagSkipTypeSkipByDefault
}

// String returns the upper-case name of the skip type, such as "SKIP_BY_DEFAULT".
func (t HTMLTagSkipType) String() string {
	switch t {
	case HTMLTagSkipTypeSkip:
		return "SKIP"
	case HTMLTagSkipTypeSkipByDefault:
		return "SKIP_BY_DEFAULT"
	case HTMLTagSkipTypeDoNotSkip:
		return "DO_NOT_SKIP"
	case HTMLTagSkipTypeDoNotSkipByDefault:
		return "DO_NOT_SKIP_BY_DEFAULT"
	}
	return "HTMLTagSkipType(" + strconv.Itoa(int(t)) + ")"
}
