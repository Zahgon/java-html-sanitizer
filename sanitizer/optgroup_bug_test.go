// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause
// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/OptgroupBugTest.java.

package sanitizer

import "testing"

// TestOptgroupInsideSelectDoesNotAddExtraSelectTags checks that optgroup
// elements inside select are not corrupted with extra select tags.
//
// Before the fix: <select><optgroup><select><option></option></select></optgroup></select>
// After the fix:  <select><optgroup><option></option></optgroup></select>
func TestOptgroupInsideSelectDoesNotAddExtraSelectTags(t *testing.T) {
	factory, err := NewHTMLPolicyBuilder().
		AllowElements("select", "optgroup", "option").
		AllowAttributes("label").Globally().
		ToFactory()
	if err != nil {
		t.Fatal(err)
	}

	input := `<select><optgroup label="mygroup"><option>My option</option></optgroup></select>`
	result := factory.Sanitize(input)

	// The key assertion: no extra select tags should be inserted.
	if result != input {
		t.Errorf("Sanitize(%q) = %q, want it unchanged", input, result)
	}
}
