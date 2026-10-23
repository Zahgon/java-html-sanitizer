// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/StringsTest.java.

package sanitizer

import "testing"

func TestValidFloatingPointNumber(t *testing.T) {
	for _, tc := range []struct {
		value string
		start int
		want  int
	}{
		{"", 0, -1},
		{"123", 0, 3},
		{"123.456", 0, 7},
		{"123.456f", 0, 7},
		{" 123.456 ", 1, 8},
		{"1e", 0, -1},
		{"1.", 0, -1},
		{"1e+", 0, -1},
		{"1e+e", 0, -1},
		{" 1E-1", 1, 5},
		{" 1E+2 ", 1, 5},
		{" 1E+2,", 1, 5},
	} {
		if got := stringsSkipValidFloatingPointNumber(tc.value, tc.start); got != tc.want {
			t.Errorf("stringsSkipValidFloatingPointNumber(%q, %d) = %d, want %d",
				tc.value, tc.start, got, tc.want)
		}
	}
}
