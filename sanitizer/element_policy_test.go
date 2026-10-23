// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/ElementPolicyTest.java.

package sanitizer

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// elementPolicyTestHasCharElementPolicy allows the elements whose names
// contain a character, clearing the attributes either way.
type elementPolicyTestHasCharElementPolicy struct {
	ch rune
}

func (p *elementPolicyTestHasCharElementPolicy) Apply(elementName string, attrs *[]string) (string, bool) {
	*attrs = (*attrs)[:0]
	if !strings.ContainsRune(elementName, p.ch) {
		return "", false
	}
	return elementName, true
}

func (p *elementPolicyTestHasCharElementPolicy) String() string {
	return fmt.Sprintf("(has '%c')", p.ch)
}

var elementPolicyTestElNames = []string{
	"abacus", "abracadabra", "bar", "foo", "far", "cadr", "cdr",
}

func elementPolicyTestAssertPassed(t *testing.T, p ElementPolicy, expected ...string) {
	t.Helper()
	var attrs []string
	actual := []string{}
	for _, elName := range elementPolicyTestElNames {
		if _, ok := p.Apply(elName, &attrs); ok {
			actual = append(actual, elName)
		}
	}
	if expected == nil {
		expected = []string{}
	}
	if !slices.Equal(expected, actual) {
		t.Errorf("%v: got %q, want %q", p, actual, expected)
	}
}

func TestElementPolicyJoin(t *testing.T) {
	a := &elementPolicyTestHasCharElementPolicy{'a'}
	b := &elementPolicyTestHasCharElementPolicy{'b'}
	c := &elementPolicyTestHasCharElementPolicy{'c'}
	d := &elementPolicyTestHasCharElementPolicy{'d'}
	elementPolicyTestAssertPassed(t, RejectAllElementPolicy)
	elementPolicyTestAssertPassed(t, IdentityElementPolicy, elementPolicyTestElNames...)
	elementPolicyTestAssertPassed(t, a, "abacus", "abracadabra", "bar", "far", "cadr")
	elementPolicyTestAssertPassed(t, c, "abacus", "abracadabra", "cadr", "cdr")
	elementPolicyTestAssertPassed(t, d, "abracadabra", "cadr", "cdr")
	aB := JoinElementPolicies(a, b)
	bA := JoinElementPolicies(b, a)
	elementPolicyTestAssertPassed(t, aB, "abacus", "abracadabra", "bar")
	elementPolicyTestAssertPassed(t, bA, "abacus", "abracadabra", "bar")
	elementPolicyTestAssertPassed(t, JoinElementPolicies(bA, bA), "abacus", "abracadabra", "bar")
	elementPolicyTestAssertPassed(t, JoinElementPolicies(aB, c), "abacus", "abracadabra")
	elementPolicyTestAssertPassed(t, JoinElementPolicies(c, RejectAllElementPolicy))
	elementPolicyTestAssertPassed(t, JoinElementPolicies(RejectAllElementPolicy, aB))
}
