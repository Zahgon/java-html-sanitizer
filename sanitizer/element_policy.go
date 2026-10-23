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

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/ElementPolicy.java.

package sanitizer

// ElementPolicy is a policy that can be applied to an element to decide
// whether or not to allow it in the output, possibly after transforming
// attributes.
//
// Element policies are applied after attribute policies so they can be used
// to add extra attributes.
//
// See HTMLPolicyBuilder.AllowElementsWithPolicy.
type ElementPolicy interface {
	// Apply is given the lower-case element name and a list of alternating
	// attribute names and values.  The list may be added to or removed from
	// through the pointer.  When removing, be careful to remove both the name
	// and its associated value.
	//
	// It returns the adjusted element name and true, or false to disallow
	// the element.
	Apply(elementName string, attrs *[]string) (string, bool)
}

// ElementPolicyFunc adapts an ordinary function to an ElementPolicy.
//
// Functions cannot be compared in Go, so when policies are joined each
// ElementPolicyFunc value counts as distinct from every other policy, even
// from another use of the same function.
type ElementPolicyFunc func(elementName string, attrs *[]string) (string, bool)

// Apply calls f(elementName, attrs).
func (f ElementPolicyFunc) Apply(elementName string, attrs *[]string) (string, bool) {
	return f(elementName, attrs)
}

// JoinElementPolicies returns an element policy equivalent to applying the
// given element policies in order, failing early if any of them fails.
// Nil policies are ignored.
func JoinElementPolicies(policies ...ElementPolicy) ElementPolicy {
	joiner := newElementPolicyUtilPolicyJoiner()
	for _, p := range policies {
		if p != nil {
			joiner.unroll(p)
		}
	}
	return joiner.join()
}

// newElementPolicyUtilPolicyJoiner returns a join helper that flattens joined
// element policies and groups the special joinable ones.
func newElementPolicyUtilPolicyJoiner() *joinableJoinHelper[ElementPolicy, JoinableElementPolicy] {
	return &joinableJoinHelper[ElementPolicy, JoinableElementPolicy]{
		zeroValue:     RejectAllElementPolicy,
		identityValue: IdentityElementPolicy,
		split: func(x ElementPolicy) ([]ElementPolicy, bool) {
			if j, ok := x.(*joinedElementPolicy); ok {
				return j.policies, true
			}
			return nil, false
		},
		rejoin: func(xs []ElementPolicy) ElementPolicy {
			return newJoinedElementPolicy(xs)
		},
	}
}

// identityElementPolicy is the type of IdentityElementPolicy.
type identityElementPolicy struct{}

// Apply returns elementName unchanged.
func (identityElementPolicy) Apply(elementName string, _ *[]string) (string, bool) {
	return elementName, true
}

// rejectAllElementPolicy is the type of RejectAllElementPolicy.
type rejectAllElementPolicy struct{}

// Apply rejects the element.
func (rejectAllElementPolicy) Apply(string, *[]string) (string, bool) {
	return "", false
}

// IdentityElementPolicy is an element policy that returns the
// element unchanged.
var IdentityElementPolicy ElementPolicy = identityElementPolicy{}

// RejectAllElementPolicy is an element policy that rejects all
// elements.
var RejectAllElementPolicy ElementPolicy = rejectAllElementPolicy{}

// JoinableElementPolicy is an element policy that is joinable:
// policies that share a join strategy are combined by it rather than simply
// applied one after the other.  Only this package can implement it.
type JoinableElementPolicy interface {
	ElementPolicy
	joinStrategy() joinableJoinStrategy[JoinableElementPolicy]
}

// joinedElementPolicy applies several element policies in order.
type joinedElementPolicy struct {
	policies []ElementPolicy
}

// newJoinedElementPolicy returns a policy that applies a copy of policies in
// order.
func newJoinedElementPolicy(policies []ElementPolicy) *joinedElementPolicy {
	return &joinedElementPolicy{policies: append([]ElementPolicy(nil), policies...)}
}

// Apply applies each policy in turn to the name the previous one returned,
// stopping at the first that rejects the element.
func (p *joinedElementPolicy) Apply(elementName string, attrs *[]string) (string, bool) {
	filteredElementName := elementName
	for _, part := range p.policies {
		var ok bool
		filteredElementName, ok = part.Apply(filteredElementName, attrs)
		if !ok {
			return "", false
		}
	}
	return filteredElementName, true
}
