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

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/AttributePolicy.java.

package sanitizer

// AttributePolicy is a policy that can be applied to an HTML attribute to
// decide whether or not to allow it in the output, possibly after
// transforming its value.
//
// See HTMLPolicyBuilderAttributeBuilder.Matching.
type AttributePolicy interface {
	// Apply is given the lower-case element name, the lower-case attribute
	// name and the attribute value without quotes and with HTML entities
	// decoded.  It returns the adjusted value and true if the attribute is
	// allowed, or false to disallow the attribute.
	Apply(elementName, attributeName, value string) (string, bool)
}

// AttributePolicyFunc adapts an ordinary function to an AttributePolicy.
//
// Functions cannot be compared in Go, so when policies are joined each
// AttributePolicyFunc value counts as distinct from every other policy, even
// from another use of the same function.  Implement AttributePolicy on a
// pointer type instead to have repeated uses of one policy recognized as such.
type AttributePolicyFunc func(elementName, attributeName, value string) (string, bool)

// Apply calls f(elementName, attributeName, value).
func (f AttributePolicyFunc) Apply(elementName, attributeName, value string) (string, bool) {
	return f(elementName, attributeName, value)
}

// JoinAttributePolicies returns an attribute policy equivalent to applying
// all the given policies in order, failing early if any of them fails.
// Nil policies are ignored.
func JoinAttributePolicies(policies ...AttributePolicy) AttributePolicy {
	joiner := newAttributePolicyUtilAttributePolicyJoiner()
	for _, p := range policies {
		if p != nil {
			joiner.unroll(p)
		}
	}
	return joiner.join()
}

// newAttributePolicyUtilAttributePolicyJoiner returns a join helper that
// flattens joined attribute policies and groups the special joinable ones.
func newAttributePolicyUtilAttributePolicyJoiner() *joinableJoinHelper[AttributePolicy, JoinableAttributePolicy] {
	return &joinableJoinHelper[AttributePolicy, JoinableAttributePolicy]{
		zeroValue:     RejectAllAttributePolicy,
		identityValue: IdentityAttributePolicy,
		split: func(x AttributePolicy) ([]AttributePolicy, bool) {
			if j, ok := x.(*joinedAttributePolicy); ok {
				return j.policies, true
			}
			return nil, false
		},
		rejoin: func(xs []AttributePolicy) AttributePolicy {
			return newJoinedAttributePolicy(xs)
		},
	}
}

// identityAttributePolicy is the type of IdentityAttributePolicy.
type identityAttributePolicy struct{}

// Apply returns value unchanged.
func (identityAttributePolicy) Apply(_, _, value string) (string, bool) {
	return value, true
}

// rejectAllAttributePolicy is the type of
// RejectAllAttributePolicy.
type rejectAllAttributePolicy struct{}

// Apply rejects the attribute.
func (rejectAllAttributePolicy) Apply(_, _, _ string) (string, bool) {
	return "", false
}

// IdentityAttributePolicy is an attribute policy that returns
// the value unchanged.
var IdentityAttributePolicy AttributePolicy = identityAttributePolicy{}

// RejectAllAttributePolicy is an attribute policy that rejects
// all values.
var RejectAllAttributePolicy AttributePolicy = rejectAllAttributePolicy{}

// JoinableAttributePolicy is an attribute policy that is
// joinable: policies that share a join strategy are combined by it rather
// than simply applied one after the other.  Only this package can implement
// it.
type JoinableAttributePolicy interface {
	AttributePolicy
	joinStrategy() joinableJoinStrategy[JoinableAttributePolicy]
}
