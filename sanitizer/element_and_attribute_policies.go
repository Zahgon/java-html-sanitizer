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

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/ElementAndAttributePolicies.java.

package sanitizer

import "maps"

// elementAndAttributePolicies encapsulates all the information needed by the
// elementAndAttributePolicyBasedSanitizerPolicy to sanitize one kind of
// element.  It is immutable.
type elementAndAttributePolicies struct {
	elementName     string
	elPolicy        ElementPolicy
	attrPolicies    map[string]AttributePolicy
	htmlTagSkipType HTMLTagSkipType
}

// newElementAndAttributePolicies returns the policies for one element,
// keeping a copy of attrPolicies.
func newElementAndAttributePolicies(
	elementName string,
	elPolicy ElementPolicy,
	attrPolicies map[string]AttributePolicy,
	htmlTagSkipType HTMLTagSkipType,
) *elementAndAttributePolicies {
	return &elementAndAttributePolicies{
		elementName:     elementName,
		elPolicy:        elPolicy,
		attrPolicies:    copyAttrPolicies(attrPolicies),
		htmlTagSkipType: htmlTagSkipType,
	}
}

// and returns policies for the same element that allow only what both p and
// q allow: overlapping attribute policies are joined, p's first, and the
// remaining attribute grants are united.  q must be for p's element.
func (p *elementAndAttributePolicies) and(q *elementAndAttributePolicies) *elementAndAttributePolicies {
	joinedAttrPolicies := make(map[string]AttributePolicy, len(p.attrPolicies)+len(q.attrPolicies))
	for attrName, a := range p.attrPolicies {
		if b, ok := q.attrPolicies[attrName]; ok {
			a = JoinAttributePolicies(a, b)
		}
		joinedAttrPolicies[attrName] = a
	}
	for attrName, b := range q.attrPolicies {
		if _, ok := p.attrPolicies[attrName]; !ok {
			joinedAttrPolicies[attrName] = b
		}
	}

	return newElementAndAttributePolicies(
		p.elementName,
		JoinElementPolicies(p.elPolicy, q.elPolicy),
		joinedAttrPolicies,
		p.htmlTagSkipType.And(q.htmlTagSkipType))
}

// andGlobals returns p with the given global attribute policies mixed in:
// joined after p's own policy for an attribute p has one for, and granted
// as they are for the others.  It returns p itself if that changes nothing.
func (p *elementAndAttributePolicies) andGlobals(globalAttrPolicies map[string]AttributePolicy) *elementAndAttributePolicies {
	if len(globalAttrPolicies) == 0 {
		return p
	}
	var anded map[string]AttributePolicy
	for attrName, attrPolicy := range p.attrPolicies {
		globalAttrPolicy, ok := globalAttrPolicies[attrName]
		if !ok {
			continue
		}
		joined := JoinAttributePolicies(attrPolicy, globalAttrPolicy)
		if !policyEquals(joined, attrPolicy) {
			if anded == nil {
				anded = copyAttrPolicies(p.attrPolicies)
			}
			anded[attrName] = joined
		}
	}
	for attrName, globalAttrPolicy := range globalAttrPolicies {
		if _, ok := p.attrPolicies[attrName]; !ok {
			if anded == nil {
				anded = copyAttrPolicies(p.attrPolicies)
			}
			anded[attrName] = globalAttrPolicy
		}
	}
	if anded == nil {
		return p
	}
	return newElementAndAttributePolicies(p.elementName, p.elPolicy, anded, p.htmlTagSkipType)
}

// copyAttrPolicies returns a new, non-nil map with the entries of m.
func copyAttrPolicies(m map[string]AttributePolicy) map[string]AttributePolicy {
	c := make(map[string]AttributePolicy, len(m))
	maps.Copy(c, m)
	return c
}
