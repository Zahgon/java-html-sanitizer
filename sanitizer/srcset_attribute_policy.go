// Copyright (c) 2019, Mike Samuel
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

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/SrcsetAttributePolicy.java.

package sanitizer

import "strings"

// srcsetAttributePolicy applies a URL policy to all URLs in a srcset
// attribute value.
//
// https://html.spec.whatwg.org/multipage/images.html#srcset-attributes
// explains srcset for images and other media content.
//
// There is a pending draft to use it on <script> to allow loading scripts
// compatible with different versions of JS.
//
// The general form of srcset is
//
//	srcset ::== space* srcplus ([,] space* srcplus)*
//	# Additionally, the URL may not start or end with a comma
//	srcplus ::== URL (space+ metadata)?
//	metadata ::== FLOAT [a-z]?
//
// This policy applies the given attribute policy to URLs and emits metadata
// as given, but normalizing spaces.
type srcsetAttributePolicy struct {
	srcPolicy AttributePolicy
}

// newSrcsetAttributePolicy returns a policy that vets each URL in a srcset
// with srcPolicy.
func newSrcsetAttributePolicy(srcPolicy AttributePolicy) *srcsetAttributePolicy {
	return &srcsetAttributePolicy{srcPolicy: srcPolicy}
}

// Apply rewrites a srcset value keeping the URLs that srcPolicy allows, or
// rejects it if it is malformed or no URL survives.
func (p *srcsetAttributePolicy) Apply(elementName, attributeName, value string) (string, bool) {
	var sb strings.Builder

	i, n := 0, len(value)
	// Skip spaces.
	for i < n && stringsIsHTMLSpace(rune(value[i])) {
		i++
	}

	for i < n {
		// Find URL end.
		urlStart := i
		for i < n && !stringsIsHTMLSpace(rune(value[i])) {
			i++
		}
		urlEnd := i
		// Find metadata end.
		for i < n && stringsIsHTMLSpace(rune(value[i])) {
			i++
		}
		metadataStart := i
		if urlEnd < i { // Space required before metadata.
			floatEnd := stringsSkipValidFloatingPointNumber(value, i)
			if floatEnd >= 0 {
				i = floatEnd
				if i < n {
					// Skip over width specifier 'w', or pixel density specifier
					// 'x'.  We make this optional to support the <script srcset>
					// proposal.
					ch := value[i] | 32
					if 'a' <= ch && ch <= 'z' {
						i++
					}
				}
			}
		}
		metadataEnd := i

		if urlStart < urlEnd {
			if value[urlStart] == ',' || value[urlEnd-1] == ',' {
				// These introduce lexical ambiguity and are called out in the
				// spec.
				return "", false
			}
			okURL, ok := p.srcPolicy.Apply(elementName, "src", value[urlStart:urlEnd])
			if ok && okURL != "" {
				if sb.Len() != 0 {
					sb.WriteString(" , ")
				}
				sb.WriteString(strings.ReplaceAll(okURL, ",", "%2c"))
				if metadataStart < metadataEnd {
					sb.WriteByte(' ')
					sb.WriteString(value[metadataStart:metadataEnd])
				}
			}
		}
		// Skip space before comma
		for i < n && stringsIsHTMLSpace(rune(value[i])) {
			i++
		}
		if i == n || value[i] != ',' {
			break
		}
		i++
		for i < n && stringsIsHTMLSpace(rune(value[i])) {
			i++
		}
	}

	if i < n || // Unexpected trailing content.
		sb.Len() == 0 { // No URLs found.
		return "", false
	}
	return sb.String(), true
}

// equals reports whether o is a srcset policy with an equal URL policy.
func (p *srcsetAttributePolicy) equals(o any) bool {
	q, ok := o.(*srcsetAttributePolicy)
	return ok && policyEquals(p.srcPolicy, q.srcPolicy)
}

// joinStrategy groups srcset policies so that they are joined by
// srcsetAttributePolicySrcsetJoinStrategyInstance.
func (p *srcsetAttributePolicy) joinStrategy() joinableJoinStrategy[JoinableAttributePolicy] {
	return srcsetAttributePolicySrcsetJoinStrategyInstance
}

// srcsetAttributePolicySrcsetJoinStrategy joins srcset policies by joining the
// policies they apply to each URL, so that the URL protocol guards inside
// them meet and join as they do on src: a builder that allowed no protocol
// yields to one that did, and two allowlists intersect.
type srcsetAttributePolicySrcsetJoinStrategy struct{}

// srcsetAttributePolicySrcsetJoinStrategyInstance is the only
// srcsetAttributePolicySrcsetJoinStrategy.
var srcsetAttributePolicySrcsetJoinStrategyInstance = srcsetAttributePolicySrcsetJoinStrategy{}

// join returns a srcset policy whose URL policy is the join of the URL
// policies of toJoin, all of which are srcset policies.
func (srcsetAttributePolicySrcsetJoinStrategy) join(toJoin []JoinableAttributePolicy) JoinableAttributePolicy {
	srcPolicies := make([]AttributePolicy, 0, len(toJoin))
	for _, p := range toJoin {
		srcPolicies = append(srcPolicies, p.(*srcsetAttributePolicy).srcPolicy)
	}
	return newSrcsetAttributePolicy(JoinAttributePolicies(srcPolicies...))
}
