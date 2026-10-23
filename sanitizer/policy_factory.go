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

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/PolicyFactory.java.

package sanitizer

import "strings"

// PolicyFactory can be used to link a sanitizer to an output receiver and
// provides a convenient Sanitize method and an And method to compose
// policies.
//
// A PolicyFactory is immutable and safe for concurrent use.
type PolicyFactory struct {
	policies           map[string]*elementAndAttributePolicies
	globalAttrPolicies map[string]AttributePolicy
	textContainers     map[string]struct{}
	// disallowedTextContainers holds the elements in which text is
	// disallowed, from HTMLPolicyBuilder.DisallowTextIn, whether the element
	// is kept, renamed or dropped.  Disjoint from textContainers.
	disallowedTextContainers map[string]struct{}
	// preprocessor is the processor that Sanitize applies before the policy.
	preprocessor  HTMLStreamEventProcessor
	postprocessor HTMLStreamEventProcessor
}

// newPolicyFactory returns a factory for the given compiled policies.  It
// keeps the maps it is given, which must not be modified afterwards.
func newPolicyFactory(
	policies map[string]*elementAndAttributePolicies,
	textContainers map[string]struct{},
	disallowedTextContainers map[string]struct{},
	globalAttrPolicies map[string]AttributePolicy,
	preprocessor HTMLStreamEventProcessor,
	postprocessor HTMLStreamEventProcessor,
) *PolicyFactory {
	return &PolicyFactory{
		policies:                 policies,
		textContainers:           textContainers,
		disallowedTextContainers: disallowedTextContainers,
		globalAttrPolicies:       globalAttrPolicies,
		preprocessor:             preprocessor,
		postprocessor:            postprocessor,
	}
}

// Apply produces a sanitizer that emits tokens to out.
func (f *PolicyFactory) Apply(out HTMLStreamEventReceiver) HTMLSanitizerPolicy {
	return newElementAndAttributePolicyBasedSanitizerPolicy(
		f.postprocessor.Wrap(out), f.policies, f.textContainers,
		f.disallowedTextContainers)
}

// ApplyWithListener produces a sanitizer that emits tokens to out and that
// notifies any listener of any dropped tags, attributes and text.
//
// Text the policy removes from a kept literal-content element is reported
// through HTMLChangeListener.DiscardedText with any out.  Content that out
// itself cannot render, such as a --> inside a kept script element, is
// reported only when out is an HTMLStreamRenderer, possibly behind
// HTMLStreamEventReceiverWrapper decorators, since that is where the second
// decision to drop it is made; SanitizeWithListener always uses one.
//
// out is a renderer that receives approved tokens only.  listener, if
// non-nil, receives notifications of tags, attributes and text that were
// rejected.  This may tie into intrusion detection systems.  If listener is
// non-nil then context is the value passed with notifications.  This can be
// used to let the listener know from which connection or request the
// questionable HTML was received.
func (f *PolicyFactory) ApplyWithListener(out HTMLStreamEventReceiver, listener HTMLChangeListener, context any) HTMLSanitizerPolicy {
	if listener == nil {
		return f.Apply(out)
	}
	r := NewHTMLChangeReporter(out, listener, context)
	r.SetPolicy(f.Apply(r.GetWrappedRenderer()))
	return r.GetWrappedPolicy()
}

// Sanitize is a convenience function that sanitizes a string of HTML.
func (f *PolicyFactory) Sanitize(html string) string {
	return f.SanitizeWithListener(html, nil, nil)
}

// SanitizeWithListener is a convenience function that sanitizes a string of
// HTML and reports the names of rejected elements and attributes to
// listener, along with the rejected attributes' values and any content the
// policy or renderer could not emit.
//
// listener, if non-nil, receives notifications of tags, attributes and text
// that were rejected.  This may tie into intrusion detection systems.  If
// listener is non-nil then context is the value passed with notifications.
// This can be used to let the listener know from which connection or request
// the questionable HTML was received.
//
// It returns a string of HTML that complies with this factory's policy.
func (f *PolicyFactory) SanitizeWithListener(html string, listener HTMLChangeListener, context any) string {
	var out strings.Builder
	out.Grow(len(html))
	Sanitize(
		html,
		f.ApplyWithListener(
			NewHTMLStreamRendererToBuilder(&out, DoNothing[string]),
			listener,
			context),
		f.preprocessor)
	return out.String()
}

// And produces a factory that allows the union of the grants, and intersects
// policies where they overlap on a particular granted attribute or element
// name.
//
// The guard a builder puts on URL attributes when it allowed no protocol is
// a default rather than a policy, so it yields here to the other factory's
// protocol allowlist; two allowlists intersect like any other overlapping
// policies.  A builder configured with HTMLPolicyBuilder.AllowOnlyRelativeURLs
// instead supplies an explicit empty allowlist that continues to reject
// absolute URLs after composition.  See HTMLPolicyBuilder.AllowURLProtocols.
func (f *PolicyFactory) And(g *PolicyFactory) *PolicyFactory {
	builder := make(map[string]*elementAndAttributePolicies, len(f.policies)+len(g.policies))
	// Merge f and g into a map of element names to attribute policies.
	for elName, p := range f.policies {
		if q, ok := g.policies[elName]; ok {
			p = p.and(q)
		} else {
			// Mix in any globals that are not already taken into account in f.
			p = p.andGlobals(g.globalAttrPolicies)
		}
		builder[elName] = p
	}
	// Handle keys that are in g but not in f.
	for elName, p := range g.policies {
		if _, ok := f.policies[elName]; !ok {
			// Mix in any globals that are not already taken into account in g.
			builder[elName] = p.andGlobals(f.globalAttrPolicies)
		}
	}
	var allTextContainers map[string]struct{}
	if containsAllStrings(f.textContainers, g.textContainers) {
		allTextContainers = f.textContainers
	} else if containsAllStrings(g.textContainers, f.textContainers) {
		allTextContainers = g.textContainers
	} else {
		allTextContainers = make(map[string]struct{}, len(f.textContainers)+len(g.textContainers))
		for name := range f.textContainers {
			allTextContainers[name] = struct{}{}
		}
		for name := range g.textContainers {
			allTextContainers[name] = struct{}{}
		}
	}
	// A DisallowTextIn from either factory carries over, unless the other
	// allows text in that element: grants union here as they do above, and
	// the two sets stay disjoint as they are in a single builder.
	allDisallowedTextContainers := make(map[string]struct{}, len(f.disallowedTextContainers)+len(g.disallowedTextContainers))
	for _, set := range []map[string]struct{}{f.disallowedTextContainers, g.disallowedTextContainers} {
		for name := range set {
			if _, ok := allTextContainers[name]; !ok {
				allDisallowedTextContainers[name] = struct{}{}
			}
		}
	}
	var allGlobalAttrPolicies map[string]AttributePolicy
	if len(g.globalAttrPolicies) == 0 {
		allGlobalAttrPolicies = f.globalAttrPolicies
	} else if len(f.globalAttrPolicies) == 0 {
		allGlobalAttrPolicies = g.globalAttrPolicies
	} else {
		allGlobalAttrPolicies = make(map[string]AttributePolicy, len(f.globalAttrPolicies)+len(g.globalAttrPolicies))
		for attrName, a := range f.globalAttrPolicies {
			allGlobalAttrPolicies[attrName] = JoinAttributePolicies(a, g.globalAttrPolicies[attrName])
		}
		for attrName, b := range g.globalAttrPolicies {
			if _, ok := f.globalAttrPolicies[attrName]; !ok {
				allGlobalAttrPolicies[attrName] = b
			}
		}
	}
	return newPolicyFactory(
		builder, allTextContainers, allDisallowedTextContainers,
		allGlobalAttrPolicies,
		ComposeProcessors(f.preprocessor, g.preprocessor),
		ComposeProcessors(f.postprocessor, g.postprocessor))
}

// containsAllStrings reports whether every element of sub is in set.
func containsAllStrings(set, sub map[string]struct{}) bool {
	for s := range sub {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}
