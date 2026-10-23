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

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/HtmlPolicyBuilder.java.

package sanitizer

import (
	"errors"
	"maps"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
)

// HTMLPolicyBuilder offers conveniences for configuring policies for the
// HTML sanitizer.
//
// # Usage
//
// To create a policy, first construct an instance with NewHTMLPolicyBuilder;
// then call Allow… methods to turn on tags, attributes, and other processing
// modes; and finally call Build or ToFactory.
//
//	// Define the policy.
//	policy, err := sanitizer.NewHTMLPolicyBuilder().
//		AllowElements("a", "p").
//		AllowAttributes("href").OnElements("a").
//		ToFactory()
//
//	// Sanitize your output.
//	sanitizer.Sanitize(myHTML, policy.Apply(myHTMLStreamRenderer),
//		sanitizer.IdentityProcessor)
//
// # Embedded Content
//
// Embedded URLs are filtered by protocol (see AllowURLProtocols).  There is a
// canned policy, AllowStandardURLProtocols, so you can easily allow widely
// used protocols that don't violate the current page's origin.  See
// "Customization" below for ways to do further filtering.  If you allow links
// it might be worthwhile to require rel=nofollow with
// RequireRelNofollowOnLinks.
//
// This type simply throws out all embedded JS.  Use a custom element or
// attribute policy to allow through signed or otherwise known-safe code.
// Check out the Caja project if you need a way to contain third-party JS.
//
// This type does not attempt to faithfully parse and sanitize CSS.  It does
// provide one styling option, AllowStyling, that allows through a few CSS
// properties that allow textual styling, but that disallow image loading,
// history stealing, layout breaking, code execution, etc.
//
// # Customization
//
// You can easily do custom processing on tags and attributes by supplying
// your own element policy or attribute policy when calling Allow… methods.
// E.g. to convert headers into <div>s, you could use an element policy
//
//	sanitizer.NewHTMLPolicyBuilder().
//		AllowElementsWithPolicy(
//			sanitizer.ElementPolicyFunc(func(elementName string, attrs *[]string) (string, bool) {
//				*attrs = append(*attrs, "class", "header-"+elementName)
//				return "div", true
//			}),
//			"h1", "h2", "h3", "h4", "h5", "h6").
//		Build(outputChannel)
//
// # Rules of Thumb
//
// Throughout this type, several rules hold:
//
//   - Everything is denied by default.  There are Disallow… methods, but
//     those reverse allows instead of rolling back overly permissive
//     defaults.
//   - The order of allows and disallows does not matter.  Disallows trump
//     allows whether they occur before or after them.  The only method that
//     needs to be called in a particular place is Build.  Allows or
//     disallows after Build is called have no effect on the already built
//     policy.
//   - Element and attribute policies are applied in the following order:
//     element specific attribute policy, global attribute policy, element
//     policy.  Element policies come last so they can observe all the
//     post-processed attributes, and so they can add attributes that are
//     exempt from attribute policies.  Element specific policies go first,
//     so they can normalize content to a form that might be acceptable to a
//     more simplistic global policy.
//
// # Errors
//
// Methods given invalid arguments, such as RequireRelsOnLinks given a value
// with spaces, record the first such error.  The builder then ignores further configuration, and Build and
// ToFactory return the error.
//
// # Concurrency and efficiency
//
// In short: build a PolicyFactory once with ToFactory and share it across
// goroutines.  Do not share a builder, and do not share a policy built with
// Build.
//
// In detail, there are three objects here with three different rules:
//
//   - An HTMLPolicyBuilder is not safe for concurrent use.  It is mutable, so
//     confine it to the goroutine that is configuring it.
//   - A PolicyFactory, from ToFactory, is safe for concurrent use and
//     immutable.  This is the object to build once and reuse.  Binding one
//     to an output channel is cheap, so there is no reason to cache anything
//     further down.
//   - The HTMLSanitizerPolicy from Build is not safe for concurrent use, and
//     neither is it reusable across concurrent sanitizations: it is bound to
//     a single output channel and keeps state to track whether text inside
//     disallowed elements should be suppressed.  Use one per sanitization.
//
// Sharing a stateful policy across goroutines corrupts output rather than
// security: a race cannot make the policy accept something it would
// otherwise reject, but it can interleave or suppress the wrong content.
//
// The same rule applies to anything you plug in.  An HTMLStreamEventProcessor
// is asked to wrap a sink once per sanitization, so any per-document state a
// pre-processor keeps belongs in the receiver it returns, not in the
// processor itself.
type HTMLPolicyBuilder struct {
	elPolicies         map[string]ElementPolicy
	attrPolicies       map[string]map[string]AttributePolicy
	globalAttrPolicies map[string]AttributePolicy
	allowedProtocols   map[string]struct{}
	// onlyRelativeURLs records whether URL values must stay relative when
	// factories are combined.
	onlyRelativeURLs bool
	skipIssueTagMap  map[string]HTMLTagSkipType
	// textContainers maps element names to whether text is allowed in them.
	textContainers      map[string]bool
	postprocessor       HTMLStreamEventProcessor
	preprocessor        HTMLStreamEventProcessor
	stylingPolicySchema *CSSSchema
	// stylingPolicySchemaIsImplicit is true when stylingPolicySchema was
	// installed by AllowAttributes("style").Globally() rather than chosen by
	// the caller, so an explicit AllowStylingWithSchema may replace it.
	stylingPolicySchemaIsImplicit bool
	styleURLPolicy                AttributePolicy
	// extraRelsForLinks is an insertion-ordered set.
	extraRelsForLinks []string
	skipRelsForLinks  map[string]struct{}
	// compiledState speeds up subsequent builds by caching the compiled
	// policies.
	compiledState *htmlPolicyBuilderCompiledState
	// err is the first configuration error, which Build and ToFactory
	// report.
	err error
}

// DefaultSkipIfEmpty is the default set of elements that are
// removed if they have no attributes.  Since <img> is in this set, by
// default, a policy will remove <img src=javascript:alert(1337)> because its
// URL is not allowed and it has no other attributes that would warrant it
// appearing in the output.
//
// It must not be modified.
var DefaultSkipIfEmpty = map[string]struct{}{
	"a": {}, "font": {}, "img": {}, "input": {}, "span": {},
}

// htmlPolicyBuilderDefaultSkipTagMapIfEmptyAttr maps each element of
// DefaultSkipIfEmpty to HTMLTagSkipTypeSkipByDefault.
var htmlPolicyBuilderDefaultSkipTagMapIfEmptyAttr = func() map[string]HTMLTagSkipType {
	m := make(map[string]HTMLTagSkipType, len(DefaultSkipIfEmpty))
	for elementName := range DefaultSkipIfEmpty {
		m[elementName] = HTMLTagSkipTypeSkipByDefault
	}
	return m
}()

// DefaultRelsOnTargettedLinks lists the rel attribute
// values (https://developer.mozilla.org/en-US/docs/Web/HTML/Link_types) that
// prevent leaking information to the linked site, and prevent the linked
// page from redirecting your page to a phishing site when opened from a
// third-party link from your site.
//
// See https://mathiasbynens.github.io/rel-noopener/ about rel=noopener.
//
// It must not be modified.
var DefaultRelsOnTargettedLinks = []string{"noopener", "noreferrer"}

// htmlPolicyBuilderDefaultRelsOnTargettedLinksStr is the space-separated
// form of DefaultRelsOnTargettedLinks.
var htmlPolicyBuilderDefaultRelsOnTargettedLinksStr = strings.Join(DefaultRelsOnTargettedLinks, " ")

// htmlPolicyBuilderSpacesInInput is the message of the error reported for a
// rel value that contains spaces.
const htmlPolicyBuilderSpacesInInput = "spaces in input.  use f(\"foo\", \"bar\") not f(\"foo bar\")"

// htmlPolicyBuilderMetadata describes the elements, to tell which can hold
// text.
var htmlPolicyBuilderMetadata = htmlElementTablesGet()

// NewHTMLPolicyBuilder returns a builder that allows nothing yet.
func NewHTMLPolicyBuilder() *HTMLPolicyBuilder {
	return &HTMLPolicyBuilder{
		elPolicies:         map[string]ElementPolicy{},
		attrPolicies:       map[string]map[string]AttributePolicy{},
		globalAttrPolicies: map[string]AttributePolicy{},
		allowedProtocols:   map[string]struct{}{},
		skipIssueTagMap:    maps.Clone(htmlPolicyBuilderDefaultSkipTagMapIfEmptyAttr),
		textContainers:     map[string]bool{},
		postprocessor:      IdentityProcessor,
		preprocessor:       IdentityProcessor,
		styleURLPolicy:     RejectAllAttributePolicy,
	}
}

// AllowElements allows the named elements.
func (b *HTMLPolicyBuilder) AllowElements(elementNames ...string) *HTMLPolicyBuilder {
	return b.AllowElementsWithPolicy(IdentityElementPolicy, elementNames...)
}

// DisallowElements disallows the named elements.  Elements are disallowed by
// default, so there is no need to disallow elements, unless you are making an
// exception based on an earlier allow.
func (b *HTMLPolicyBuilder) DisallowElements(elementNames ...string) *HTMLPolicyBuilder {
	return b.AllowElementsWithPolicy(RejectAllElementPolicy, elementNames...)
}

// AllowElementsWithPolicy allows the given elements with the given policy,
// which may remove or add attributes, change the element name, or deny the
// element.
//
// Whether text may appear inside an element the policy renames follows the
// name given here, which AllowTextIn and DisallowTextIn take as well, not the
// name the policy returns: a policy that turns span into div keeps the text
// of the span whether or not div is allowed in its own right.  The one
// exception is a rename into an element whose content a browser reads
// literally, such as style or script, which keeps text only if that name was
// also passed to AllowTextIn, as it would have to be if written.  A void
// element renamed to one that is not void, such as br to span, is closed at
// once, since no close tag will come for it.
func (b *HTMLPolicyBuilder) AllowElementsWithPolicy(policy ElementPolicy, elementNames ...string) *HTMLPolicyBuilder {
	if b.err != nil {
		return b
	}
	b.invalidateCompiledState()
	for _, elementName := range elementNames {
		elementName = htmlLexerCanonicalElementName(elementName)
		newPolicy := JoinElementPolicies(b.elPolicies[elementName], policy)
		// Don't remove if newPolicy is the always reject policy since we want
		// that to infect later AllowElements calls for this particular element
		// name.  Rejects should have higher priority than allows.
		b.elPolicies[elementName] = newPolicy
		// An allowed element that can hold text is a text container unless
		// told otherwise.  A rejected element grants nothing, so it is not
		// recorded as one: under PolicyFactory.And, that record would cancel a
		// DisallowTextIn for the same element in the other factory.
		if _, known := b.textContainers[elementName]; !known &&
			!policyEquals(RejectAllElementPolicy, newPolicy) {
			if htmlPolicyBuilderMetadata.CanContainPlainText(htmlPolicyBuilderMetadata.IndexForName(elementName)) {
				b.textContainers[elementName] = true
			}
		}
	}
	return b
}

// AllowCommonInlineFormattingElements is a canned policy that allows a number
// of common formatting elements.
func (b *HTMLPolicyBuilder) AllowCommonInlineFormattingElements() *HTMLPolicyBuilder {
	return b.AllowElements(
		"b", "i", "font", "s", "u", "o", "sup", "sub", "ins", "del", "strong",
		"strike", "tt", "code", "big", "small", "br", "span", "em")
}

// AllowCommonBlockElements is a canned policy that allows a number of common
// block elements.
func (b *HTMLPolicyBuilder) AllowCommonBlockElements() *HTMLPolicyBuilder {
	return b.AllowElements(
		"p", "div", "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li",
		"blockquote")
}

// AllowTextIn allows text content in the named elements.  By default, text
// content is allowed in any allowed elements that can contain character data
// per the HTML5 spec, but text content is not allowed by default in elements
// that contain content of other kinds (like JavaScript in <script> elements).
//
// To write a policy that allows <script> or <style> elements, first
// AllowTextIn("script").
//
// Security note: this method allows the element's text through as text; it
// does not vet that text.  In particular, allowing text in <style> does not
// run the stylesheet through a CSSSchema: the schema guards the style
// attribute, so a rule like a { background: url(javascript:alert(1)) }
// inside a <style> element survives untouched, as does any selector that
// restyles the surrounding page.  The same goes for <script>, where the text
// is script source.  If you allow text in either element and the input is
// untrusted, vet that text yourself, for example with a pre-processor (see
// WithPreprocessor) that parses and rewrites it.
func (b *HTMLPolicyBuilder) AllowTextIn(elementNames ...string) *HTMLPolicyBuilder {
	if b.err != nil {
		return b
	}
	b.invalidateCompiledState()
	for _, elementName := range elementNames {
		b.textContainers[htmlLexerCanonicalElementName(elementName)] = true
	}
	return b
}

// DisallowTextIn disallows text in elements with the given name.
//
// This is useful when an element contains text that is not meant to be
// displayed to the end-user.  Typically these elements are styled
// display:none in browsers' default stylesheets, or, like <template> contain
// text nodes that are eventually for human consumption, but which are
// created in a separate document fragment.
//
// This applies to the element as the author wrote it, whether the policy
// keeps it, renames it or drops it.  With both DisallowElements("template")
// and DisallowTextIn("template") in effect, <template>hidden</template>
// contributes nothing to the output, where dropping the element alone would
// leave hidden behind as bare text.
//
// Text belongs to the nearest enclosing element that survives the policy, so
// this does not reach text inside a nested element that survives:
// <template><p>shown</p></template> keeps shown if <p> is allowed and kept.
// It is not a way to drop an element together with everything inside it.
func (b *HTMLPolicyBuilder) DisallowTextIn(elementNames ...string) *HTMLPolicyBuilder {
	if b.err != nil {
		return b
	}
	b.invalidateCompiledState()
	for _, elementName := range elementNames {
		b.textContainers[htmlLexerCanonicalElementName(elementName)] = false
	}
	return b
}

// AllowWithoutAttributes allows the given elements, assuming they are
// allowed, to appear without attributes.
//
// See DefaultSkipIfEmpty and DisallowWithoutAttributes.
func (b *HTMLPolicyBuilder) AllowWithoutAttributes(elementNames ...string) *HTMLPolicyBuilder {
	if b.err != nil {
		return b
	}
	b.invalidateCompiledState()
	for _, elementName := range elementNames {
		b.skipIssueTagMap[htmlLexerCanonicalElementName(elementName)] = HTMLTagSkipTypeDoNotSkip
	}
	return b
}

// DisallowWithoutAttributes disallows the given elements from appearing
// without attributes.
//
// See DefaultSkipIfEmpty and AllowWithoutAttributes.
func (b *HTMLPolicyBuilder) DisallowWithoutAttributes(elementNames ...string) *HTMLPolicyBuilder {
	if b.err != nil {
		return b
	}
	b.invalidateCompiledState()
	for _, elementName := range elementNames {
		b.skipIssueTagMap[htmlLexerCanonicalElementName(elementName)] = HTMLTagSkipTypeSkip
	}
	return b
}

// AllowAttributes returns an object that lets you associate policies with the
// given attributes, and allow them globally or on specific elements.
func (b *HTMLPolicyBuilder) AllowAttributes(attributeNames ...string) *HTMLPolicyBuilderAttributeBuilder {
	canonNames := make([]string, len(attributeNames))
	for i, attributeName := range attributeNames {
		canonNames[i] = htmlLexerCanonicalAttributeName(attributeName)
	}
	return newHTMLPolicyBuilderAttributeBuilder(b, canonNames)
}

// DisallowAttributes reverses an earlier attribute allow (see
// AllowAttributes).
//
// For this to have an effect you must call at least one of
// HTMLPolicyBuilderAttributeBuilder.Globally and
// HTMLPolicyBuilderAttributeBuilder.OnElements.
//
// Attributes are disallowed by default, so there is no need to call this with
// a laundry list of attribute/element pairs.
//
// This rejects the attribute whatever its value, and a Matching… call on the
// returned builder has no effect: rejecting everything and then narrowing to
// the values that match still rejects everything.  To keep an attribute
// except where its value matches, allow it with a policy that excludes those
// values instead:
//
//	// Not this: the pattern is ignored and every src is dropped.
//	DisallowAttributes("src").MatchingPattern(badURL).OnElements("img")
//
//	// This: keep the values that are not bad.
//	AllowAttributes("src").
//		Matching(sanitizer.AttributePolicyFunc(func(_, _, v string) (string, bool) {
//			return v, !badURL.MatchString(v)
//		})).
//		OnElements("img")
//
// A factory built the second way can also narrow a more permissive one
// through PolicyFactory.And, since And intersects the two attribute
// policies.
func (b *HTMLPolicyBuilder) DisallowAttributes(attributeNames ...string) *HTMLPolicyBuilderAttributeBuilder {
	return b.AllowAttributes(attributeNames...).Matching(RejectAllAttributePolicy)
}

// allowAttributesGlobally joins policy onto the global policies of the named
// attributes.
func (b *HTMLPolicyBuilder) allowAttributesGlobally(policy AttributePolicy, attributeNames []string) *HTMLPolicyBuilder {
	if b.err != nil {
		return b
	}
	b.invalidateCompiledState()
	for _, attributeName := range attributeNames {
		// We reinterpret the identity policy later via policy joining since
		// it's the default passed from the policy-less method, but we don't do
		// anything here since we don't know until Build is called whether the
		// policy author wants to allow certain URL protocols or wants to deal
		// with styles.
		b.globalAttrPolicies[attributeName] = JoinAttributePolicies(b.globalAttrPolicies[attributeName], policy)
	}
	return b
}

// allowAttributesOnElements joins policy onto the policies of the named
// attributes on the named elements.
func (b *HTMLPolicyBuilder) allowAttributesOnElements(policy AttributePolicy, attributeNames, elementNames []string) *HTMLPolicyBuilder {
	if b.err != nil {
		return b
	}
	b.invalidateCompiledState()
	for _, elementName := range elementNames {
		policies := b.attrPolicies[elementName]
		if policies == nil {
			policies = map[string]AttributePolicy{}
			b.attrPolicies[elementName] = policies
		}
		for _, attributeName := range attributeNames {
			policies[attributeName] = JoinAttributePolicies(policies[attributeName], policy)
		}
	}
	return b
}

// RequireRelNofollowOnLinks adds rel=nofollow
// (https://developer.mozilla.org/en-US/docs/Web/HTML/Link_types) to links.
//
// See DefaultRelsOnTargettedLinks and SkipRelsOnLinks.
func (b *HTMLPolicyBuilder) RequireRelNofollowOnLinks() *HTMLPolicyBuilder {
	return b.RequireRelsOnLinks("nofollow")
}

// RequireRelsOnLinks adds rel="..."
// (https://developer.mozilla.org/en-US/docs/Web/HTML/Link_types) to
// <a href="..."> tags beyond those in
// DefaultRelsOnTargettedLinks.
//
// Each value must be a single keyword: a value that contains spaces is a
// configuration error that Build and ToFactory report.
//
// See SkipRelsOnLinks.
func (b *HTMLPolicyBuilder) RequireRelsOnLinks(linkValues ...string) *HTMLPolicyBuilder {
	if b.err != nil {
		return b
	}
	b.invalidateCompiledState()
	if b.extraRelsForLinks == nil {
		b.extraRelsForLinks = []string{}
	}
	for _, linkValue := range linkValues {
		linkValue = htmlLexerCanonicalKeywordAttributeValue(linkValue)
		if stringsContainsHTMLSpace(linkValue) {
			b.err = errors.New(htmlPolicyBuilderSpacesInInput)
			return b
		}
		if !slices.Contains(b.extraRelsForLinks, linkValue) {
			b.extraRelsForLinks = append(b.extraRelsForLinks, linkValue)
		}
	}
	for _, rel := range b.extraRelsForLinks {
		delete(b.skipRelsForLinks, rel)
	}
	return b
}

// SkipRelsOnLinks opts out of some of the
// DefaultRelsOnTargettedLinks from being added to links, and
// reverses previous calls to RequireRelsOnLinks with the given link values.
//
// Each value must be a single keyword: a value that contains spaces is a
// configuration error that Build and ToFactory report.
//
// See RequireRelsOnLinks.
func (b *HTMLPolicyBuilder) SkipRelsOnLinks(linkValues ...string) *HTMLPolicyBuilder {
	if b.err != nil {
		return b
	}
	b.invalidateCompiledState()
	if b.skipRelsForLinks == nil {
		b.skipRelsForLinks = map[string]struct{}{}
	}
	for _, linkValue := range linkValues {
		linkValue = htmlLexerCanonicalKeywordAttributeValue(linkValue)
		if stringsContainsHTMLSpace(linkValue) {
			b.err = errors.New(htmlPolicyBuilderSpacesInInput)
			return b
		}
		b.skipRelsForLinks[linkValue] = struct{}{}
	}
	if b.extraRelsForLinks != nil {
		b.extraRelsForLinks = slices.DeleteFunc(b.extraRelsForLinks, func(rel string) bool {
			_, skipped := b.skipRelsForLinks[rel]
			return skipped
		})
	}
	return b
}

// AllowURLProtocols adds to the set of protocols that are allowed in URL
// attributes.  For each URL attribute that is allowed, we further constrain
// it by only allowing the value through if it specifies no protocol, or if it
// specifies one in the allowed protocols.  This is done regardless of
// whether any protocols have been allowed, so allowing the attribute "href"
// globally with the identity policy but not allowing any protocols,
// effectively disallows the "href" attribute globally.
//
// That default is not itself an allowlist, and PolicyFactory.And treats it
// differently from one.  A factory that allowed no protocol, combined with
// one that did, defers to it, so the combination allows the protocols the
// other factory allowed.  Two factories that each allowed some protocols
// together allow only those both allowed.  Use AllowOnlyRelativeURLs when
// this builder should continue to reject every URL with a protocol after it
// is combined with another factory.
//
// The guard runs after any policies attached to the attribute with
// HTMLPolicyBuilderAttributeBuilder.Matching, and after the policy given to
// AllowURLsInStyles, so it vets the value they produce.  They in turn see the
// value before the guard has vetted or normalized it, so a policy that
// rewrites URLs must vet the protocol itself; see Matching for the details
// and an example.
//
// Do not allow any *script such as javascript protocols if you might use
// this policy with untrusted code.
func (b *HTMLPolicyBuilder) AllowURLProtocols(protocols ...string) *HTMLPolicyBuilder {
	if b.err != nil {
		return b
	}
	b.invalidateCompiledState()
	// If there is at least one allowed protocol, then allow URLs and add a
	// filter that checks href and src values.

	// Do not allow href and srcs through otherwise, and only allow on images
	// and links.
	for _, protocol := range protocols {
		b.allowedProtocols[stringsToLowerCase(protocol)] = struct{}{}
	}
	return b
}

// AllowOnlyRelativeURLs restricts URL values to relative URLs.  A relative
// URL here has neither a protocol nor an authority, so values such as path,
// /path, ?query, and #fragment are allowed, while https://example.org/ and
// the protocol-relative //example.org/ are rejected.  Browsers treat
// backslashes as slashes when resolving against an HTTP(S) page, so
// equivalent authority spellings such as \\example.org/ are rejected too.
//
// Unlike the default guard used when AllowURLProtocols was never called,
// this is an explicit restriction.  It continues to reject every URL with a
// protocol when the resulting factory is combined with another factory by
// PolicyFactory.And.  Use this on a restrictive builder that previously
// relied on its empty protocol set to narrow another factory during
// composition.
//
// This restriction takes precedence over calls to AllowURLProtocols,
// regardless of call order.  It does not itself allow any URL attribute or
// URLs in styles, and it reaches only those this builder allows: And unions
// grants, so a URL attribute that only the other factory allows keeps that
// factory's protocols.
func (b *HTMLPolicyBuilder) AllowOnlyRelativeURLs() *HTMLPolicyBuilder {
	if b.err != nil {
		return b
	}
	b.invalidateCompiledState()
	b.onlyRelativeURLs = true
	return b
}

// DisallowURLProtocols reverses a decision made by AllowURLProtocols.  Unless
// AllowOnlyRelativeURLs was called, removing every allowed protocol makes the
// builder use the default guard that yields to another factory's allowlist
// during PolicyFactory.And.
func (b *HTMLPolicyBuilder) DisallowURLProtocols(protocols ...string) *HTMLPolicyBuilder {
	if b.err != nil {
		return b
	}
	b.invalidateCompiledState()
	for _, protocol := range protocols {
		delete(b.allowedProtocols, stringsToLowerCase(protocol))
	}
	return b
}

// AllowStandardURLProtocols is a canned URL protocol policy that allows http,
// https, and mailto.
func (b *HTMLPolicyBuilder) AllowStandardURLProtocols() *HTMLPolicyBuilder {
	return b.AllowURLProtocols("http", "https", "mailto")
}

// AllowStyling converts style="<CSS>" to sanitized CSS which allows color,
// font-size, type-face, and other styling using the default schema; but
// which does not allow content to escape its clipping context.
//
// "Does not allow content to escape its clipping context" is the reason
// DefaultCSSSchema withholds every property that changes how an element takes
// part in page layout: display, position, float, clear, overflow, z-index,
// opacity, visibility, the offsets, and the flexbox, grid and transform
// families.  A style attribute can restyle content, but it cannot reposition
// it, lay something over the top of it, or hide it.  Note that this excludes
// display:block just as it excludes display:none -- the whole property is
// withheld, not a few values.
//
// A policy that needs layout control can opt in with CSSSchemaUnion, which is
// the supported way to widen the default schema:
//
//	layout := sanitizer.CSSSchemaWithProperties([]string{
//		"display", "grid-template-columns", "gap",
//		"repeat()", "minmax()"}) // functions need listing too
//	union, err := sanitizer.CSSSchemaUnion(sanitizer.DefaultCSSSchema, layout)
//	builder.AllowStylingWithSchema(union)
//
// Weigh that against the content you are sanitizing: layout control is what
// lets untrusted markup cover or hide the page around it.  Note that
// position:fixed and position:sticky are withheld even then, because they
// escape a scrolling container entirely.
func (b *HTMLPolicyBuilder) AllowStyling() *HTMLPolicyBuilder {
	return b.AllowStylingWithSchema(DefaultCSSSchema)
}

// AllowStylingWithSchema converts style="<CSS>" to sanitized CSS which allows
// color, font-size, type-face, and other styling using the given schema,
// which lists the CSS properties to allow in a style attribute.
//
// Naming a schema here replaces the default that
// AllowAttributes("style").Globally() installs, in either order, so a schema
// narrower than DefaultCSSSchema stays narrow.  Calling this more than once
// with a schema of your own combines them with CSSSchemaUnion, whose error,
// if two of them define the same property differently, Build and ToFactory
// report; use CSSSchemaWithOverrides to say which definition wins.
func (b *HTMLPolicyBuilder) AllowStylingWithSchema(whitelist *CSSSchema) *HTMLPolicyBuilder {
	if b.err != nil {
		return b
	}
	b.invalidateCompiledState()

	// An implicit schema is the default that AllowAttributes("style")
	// .Globally() installs so that styling is sanitized at all.  A caller
	// naming a schema is choosing one, not adding to that default, so it
	// replaces it.  Unioning instead would silently hand back the default to
	// a caller who asked for something narrower.  Two explicit calls still
	// union, which is the documented way to combine schemas.
	if b.stylingPolicySchema == nil || b.stylingPolicySchemaIsImplicit {
		b.stylingPolicySchema = whitelist
	} else {
		union, err := CSSSchemaUnion(b.stylingPolicySchema, whitelist)
		if err != nil {
			b.err = err
			return b
		}
		b.stylingPolicySchema = union
	}
	b.stylingPolicySchemaIsImplicit = false

	// Allow the style attribute, and then we will fix it up later.  This
	// allows us to attach the final URL policy to the style attribute policy,
	// while still not allowing styles when AllowStyling is followed by a call
	// to DisallowAttributes("style").Globally().
	return b.allowAttributesGlobally(IdentityAttributePolicy, []string{"style"})
}

// AllowURLsInStyles allows URLs in CSS styles.  For example,
// <span style="background-image: url(http://example.com/image.png)">.
//
// URLs in CSS are typically loaded without user-interaction, the way links
// are, so a greater degree of scrutiny is warranted.
//
// This method only narrows what is allowed; it cannot widen it.  A URL has
// to clear both the policy given here and the protocol guard built from
// AllowURLProtocols, in that order.  The policy runs first, so it sees each
// URL before the guard has vetted or normalized it and can be handed a
// javascript: URL the builder never allowed.  That is harmless for a policy
// that only accepts or rejects, since the guard still rejects the URL
// afterwards, but a policy that rewrites URLs must vet the protocol itself,
// as HTMLPolicyBuilderAttributeBuilder.Matching describes.
//
// If AllowURLProtocols was never called, the guard rejects every URL that
// names a protocol whatever this policy said about it, so AllowURLsInStyles
// on its own admits only relative URLs.  Pair it with an AllowURLProtocols
// call:
//
//	sanitizer.NewHTMLPolicyBuilder().
//		AllowStyling().
//		AllowURLProtocols("https").       // without this, the guard drops
//		AllowURLsInStyles(myURLPolicy)    // every absolute URL this keeps
//
// newStyleURLPolicy receives each URL from the CSS before the protocol guard
// does, and may reject the URL or return the URL to use.  URLs will be
// reported as content in <img src=...>.
func (b *HTMLPolicyBuilder) AllowURLsInStyles(newStyleURLPolicy AttributePolicy) *HTMLPolicyBuilder {
	if b.err != nil {
		return b
	}
	b.invalidateCompiledState()
	b.styleURLPolicy = newStyleURLPolicy
	return b
}

// WithPreprocessor inserts a pre-processor into the pipeline between the
// lexer and the policy.  Pre-processors receive HTML events before the
// policy, so the policy will be applied to anything they add.
// Pre-processors are not in the TCB since they cannot bypass the policy.
func (b *HTMLPolicyBuilder) WithPreprocessor(pp HTMLStreamEventProcessor) *HTMLPolicyBuilder {
	if b.err != nil {
		return b
	}
	b.preprocessor = ComposeProcessors(b.preprocessor, pp)
	return b
}

// WithPostprocessor inserts a post-processor into the pipeline between the
// policy and the output sink.  Post-processors can insert events into the
// stream that are not vetted by the policy, so they are in the TCB.
//
// Try doing what you want with a pre-processor instead of a post-processor
// but if you're thinking of doing search/replace on a sanitized string, then
// definitely use either a pre or post-processor instead.
func (b *HTMLPolicyBuilder) WithPostprocessor(pp HTMLStreamEventProcessor) *HTMLPolicyBuilder {
	if b.err != nil {
		return b
	}
	b.postprocessor = ComposeProcessors(b.postprocessor, pp)
	return b
}

// attributeGuardMaker produces, given some policy builder state, a guard for
// an HTML attribute that needs extra handling on top of any
// policy-author-supplied custom attribute policy.  It may return nil for no
// guard.
type attributeGuardMaker func(intermediates *attributeGuardIntermediates) AttributePolicy

// attributeGuardIntermediates is a grab bag of state that is useful when
// coming up with guards for HTML attributes that need extra handling on top
// of any policy-author-supplied custom attribute policy.
type attributeGuardIntermediates struct {
	urlAttributePolicy AttributePolicy
	styleURLPolicy     AttributePolicy
	cssSchema          *CSSSchema
}

// htmlPolicyBuilderAttributeGuards maps attribute names that need extra
// handling to producers of those extra guards.
var htmlPolicyBuilderAttributeGuards = func() map[string]attributeGuardMaker {
	// For each URL attribute that is allowed, we further constrain it by only
	// allowing the value through if it specifies no protocol, or if it
	// specifies one in the allowed protocols.  This is done regardless of
	// whether any protocols have been allowed, so allowing the attribute
	// "href" globally with the identity policy but not allowing any
	// protocols, effectively disallows the "href" attribute globally.
	guards := map[string]attributeGuardMaker{}
	identityGuard := func(intermediates *attributeGuardIntermediates) AttributePolicy {
		return intermediates.urlAttributePolicy
	}
	for _, urlAttributeName := range []string{
		"action", "archive", "background", "cite", "classid", "codebase", "data",
		"dsync", "formaction", "href", "icon", "longdesc", "manifest", "poster",
		"profile", "src", "usemap",
	} {
		guards[urlAttributeName] = identityGuard
	}
	guards["style"] = func(intermediates *attributeGuardIntermediates) AttributePolicy {
		if intermediates.cssSchema == nil {
			return nil
		}
		return newStylingPolicy(
			intermediates.cssSchema,
			newStylingPolicyURLPolicyRewriter(
				JoinAttributePolicies(
					intermediates.styleURLPolicy,
					intermediates.urlAttributePolicy)))
	}
	guards["srcset"] = func(intermediates *attributeGuardIntermediates) AttributePolicy {
		return newSrcsetAttributePolicy(intermediates.urlAttributePolicy)
	}
	return guards
}()

// Build produces a policy based on the allow and disallow calls previously
// made, or returns the first configuration error.
//
// out receives calls to open only tags allowed by previous calls to this
// object.  Typically an HTMLStreamRenderer.
func (b *HTMLPolicyBuilder) Build(out HTMLStreamEventReceiver) (HTMLSanitizerPolicy, error) {
	f, err := b.ToFactory()
	if err != nil {
		return nil, err
	}
	return f.Apply(out), nil
}

// BuildWithListener produces a policy based on the allow and disallow calls
// previously made, or returns the first configuration error.
//
// out receives calls to open only tags allowed by previous calls to this
// object.  Typically an HTMLStreamRenderer.  listener is notified of dropped
// tags, attributes and text so that intrusion detection systems can be
// alerted to questionable HTML.  If nil then no notifications are sent.  If
// listener is non-nil then context is the value passed with alerts.  This can
// be used to let the listener know from which connection or request the
// questionable HTML was received.
func (b *HTMLPolicyBuilder) BuildWithListener(out HTMLStreamEventReceiver, listener HTMLChangeListener, context any) (HTMLSanitizerPolicy, error) {
	f, err := b.ToFactory()
	if err != nil {
		return nil, err
	}
	return f.ApplyWithListener(out, listener, context), nil
}

// Err returns the first configuration error recorded by this builder, or nil.
// Once a call has failed, later calls leave the builder unchanged, and Build
// and ToFactory return the same error.
func (b *HTMLPolicyBuilder) Err() error {
	return b.err
}

// ToFactory is like Build but can be reused to create many different
// policies each backed by a different output channel.  It returns the first
// configuration error, if any.
func (b *HTMLPolicyBuilder) ToFactory() (*PolicyFactory, error) {
	if b.err != nil {
		return nil, b.err
	}
	textContainerSet := map[string]struct{}{}
	disallowedTextContainerSet := map[string]struct{}{}
	for elementName, allowed := range b.textContainers {
		if allowed {
			textContainerSet[elementName] = struct{}{}
		} else {
			disallowedTextContainerSet[elementName] = struct{}{}
		}
	}
	compiled := b.compilePolicies()

	return newPolicyFactory(
		compiled.compiledPolicies,
		textContainerSet,
		disallowedTextContainerSet,
		maps.Clone(compiled.globalAttrPolicies),
		b.preprocessor, b.postprocessor), nil
}

// htmlPolicyBuilderCompiledState holds the policies compiled from a
// builder's configuration.
type htmlPolicyBuilderCompiledState struct {
	globalAttrPolicies map[string]AttributePolicy
	compiledPolicies   map[string]*elementAndAttributePolicies
}

// invalidateCompiledState is called by mutators to signal that any compiled
// policy is out-of-date.
func (b *HTMLPolicyBuilder) invalidateCompiledState() {
	b.compiledState = nil
}

// compilePolicies applies the link rels and the attribute guards to copies of
// the configured policies and combines them per element.
func (b *HTMLPolicyBuilder) compilePolicies() *htmlPolicyBuilderCompiledState {
	if b.compiledState != nil {
		return b.compiledState
	}

	// Copy maps before normalizing in case builder is reused.
	elPolicies := maps.Clone(b.elPolicies)
	attrPolicies := make(map[string]map[string]AttributePolicy, len(b.attrPolicies))
	for elementName, policies := range b.attrPolicies {
		attrPolicies[elementName] = maps.Clone(policies)
	}
	globalAttrPolicies := maps.Clone(b.globalAttrPolicies)

	// Implement RequireRelsOnLinks & SkipRelsOnLinks.
	if linkPolicy, ok := elPolicies["a"]; ok {
		relsOnLinksPolicy := htmlPolicyBuilderRelsOnLinksPolicyCreate(b.extraRelsForLinks, b.skipRelsForLinks)
		elPolicies["a"] = JoinElementPolicies(linkPolicy, relsOnLinksPolicy)
	}

	// Add guards on top of any custom policies.
	{
		var urlAttributePolicy AttributePolicy
		if b.onlyRelativeURLs {
			urlAttributePolicy = urlProtocolGuardRelativeOnly
		} else {
			urlAttributePolicy = urlProtocolGuardForProtocols(b.allowedProtocols)
		}

		intermediates := &attributeGuardIntermediates{
			urlAttributePolicy: urlAttributePolicy,
			styleURLPolicy:     b.styleURLPolicy,
			cssSchema:          b.stylingPolicySchema,
		}
		toGuard := map[string]attributeGuardMaker{}
		for attributeName, makeGuard := range htmlPolicyBuilderAttributeGuards {
			if policy, ok := globalAttrPolicies[attributeName]; ok {
				globalAttrPolicies[attributeName] = JoinAttributePolicies(makeGuard(intermediates), policy)
			} else {
				toGuard[attributeName] = makeGuard
			}
		}
		// Implement guards not implemented on global policies in the
		// per-element policy maps.
		for _, policies := range attrPolicies {
			for attributeName, makeGuard := range toGuard {
				if policy, ok := policies[attributeName]; ok {
					policies[attributeName] = JoinAttributePolicies(makeGuard(intermediates), policy)
				}
			}
		}
	}

	compiledPolicies := make(map[string]*elementAndAttributePolicies, len(elPolicies))
	for elementName, elPolicy := range elPolicies {
		if policyEquals(RejectAllElementPolicy, elPolicy) {
			continue
		}

		elAttrPolicies := attrPolicies[elementName]
		attrs := map[string]AttributePolicy{}
		for attributeName, policy := range elAttrPolicies {
			// Handled below so we don't end up putting the same key into the
			// map twice.
			if _, ok := globalAttrPolicies[attributeName]; ok {
				continue
			}
			if !policyEquals(RejectAllAttributePolicy, policy) {
				attrs[attributeName] = policy
			}
		}
		for attributeName, globalPolicy := range globalAttrPolicies {
			policy := JoinAttributePolicies(elAttrPolicies[attributeName], globalPolicy)
			if !policyEquals(RejectAllAttributePolicy, policy) {
				attrs[attributeName] = policy
			}
		}

		compiledPolicies[elementName] = newElementAndAttributePolicies(
			elementName, elPolicy, attrs, b.skipType(elementName))
	}
	b.compiledState = &htmlPolicyBuilderCompiledState{
		globalAttrPolicies: globalAttrPolicies,
		compiledPolicies:   compiledPolicies,
	}
	return b.compiledState
}

// skipType returns whether the named element is skipped when it has no
// attributes.
func (b *HTMLPolicyBuilder) skipType(elementName string) HTMLTagSkipType {
	if htmlTagSkipType, ok := b.skipIssueTagMap[elementName]; ok {
		return htmlTagSkipType
	}
	if _, ok := htmlPolicyBuilderDefaultSkipTagMapIfEmptyAttr[elementName]; ok {
		return HTMLTagSkipTypeSkipByDefault
	}
	return HTMLTagSkipTypeDoNotSkipByDefault
}

// HTMLPolicyBuilderAttributeBuilder builds the relationship between
// attributes, the values that they may have, and the elements on which they
// may appear.
type HTMLPolicyBuilderAttributeBuilder struct {
	builder        *HTMLPolicyBuilder
	attributeNames []string
	policy         AttributePolicy
}

// newHTMLPolicyBuilderAttributeBuilder returns an attribute builder for the
// given canonical attribute names that adds its grants to builder.
func newHTMLPolicyBuilderAttributeBuilder(builder *HTMLPolicyBuilder, attributeNames []string) *HTMLPolicyBuilderAttributeBuilder {
	return &HTMLPolicyBuilderAttributeBuilder{
		builder:        builder,
		attributeNames: slices.Clone(attributeNames),
		policy:         IdentityAttributePolicy,
	}
}

// Matching filters and/or transforms the attribute values allowed by later
// Globally and OnElements calls.  Multiple calls to Matching… are combined
// so that the policies receive the value in order, each seeing the value
// after any transformation by a previous policy.
//
// On a URL attribute such as href or src, the protocol guard built from
// HTMLPolicyBuilder.AllowURLProtocols runs after the policies given here and
// vets what they produce.  The first policy therefore sees the value as
// written, after entity decoding but before the guard trims surrounding
// whitespace and percent-encodes parentheses and control characters, so a
// pattern should match the value as written; one that expects the normalized
// form rejects the raw one, which fails closed.  The policies also run before
// the guard has rejected anything, so a policy can be handed
// javascript:alert(1) even though the builder allowed no such protocol.  That
// is harmless for a policy that only accepts or rejects, since the guard
// still rejects the value afterwards, but a policy that rewrites one URL into
// another, such as a redirector or proxy that returns
// "https://example.com/go?u=" + value, would hand the guard an https: URL
// that carries the unvetted one to the redirector.  Such a policy should vet
// the protocol itself first, for example by putting a
// FilterURLByProtocolAttributePolicy ahead of it:
//
//	vetProtocol := sanitizer.NewFilterURLByProtocolAttributePolicy(
//		[]string{"http", "https"})
//	sanitizer.NewHTMLPolicyBuilder().
//		AllowElements("a").
//		AllowAttributes("href").
//		Matching(vetProtocol).
//		Matching(sanitizer.AttributePolicyFunc(func(_, _, url string) (string, bool) {
//			return "https://example.com/go?u=" + url, true
//		})).
//		OnElements("a").
//		AllowURLProtocols("https")
//
// Since the combination fails as soon as one policy rejects, this has no
// effect on a builder from HTMLPolicyBuilder.DisallowAttributes, which
// already rejects every value.  See that method for how to reject only some.
func (ab *HTMLPolicyBuilderAttributeBuilder) Matching(attrPolicy AttributePolicy) *HTMLPolicyBuilderAttributeBuilder {
	ab.policy = JoinAttributePolicies(ab.policy, attrPolicy)
	return ab
}

// MatchingPattern restricts the values allowed by later Globally and
// OnElements calls to those that pattern matches in their entirety.
// Multiple calls to Matching… are combined to
// restrict to the intersection of possible matched values.
//
// pattern has Go regexp (RE2) semantics: for example \s does not match a
// vertical tab, and (?i) folds case by Unicode rules, so (?i)k also matches
// the Kelvin sign.
func (ab *HTMLPolicyBuilderAttributeBuilder) MatchingPattern(pattern *regexp.Regexp) *HTMLPolicyBuilderAttributeBuilder {
	// These value policies are pointers to small structs that refer to
	// nothing but their parameters, so a PolicyFactory, which typically lives
	// as long as the program, does not keep the builder reachable.
	return ab.Matching(&patternAttributePolicy{pattern: wholeValuePattern(pattern)})
}

// wholeValuePattern returns a pattern that matches exactly the strings that
// pattern matches in their entirety.
//
// The source is anchored at both ends so that it must match the whole value
// rather than a prefix the leftmost-first search happens to prefer.  It is
// parsed and printed first so that a \Q without its \E cannot quote the
// anchors.
func wholeValuePattern(pattern *regexp.Regexp) *regexp.Regexp {
	re, err := syntax.Parse(pattern.String(), syntax.Perl)
	if err != nil {
		// The source compiled once already, so it parses.
		panic(err)
	}
	return regexp.MustCompile(`\A(?:` + re.String() + `)\z`)
}

// MatchingPredicate restricts the values allowed by later Globally and
// OnElements calls to those matching the given predicate.  Multiple calls to
// Matching… are combined to restrict to the intersection of possible matched
// values.
func (ab *HTMLPolicyBuilderAttributeBuilder) MatchingPredicate(filter func(value string) bool) *HTMLPolicyBuilderAttributeBuilder {
	return ab.Matching(&predicateAttributePolicy{filter: filter})
}

// MatchingValues restricts the values allowed by later Globally and
// OnElements calls to those supplied.  Multiple calls to Matching… are
// combined to restrict to the intersection of possible matched values.
//
// When ignoreCase is true the attribute value is lower-cased before it is
// looked up but allowedValues is used as given, so the allowed values must
// already be lower-case; one that is not can never match.
//
// A repeated value is a configuration error that Build and ToFactory
// report.
func (ab *HTMLPolicyBuilderAttributeBuilder) MatchingValues(ignoreCase bool, allowedValues ...string) *HTMLPolicyBuilderAttributeBuilder {
	allowed := make(map[string]struct{}, len(allowedValues))
	for _, value := range allowedValues {
		if _, dup := allowed[value]; dup {
			if ab.builder.err == nil {
				ab.builder.err = errors.New("duplicate element: " + value)
			}
			return ab
		}
		allowed[value] = struct{}{}
	}
	return ab.MatchingValueSet(ignoreCase, allowed)
}

// MatchingValueSet restricts the values allowed by later Globally and
// OnElements calls to those in allowedValues.  Multiple calls to Matching…
// are combined to restrict to the intersection of possible matched values.
//
// When ignoreCase is true the attribute value is lower-cased before it is
// looked up but allowedValues is used as given, so the allowed values must
// already be lower-case; one that is not can never match.
func (ab *HTMLPolicyBuilderAttributeBuilder) MatchingValueSet(ignoreCase bool, allowedValues map[string]struct{}) *HTMLPolicyBuilderAttributeBuilder {
	return ab.Matching(&valueSetAttributePolicy{
		ignoreCase: ignoreCase,
		allowed:    maps.Clone(allowedValues),
	})
}

// Globally allows the attributes on any elements but filters the attributes'
// values based on previous calls to Matching….  Global attribute policies
// are applied after element specific policies.  Be careful of using this
// with attributes like type which have different meanings on different
// elements.  Also be careful of allowing globally attributes like href which
// can have more far-reaching effects on tags like <base> and <link> than on
// <a> because in the former, they have an effect without user interaction
// and can change the behavior of the current page.
func (ab *HTMLPolicyBuilderAttributeBuilder) Globally() *HTMLPolicyBuilder {
	b := ab.builder
	if slices.Contains(ab.attributeNames, "style") {
		// Make sure styling is sanitized rather than passed through, but do
		// not overrule a schema the caller named, in either order.
		if b.stylingPolicySchema == nil {
			b.AllowStyling()
			b.stylingPolicySchemaIsImplicit = true
		}
	}
	return b.allowAttributesGlobally(ab.policy, ab.attributeNames)
}

// OnElements allows the named attributes on the given elements but filters
// the attributes' values based on previous calls to Matching….
func (ab *HTMLPolicyBuilderAttributeBuilder) OnElements(elementNames ...string) *HTMLPolicyBuilder {
	canonNames := make([]string, len(elementNames))
	for i, elementName := range elementNames {
		canonNames[i] = htmlLexerCanonicalElementName(elementName)
	}
	return ab.builder.allowAttributesOnElements(ab.policy, ab.attributeNames, canonNames)
}

// patternAttributePolicy allows the values an anchored pattern matches.
type patternAttributePolicy struct {
	pattern *regexp.Regexp
}

// Apply returns value if the pattern matches it.
func (p *patternAttributePolicy) Apply(_, _, value string) (string, bool) {
	if !p.pattern.MatchString(value) {
		return "", false
	}
	return value, true
}

// predicateAttributePolicy allows the values a predicate accepts.
type predicateAttributePolicy struct {
	filter func(value string) bool
}

// Apply returns value if the predicate accepts it.
func (p *predicateAttributePolicy) Apply(_, _, value string) (string, bool) {
	if !p.filter(value) {
		return "", false
	}
	return value, true
}

// valueSetAttributePolicy allows the values in a set, optionally after
// lower-casing them.
type valueSetAttributePolicy struct {
	ignoreCase bool
	allowed    map[string]struct{}
}

// Apply returns the possibly lower-cased value if it is in the set.
func (p *valueSetAttributePolicy) Apply(_, _, uncanonValue string) (string, bool) {
	value := uncanonValue
	if p.ignoreCase {
		value = stringsToLowerCase(uncanonValue)
	}
	if _, ok := p.allowed[value]; !ok {
		return "", false
	}
	return value, true
}

// htmlPolicyBuilderRelsOnLinksPolicy adds the required rel values to links
// and removes the skipped ones.
type htmlPolicyBuilderRelsOnLinksPolicy struct {
	// extra is an insertion-ordered set.
	extra []string
	skip  map[string]struct{}
	// whenTargetPresent lists the default rels not otherwise added or
	// skipped, in hashOrderedSet order.
	whenTargetPresent []string
}

// htmlPolicyBuilderRelsOnLinksPolicyEmpty is the policy that only adds the
// default rels to links with a target.
var htmlPolicyBuilderRelsOnLinksPolicyEmpty = newHTMLPolicyBuilderRelsOnLinksPolicy(nil, nil)

// htmlPolicyBuilderRelsOnLinksPolicyCreate returns the policy for the given
// insertion-ordered extra rels and the skipped rels.
func htmlPolicyBuilderRelsOnLinksPolicyCreate(extra []string, skip map[string]struct{}) *htmlPolicyBuilderRelsOnLinksPolicy {
	if len(extra) == 0 && len(skip) == 0 {
		return htmlPolicyBuilderRelsOnLinksPolicyEmpty
	}
	return newHTMLPolicyBuilderRelsOnLinksPolicy(extra, skip)
}

// newHTMLPolicyBuilderRelsOnLinksPolicy returns a policy that keeps copies of
// extra and skip.
func newHTMLPolicyBuilderRelsOnLinksPolicy(extra []string, skip map[string]struct{}) *htmlPolicyBuilderRelsOnLinksPolicy {
	targetOnly := newHashOrderedSet()
	for _, rel := range htmlPolicyBuilderDefaultRelsOnTargettedLinksList {
		targetOnly.add(rel)
	}
	for _, rel := range extra {
		targetOnly.remove(rel)
	}
	for rel := range skip {
		targetOnly.remove(rel)
	}
	return &htmlPolicyBuilderRelsOnLinksPolicy{
		extra:             slices.Clone(extra),
		skip:              maps.Clone(skip),
		whenTargetPresent: targetOnly.items(),
	}
}

// htmlPolicyBuilderDefaultRelsOnTargettedLinksList is a private copy of
// DefaultRelsOnTargettedLinks.
var htmlPolicyBuilderDefaultRelsOnTargettedLinksList = slices.Clone(DefaultRelsOnTargettedLinks)

// htmlPolicyBuilderRelsOnLinksPolicyIndexOfAttributeValue returns the index
// of the value of the named attribute in attrs, or -1.
func htmlPolicyBuilderRelsOnLinksPolicyIndexOfAttributeValue(canonAttrName string, attrs []string) int {
	for i := 0; i < len(attrs); i += 2 {
		if attrs[i] == canonAttrName {
			return i + 1
		}
	}
	return -1
}

// Apply adjusts the rel attribute of links.
func (p *htmlPolicyBuilderRelsOnLinksPolicy) Apply(elementName string, attrs *[]string) (string, bool) {
	if htmlPolicyBuilderRelsOnLinksPolicyIndexOfAttributeValue("href", *attrs) < 0 {
		return elementName, true
	}
	// It's a link.
	hasTarget := htmlPolicyBuilderRelsOnLinksPolicyIndexOfAttributeValue("target", *attrs) >= 0
	if !hasTarget && len(p.extra) == 0 {
		return elementName, true
	}
	relIndex := htmlPolicyBuilderRelsOnLinksPolicyIndexOfAttributeValue("rel", *attrs)
	var relValue string
	if relIndex < 0 && hasTarget && len(p.extra) == 0 && len(p.skip) == 0 {
		relValue = htmlPolicyBuilderDefaultRelsOnTargettedLinksStr
	} else {
		var sb strings.Builder
		present := map[string]struct{}{}
		addRel := func(rel string) {
			if _, ok := present[rel]; !ok {
				present[rel] = struct{}{}
				sb.WriteString(rel)
				sb.WriteByte(' ')
			}
		}
		if relIndex >= 0 {
			// Preserve values that are not explicitly skipped.
			rels := (*attrs)[relIndex]
			left, n := 0, len(rels)
			for i := 0; i <= n; i++ {
				if i == n || stringsIsHTMLSpace(rune(rels[i])) {
					if left < i {
						lowerCaseRel := stringsToLowerCase(rels[left:i])
						if _, skipped := p.skip[lowerCaseRel]; !skipped {
							addRel(lowerCaseRel)
						}
					}
					left = i + 1
				}
			}
		}
		for _, rel := range p.extra {
			addRel(rel)
		}
		if hasTarget {
			for _, rel := range p.whenTargetPresent {
				addRel(rel)
			}
		}
		// Trim the last space.
		relValue = strings.TrimSuffix(sb.String(), " ")
	}
	if relValue == "" {
		if relIndex >= 0 {
			*attrs = slices.Delete(*attrs, relIndex-1, relIndex+1)
		}
	} else if relIndex < 0 {
		*attrs = append(*attrs, "rel", relValue)
	} else {
		(*attrs)[relIndex] = relValue
	}
	return elementName, true
}

// joinStrategy groups rel policies so that they are joined by
// htmlPolicyBuilderJoinRelsOnLinksPoliciesInstance.
func (p *htmlPolicyBuilderRelsOnLinksPolicy) joinStrategy() joinableJoinStrategy[JoinableElementPolicy] {
	return htmlPolicyBuilderJoinRelsOnLinksPoliciesInstance
}

// htmlPolicyBuilderJoinRelsOnLinksPolicies joins rel policies into one that
// adds the rels any of them adds unless any of them skips it.
type htmlPolicyBuilderJoinRelsOnLinksPolicies struct{}

// htmlPolicyBuilderJoinRelsOnLinksPoliciesInstance is the only
// htmlPolicyBuilderJoinRelsOnLinksPolicies.
var htmlPolicyBuilderJoinRelsOnLinksPoliciesInstance = htmlPolicyBuilderJoinRelsOnLinksPolicies{}

// join returns the rel policy for the union of the extra rels of toJoin
// minus the union of their skipped rels.
func (htmlPolicyBuilderJoinRelsOnLinksPolicies) join(toJoin []JoinableElementPolicy) JoinableElementPolicy {
	var extra []string
	skip := map[string]struct{}{}
	for _, ep := range toJoin {
		p := ep.(*htmlPolicyBuilderRelsOnLinksPolicy)
		for _, rel := range p.extra {
			if !slices.Contains(extra, rel) {
				extra = append(extra, rel)
			}
		}
		for rel := range p.skip {
			skip[rel] = struct{}{}
		}
	}
	extra = slices.DeleteFunc(extra, func(rel string) bool {
		_, skipped := skip[rel]
		return skipped
	})
	return htmlPolicyBuilderRelsOnLinksPolicyCreate(extra, skip)
}
