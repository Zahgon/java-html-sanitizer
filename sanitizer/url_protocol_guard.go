// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/UrlProtocolGuard.java.

package sanitizer

// urlProtocolGuard is the guard HTMLPolicyBuilder puts on every URL attribute
// it allows, which lets a value through only if it names no protocol or names
// one the builder allowed via HTMLPolicyBuilder.AllowURLProtocols.
//
// A builder that allowed no protocol installs urlProtocolGuardNone, which
// rejects every URL that names a protocol.  That is a default, not an
// allowlist, and the difference shows when two factories are combined by
// PolicyFactory.And: the default yields to the other factory's allowlist,
// whereas two allowlists intersect, as policies on the same attribute always
// do.  So a factory that never mentioned protocols leaves the links of one
// that did alone, while two factories that each allowed some protocols
// together allow only those both allowed.  The default yields only to another
// guard.  It never yields to a policy an author attached with Matching, so a
// builder that allowed no protocol rejects every absolute URL on its own,
// however its author-supplied policies are written.
//
// HTMLPolicyBuilder.AllowOnlyRelativeURLs installs urlProtocolGuardRelativeOnly,
// whose explicit empty allowlist does not yield.  Two nonempty allowlists
// with nothing in common also join to an explicit empty allowlist.  On its
// own either behaves like the default, but neither is one, so the same
// factories combined in any grouping allow the same URLs.
type urlProtocolGuard struct {
	// allowlist holds the protocols allowed.  It is nil, as opposed to empty,
	// only for the default guard.
	allowlist map[string]struct{}
	delegate  AttributePolicy
}

// urlProtocolGuardStandardProtocols is the protocol set that
// standardURLAttributePolicy checks.
var urlProtocolGuardStandardProtocols = map[string]struct{}{
	"http": {}, "https": {}, "mailto": {},
}

// urlProtocolGuardNone is the guard for a builder that allowed no protocol.
var urlProtocolGuardNone = newURLProtocolGuard(nil)

// urlProtocolGuardRelativeOnly is the explicit empty allowlist for a
// relative-only builder.
var urlProtocolGuardRelativeOnly = newURLProtocolGuard(map[string]struct{}{})

// urlProtocolGuardForProtocols returns the guard that enforces the given
// allowlist, or urlProtocolGuardNone if it is empty.
func urlProtocolGuardForProtocols(protocols map[string]struct{}) *urlProtocolGuard {
	if len(protocols) == 0 {
		return urlProtocolGuardNone
	}
	return newURLProtocolGuard(protocols)
}

// newURLProtocolGuard returns a guard that enforces a copy of allowlist, or
// the default guard if allowlist is nil.
func newURLProtocolGuard(allowlist map[string]struct{}) *urlProtocolGuard {
	if allowlist == nil {
		return &urlProtocolGuard{
			delegate: NewFilterURLByProtocolAttributePolicy(nil),
		}
	}
	g := &urlProtocolGuard{allowlist: make(map[string]struct{}, len(allowlist))}
	protocols := make([]string, 0, len(allowlist))
	for protocol := range allowlist {
		g.allowlist[protocol] = struct{}{}
		protocols = append(protocols, protocol)
	}
	// The standard set has a checker that allocates nothing per URL.
	if policyStringSetsEqual(urlProtocolGuardStandardProtocols, g.allowlist) {
		g.delegate = standardURLAttributePolicyInstance
	} else {
		g.delegate = NewFilterURLByProtocolAttributePolicy(protocols)
	}
	return g
}

// Apply vets the URL with the delegate checker.
func (g *urlProtocolGuard) Apply(elementName, attributeName, value string) (string, bool) {
	return g.delegate.Apply(elementName, attributeName, value)
}

// joinStrategy groups guards so that they are joined by
// urlProtocolGuardURLProtocolGuardJoinStrategyInstance.
func (g *urlProtocolGuard) joinStrategy() joinableJoinStrategy[JoinableAttributePolicy] {
	return urlProtocolGuardURLProtocolGuardJoinStrategyInstance
}

// equals reports whether o is a guard with the same allowlist, the default
// guard being equal only to itself.
func (g *urlProtocolGuard) equals(o any) bool {
	h, ok := o.(*urlProtocolGuard)
	if !ok {
		return false
	}
	if g.allowlist == nil || h.allowlist == nil {
		return g.allowlist == nil && h.allowlist == nil
	}
	return policyStringSetsEqual(g.allowlist, h.allowlist)
}

// urlProtocolGuardURLProtocolGuardJoinStrategy intersects the allowlists
// being joined; the default guard yields.
type urlProtocolGuardURLProtocolGuardJoinStrategy struct{}

// urlProtocolGuardURLProtocolGuardJoinStrategyInstance is the only
// urlProtocolGuardURLProtocolGuardJoinStrategy.
var urlProtocolGuardURLProtocolGuardJoinStrategyInstance = urlProtocolGuardURLProtocolGuardJoinStrategy{}

// join returns the guard for the intersection of the allowlists of toJoin,
// ignoring default guards, or the default guard if all of them are.
func (urlProtocolGuardURLProtocolGuardJoinStrategy) join(toJoin []JoinableAttributePolicy) JoinableAttributePolicy {
	var allowed map[string]struct{}
	for _, p := range toJoin {
		allowlist := p.(*urlProtocolGuard).allowlist
		if allowlist == nil {
			continue
		}
		if allowed == nil {
			allowed = make(map[string]struct{}, len(allowlist))
			for protocol := range allowlist {
				allowed[protocol] = struct{}{}
			}
		} else {
			for protocol := range allowed {
				if _, ok := allowlist[protocol]; !ok {
					delete(allowed, protocol)
				}
			}
		}
	}
	if allowed == nil {
		return urlProtocolGuardNone
	}
	return newURLProtocolGuard(allowed)
}
