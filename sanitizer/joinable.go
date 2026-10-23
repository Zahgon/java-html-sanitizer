// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/Joinable.java.

package sanitizer

import "reflect"

// joinable is something that can request special joining.
// If two or more things have the same (per policyEquals) join strategy then
// they will be grouped together for joining according to that strategy.
type joinable[T any] interface {
	joinStrategy() joinableJoinStrategy[T]
}

// joinableJoinStrategy is an n-ary function from T to a joined T.
//
// Strategies are grouped by policyEquals, so implementations should be
// comparable singletons.
type joinableJoinStrategy[T any] interface {
	// join joins toJoin into a single T.
	join(toJoin []T) T
}

// policyEquals reports whether a and b are equal policies, by the equality
// that the policies of this package define.
//
// A value whose type has an equals(any) bool method decides for itself.
// Any other value is equal only to an identical value of the same dynamic
// type, which gives pointers identity semantics.  Values that cannot be
// compared, such as an AttributePolicyFunc or an ElementPolicyFunc, are
// equal to nothing, not even to themselves, so joining never mistakes two
// distinct functions for one.
func policyEquals(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if e, ok := a.(interface{ equals(o any) bool }); ok {
		return e.equals(b)
	}
	va := reflect.ValueOf(a)
	if va.Type() != reflect.TypeOf(b) || !va.Comparable() {
		return false
	}
	return a == b
}

// indexOfPolicy returns the index of the first element of xs that is
// policyEquals to x, or -1.
func indexOfPolicy[T any](xs []T, x T) int {
	for i, el := range xs {
		if policyEquals(el, x) {
			return i
		}
	}
	return -1
}

// addPolicy appends x to the insertion-ordered set xs unless an equal element
// is already present, in which case xs keeps its order.
func addPolicy[T any](xs []T, x T) []T {
	if indexOfPolicy(xs, x) >= 0 {
		return xs
	}
	return append(xs, x)
}

// joinableJoinGroup is the set of special joinables that share a strategy.
type joinableJoinGroup[SJ any] struct {
	strategy joinableJoinStrategy[SJ]
	members  []SJ
}

// joinableJoinHelper flattens and joins policies of base type T, grouping
// those that implement the special joinable type SJ by their strategy.
//
// Every collection it keeps is insertion ordered, so the joined policy
// applies the plain policies in the order they were unrolled, followed by
// one joined policy per strategy in the order the strategies were first
// seen.
type joinableJoinHelper[T any, SJ joinable[SJ]] struct {
	zeroValue     T
	identityValue T
	// split returns the parts of x if x is itself a join of policies.
	split func(x T) ([]T, bool)
	// rejoin builds a policy that applies all of xs in order.
	rejoin                func(xs []T) T
	requireSpecialJoining []*joinableJoinGroup[SJ]
	uniq                  []T
}

// unroll adds x, or the parts of x if it is a joined policy, to the policies
// to join.
func (h *joinableJoinHelper[T, SJ]) unroll(x T) {
	if parts, ok := h.split(x); ok {
		for _, part := range parts {
			h.unroll(part)
		}
	} else if sj, ok := any(x).(SJ); ok {
		strategy := sj.joinStrategy()
		var group *joinableJoinGroup[SJ]
		for _, g := range h.requireSpecialJoining {
			if policyEquals(g.strategy, strategy) {
				group = g
				break
			}
		}
		if group == nil {
			group = &joinableJoinGroup[SJ]{strategy: strategy}
			h.requireSpecialJoining = append(h.requireSpecialJoining, group)
		}
		group.members = addPolicy(group.members, sj)
	} else {
		h.uniq = addPolicy(h.uniq, x)
	}
}

// join returns a policy equivalent to applying everything unrolled so far in
// order, failing early.
func (h *joinableJoinHelper[T, SJ]) join() T {
	if indexOfPolicy(h.uniq, h.zeroValue) >= 0 {
		return h.zeroValue
	}

	for _, group := range h.requireSpecialJoining {
		joined := group.members[0]
		if len(group.members) != 1 {
			joined = group.strategy.join(group.members)
		}
		h.uniq = addPolicy(h.uniq, any(joined).(T))
	}
	h.requireSpecialJoining = nil

	if i := indexOfPolicy(h.uniq, h.identityValue); i >= 0 {
		h.uniq = append(h.uniq[:i], h.uniq[i+1:]...)
	}

	switch len(h.uniq) {
	case 0:
		return h.identityValue
	case 1:
		return h.uniq[0]
	default:
		return h.rejoin(h.uniq)
	}
}
