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

package sanitizer

// The tables in this file reproduce one specific iteration order: that of a
// power-of-two table of buckets indexed by the low bits of a key's spread
// hash (stringHash with its high 16 bits folded into the low 16), with the
// entries of a bucket kept in insertion order and the table doubled when it
// becomes more than three-quarters full.  Where the sanitizer iterates over a
// set or map of names, for example the properties of a CSS schema or the
// rel values added to links that have a target, its output follows this
// order, so the order is reproduced exactly rather than left to Go's
// randomized map iteration or replaced by sorting.

// Sizing constants of the table.  A table starts with
// hashOrderedDefaultCapacity buckets unless a capacity is given, never grows
// beyond hashOrderedMaximumCapacity buckets, and doubles once it holds more
// than hashOrderedLoadFactor entries per bucket.  A bucket that grows past
// hashOrderedLongBucket entries while the table has fewer than
// hashOrderedLargeTable buckets also doubles the table.
const (
	hashOrderedDefaultCapacity = 16
	hashOrderedMaximumCapacity = 1 << 30
	hashOrderedLongBucket      = 8
	hashOrderedLargeTable      = 64
	hashOrderedLoadFactor      = float32(0.75)
)

// hashOrderedNode is one entry in a bucket of a hashOrderedMap.
type hashOrderedNode[V any] struct {
	hash  int32
	key   string
	value V
	next  *hashOrderedNode[V]
}

// hashOrderedEntry is a key and value pair, as returned by
// hashOrderedMap.entries.
type hashOrderedEntry[V any] struct {
	key   string
	value V
}

// hashOrderedMap is a map from strings to V whose iteration order is a
// deterministic function of the sequence of operations applied to it.
//
// It iterates over its buckets in index order and over each bucket's list in
// insertion order.  A resize splits each bucket into a low and a high half
// that keep that order, so the order depends on the history of operations
// only through the table size.  The table grows when it passes three-quarters
// full, and also when a bucket grows past eight entries in a table of fewer
// than 64 buckets.  A bucket longer than eight in a larger table keeps
// insertion order too; string keys only collide that much when they are
// chosen to.
type hashOrderedMap[V any] struct {
	table     []*hashOrderedNode[V]
	n         int
	threshold int
}

// newHashOrderedMap returns an empty map that allocates the default table
// size on first insertion.
func newHashOrderedMap[V any]() *hashOrderedMap[V] {
	return &hashOrderedMap[V]{}
}

// newHashOrderedMapWithCapacity returns an empty map whose table, once
// allocated, has initialCapacity buckets rounded up to a power of two.
func newHashOrderedMapWithCapacity[V any](initialCapacity int) *hashOrderedMap[V] {
	if initialCapacity < 0 {
		initialCapacity = 0
	}
	if initialCapacity > hashOrderedMaximumCapacity {
		initialCapacity = hashOrderedMaximumCapacity
	}
	return &hashOrderedMap[V]{threshold: hashOrderedTableSize(initialCapacity)}
}

// newHashOrderedMapFrom returns a map holding entries, inserted in order
// into a table sized for them as putAll sizes it.
func newHashOrderedMapFrom[V any](entries []hashOrderedEntry[V]) *hashOrderedMap[V] {
	m := newHashOrderedMap[V]()
	m.putAll(entries)
	return m
}

// hashOrderedTableSize returns the smallest power of two at least c,
// clamped to [1, hashOrderedMaximumCapacity].
func hashOrderedTableSize(c int) int {
	n := 1
	for n < c && n < hashOrderedMaximumCapacity {
		n <<= 1
	}
	return n
}

// spreadStringHash returns stringHash(key) with its high 16 bits XORed into
// the low 16, so that they take part in choosing the bucket.
func spreadStringHash(key string) int32 {
	h := stringHash(key)
	return h ^ int32(uint32(h)>>16)
}

// size returns the number of entries.
func (m *hashOrderedMap[V]) size() int { return m.n }

// resize allocates the table or doubles its size, splitting each bucket
// into a low and a high bucket that keep the order of their entries.
func (m *hashOrderedMap[V]) resize() {
	oldCap := len(m.table)
	oldThr := m.threshold
	newCap, newThr := 0, 0
	switch {
	case oldCap > 0:
		if oldCap >= hashOrderedMaximumCapacity {
			m.threshold = int(^uint32(0) >> 1)
			return
		}
		newCap = oldCap << 1
		if newCap < hashOrderedMaximumCapacity &&
			oldCap >= hashOrderedDefaultCapacity {
			newThr = oldThr << 1
		}
	case oldThr > 0:
		newCap = oldThr
	default:
		newCap = hashOrderedDefaultCapacity
		newThr = int(hashOrderedLoadFactor * hashOrderedDefaultCapacity)
	}
	if newThr == 0 {
		ft := float32(newCap) * hashOrderedLoadFactor
		if newCap < hashOrderedMaximumCapacity &&
			ft < float32(hashOrderedMaximumCapacity) {
			newThr = int(ft)
		} else {
			newThr = int(^uint32(0) >> 1)
		}
	}
	m.threshold = newThr
	newTab := make([]*hashOrderedNode[V], newCap)
	for j, e := range m.table {
		var loHead, loTail, hiHead, hiTail *hashOrderedNode[V]
		for ; e != nil; e = e.next {
			if int(e.hash)&oldCap == 0 {
				if loTail == nil {
					loHead = e
				} else {
					loTail.next = e
				}
				loTail = e
			} else {
				if hiTail == nil {
					hiHead = e
				} else {
					hiTail.next = e
				}
				hiTail = e
			}
		}
		if loTail != nil {
			loTail.next = nil
			newTab[j] = loHead
		}
		if hiTail != nil {
			hiTail.next = nil
			newTab[j+oldCap] = hiHead
		}
	}
	m.table = newTab
}

// put replaces the value of an existing entry in place or appends a new
// entry to its bucket.  It returns the previous value and
// whether there was one.
func (m *hashOrderedMap[V]) put(key string, value V) (V, bool) {
	if len(m.table) == 0 {
		m.resize()
	}
	hash := spreadStringHash(key)
	i := int(hash) & (len(m.table) - 1)
	p := m.table[i]
	if p == nil {
		m.table[i] = &hashOrderedNode[V]{hash: hash, key: key, value: value}
	} else {
		for binCount := 0; ; binCount++ {
			if p.hash == hash && p.key == key {
				old := p.value
				p.value = value
				return old, true
			}
			if p.next == nil {
				p.next = &hashOrderedNode[V]{hash: hash, key: key, value: value}
				if binCount >= hashOrderedLongBucket-1 &&
					len(m.table) < hashOrderedLargeTable {
					// A long bucket in a small table doubles the table.
					m.resize()
				}
				break
			}
			p = p.next
		}
	}
	m.n++
	if m.n > m.threshold {
		m.resize()
	}
	var zero V
	return zero, false
}

// putAll puts the entries in order.  It first sizes the table for the
// incoming entries: an unallocated table gets room for all of them at the
// load factor, and an allocated one doubles until its threshold covers their
// number.
func (m *hashOrderedMap[V]) putAll(entries []hashOrderedEntry[V]) {
	s := len(entries)
	if s == 0 {
		return
	}
	if len(m.table) == 0 {
		dt := float64(s) / float64(hashOrderedLoadFactor)
		t := int(dt)
		if float64(t) < dt {
			t++
		}
		if t > hashOrderedMaximumCapacity {
			t = hashOrderedMaximumCapacity
		}
		if t > m.threshold {
			m.threshold = hashOrderedTableSize(t)
		}
	} else {
		for s > m.threshold && len(m.table) < hashOrderedMaximumCapacity {
			m.resize()
		}
	}
	for _, e := range entries {
		m.put(e.key, e.value)
	}
}

// remove deletes the entry for key and returns its value and whether there
// was one.
func (m *hashOrderedMap[V]) remove(key string) (V, bool) {
	var zero V
	if len(m.table) == 0 {
		return zero, false
	}
	hash := spreadStringHash(key)
	i := int(hash) & (len(m.table) - 1)
	var prev *hashOrderedNode[V]
	for e := m.table[i]; e != nil; prev, e = e, e.next {
		if e.hash == hash && e.key == key {
			if prev == nil {
				m.table[i] = e.next
			} else {
				prev.next = e.next
			}
			m.n--
			return e.value, true
		}
	}
	return zero, false
}

// entries returns the entries in iteration order.
func (m *hashOrderedMap[V]) entries() []hashOrderedEntry[V] {
	out := make([]hashOrderedEntry[V], 0, m.n)
	for _, e := range m.table {
		for ; e != nil; e = e.next {
			out = append(out, hashOrderedEntry[V]{e.key, e.value})
		}
	}
	return out
}

// keys returns the keys in iteration order.
func (m *hashOrderedMap[V]) keys() []string {
	out := make([]string, 0, m.n)
	for _, e := range m.table {
		for ; e != nil; e = e.next {
			out = append(out, e.key)
		}
	}
	return out
}

// hashOrderedSet is a set of strings whose iteration order is a
// deterministic function of the sequence of operations applied to it.  It is
// a hashOrderedMap with empty values; see there for the order.
type hashOrderedSet struct {
	m *hashOrderedMap[struct{}]
}

// newHashOrderedSet returns an empty set.
func newHashOrderedSet() *hashOrderedSet {
	return &hashOrderedSet{newHashOrderedMap[struct{}]()}
}

// newHashOrderedSetWithCapacity returns an empty set whose table, once
// allocated, has initialCapacity buckets rounded up to a power of two.
func newHashOrderedSetWithCapacity(initialCapacity int) *hashOrderedSet {
	return &hashOrderedSet{newHashOrderedMapWithCapacity[struct{}](initialCapacity)}
}

// add adds item and reports whether it was absent.  Adding an item that is
// present leaves its position unchanged.
func (s *hashOrderedSet) add(item string) bool {
	_, existed := s.m.put(item, struct{}{})
	return !existed
}

// remove removes item and reports whether it was present.
func (s *hashOrderedSet) remove(item string) bool {
	_, existed := s.m.remove(item)
	return existed
}

// items returns the items in iteration order.
func (s *hashOrderedSet) items() []string { return s.m.keys() }
