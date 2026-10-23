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

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/Trie.java.

package sanitizer

import (
	"slices"
	"sort"
)

// trie maps strings to values so that a greedy left-to-right scan can find
// the longest key that prefixes some text, as the HTML entity decoder does
// with entity names.
//
// Edges are labelled with UTF-16 code units, so keys are ordered by code
// unit.  The keys used in this package are all ASCII, so an edge label is
// also the key's byte at that depth.
type trie[T any] struct {
	childMap []rune
	children []*trie[T]
	terminal bool
	value    T
}

// trieEntry is a key, as UTF-16 code units, with its value.
type trieEntry[T any] struct {
	key   []uint16
	value T
}

// newTrie builds a trie from elements, which must not be empty.
func newTrie[T any](elements map[string]T) *trie[T] {
	entries := make([]trieEntry[T], 0, len(elements))
	for k, v := range elements {
		entries = append(entries, trieEntry[T]{utf16Units(k), v})
	}
	sort.Slice(entries, func(i, j int) bool {
		return slices.Compare(entries[i].key, entries[j].key) < 0
	})
	return newTrieRange(entries, 0, 0, len(entries))
}

// newTrieRange builds the subtree at the given depth for the sorted entries
// in [start, end), all of which share their first depth code units.
func newTrieRange[T any](
	elements []trieEntry[T], depth, start, end int,
) *trie[T] {
	t := &trie[T]{}
	pos := start
	t.terminal = depth == len(elements[pos].key)
	if t.terminal {
		t.value = elements[pos].value
		if pos+1 == end { // base case
			return t
		}
		pos++
	}
	childCount := 0
	{
		last := -1
		for i := pos; i < end; i++ {
			ch := int(elements[i].key[depth])
			if ch != last {
				childCount++
				last = ch
			}
		}
	}
	t.childMap = make([]rune, 0, childCount)
	t.children = make([]*trie[T], 0, childCount)
	childStart := pos
	lastCh := elements[pos].key[depth]
	for i := pos + 1; i < end; i++ {
		ch := elements[i].key[depth]
		if ch != lastCh {
			t.childMap = append(t.childMap, rune(lastCh))
			t.children = append(
				t.children, newTrieRange(elements, depth+1, childStart, i))
			childStart = i
			lastCh = ch
		}
	}
	t.childMap = append(t.childMap, rune(lastCh))
	t.children = append(
		t.children, newTrieRange(elements, depth+1, childStart, end))
	return t
}

// isTerminal reports whether this node corresponds to a complete string in
// the input set.
func (t *trie[T]) isTerminal() bool { return t.terminal }

// lookup returns the child corresponding to the UTF-16 code unit ch, or nil
// if there is no such trie.
func (t *trie[T]) lookup(ch rune) *trie[T] {
	if i, ok := slices.BinarySearch(t.childMap, ch); ok {
		return t.children[i]
	}
	return nil
}
