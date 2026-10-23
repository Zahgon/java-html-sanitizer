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

import (
	"bufio"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// hashOrderUnescape decodes the \uXXXX escapes of the recorded keys.
func hashOrderUnescape(t *testing.T, s string) string {
	var units []uint16
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			v, err := strconv.ParseUint(s[i+2:i+6], 16, 16)
			if err != nil {
				t.Fatal(err)
			}
			units = append(units, uint16(v))
			i += 5
		} else {
			units = append(units, uint16(s[i]))
		}
	}
	return fromUTF16Units(units)
}

// hashOrderEntries parses "KEY=VALUE" fields.
func hashOrderEntries(t *testing.T, fields []string) []hashOrderedEntry[int] {
	var entries []hashOrderedEntry[int]
	for _, f := range fields {
		k, v, _ := strings.Cut(f, "=")
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, hashOrderedEntry[int]{hashOrderUnescape(t, k), n})
	}
	return entries
}

// TestHashOrder replays the recorded operation sequences in testdata and
// checks that the sets and maps iterate in the recorded order.
func TestHashOrder(t *testing.T) {
	f, err := os.Open("testdata/hash_order.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	var set *hashOrderedSet
	var m *hashOrderedMap[int]
	nCases, lineNo := 0, 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		args := fields[1:]
		switch op := fields[0]; {
		case op == "set" || op == "map":
			set, m = nil, nil
			capacity := -1
			if len(args) != 0 {
				if capacity, err = strconv.Atoi(args[0]); err != nil {
					t.Fatal(err)
				}
			}
			switch {
			case op == "set" && capacity < 0:
				set = newHashOrderedSet()
			case op == "set":
				set = newHashOrderedSetWithCapacity(capacity)
			case capacity < 0:
				m = newHashOrderedMap[int]()
			default:
				m = newHashOrderedMapWithCapacity[int](capacity)
			}
		case op == "setfrom":
			m = nil
			var items []string
			for _, a := range args {
				items = append(items, hashOrderUnescape(t, a))
			}
			// Sized for max(n, 12) items at the load factor.
			n := max(len(items), 12)
			set = newHashOrderedSetWithCapacity((n*4 + 2) / 3)
			for _, item := range items {
				set.add(item)
			}
		case op == "mapfrom":
			set = nil
			m = newHashOrderedMapFrom(hashOrderEntries(t, args))
		case op == "*":
			if set != nil {
				for _, a := range args {
					set.add(hashOrderUnescape(t, a))
				}
			} else {
				m.putAll(hashOrderEntries(t, args))
			}
		case op == "=":
			nCases++
			var got []string
			if set != nil {
				for _, k := range set.items() {
					got = append(got, k)
				}
			} else {
				for _, e := range m.entries() {
					got = append(got, e.key+"="+strconv.Itoa(e.value))
				}
			}
			var want []string
			for _, a := range args {
				if set != nil {
					want = append(want, hashOrderUnescape(t, a))
				} else {
					k, v, _ := strings.Cut(a, "=")
					want = append(want, hashOrderUnescape(t, k)+"="+v)
				}
			}
			if !slices.Equal(got, want) {
				t.Errorf("line %d: order\n got %q\nwant %q", lineNo, got, want)
			}
		case strings.HasPrefix(op, "+"):
			if set != nil {
				set.add(hashOrderUnescape(t, op[1:]))
			} else {
				e := hashOrderEntries(t, []string{op[1:]})[0]
				m.put(e.key, e.value)
			}
		case strings.HasPrefix(op, "-"):
			k := hashOrderUnescape(t, op[1:])
			if set != nil {
				set.remove(k)
			} else {
				m.remove(k)
			}
		default:
			t.Fatalf("line %d: bad operation %q", lineNo, line)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if nCases < 300 {
		t.Errorf("only %d cases", nCases)
	}
}

// TestHashOrderedSetResizesLongBucketInSmallTable checks that a bucket of
// more than eight entries in a table smaller than 64 doubles the table.  The
// keys in family all have the same stringHash.
func TestHashOrderedSetResizesLongBucketInSmallTable(t *testing.T) {
	var family []string
	for i := 0; i < 16; i++ {
		k := "c"
		for bit := 3; bit >= 0; bit-- {
			if i>>bit&1 == 0 {
				k += "Aa"
			} else {
				k += "BB"
			}
		}
		family = append(family, k)
	}
	for _, tc := range []struct {
		pre       []string
		n         int
		tableSize int
		want      string
	}{
		{strings.Fields("a b c d e f g h"), 8, 64,
			"a b c cAaAaAaAa cAaAaAaBB cAaAaBBAa cAaAaBBBB cAaBBAaAa cAaBBAaBB cAaBBBBAa cAaBBBBBB d e f g h"},
		{nil, 9, 32,
			"cAaAaAaAa cAaAaAaBB cAaAaBBAa cAaAaBBBB cAaBBAaAa cAaBBAaBB cAaBBBBAa cAaBBBBBB cBBAaAaAa"},
		{nil, 10, 64,
			"cAaAaAaAa cAaAaAaBB cAaAaBBAa cAaAaBBBB cAaBBAaAa cAaBBAaBB cAaBBBBAa cAaBBBBBB cBBAaAaAa cBBAaAaBB"},
		{[]string{"x", "y"}, 10, 64,
			"cAaAaAaAa cAaAaAaBB cAaAaBBAa cAaAaBBBB cAaBBAaAa cAaBBAaBB cAaBBBBAa cAaBBBBBB cBBAaAaAa cBBAaAaBB x y"},
	} {
		s := newHashOrderedSet()
		for _, k := range append(slices.Clone(tc.pre), family[:tc.n]...) {
			s.add(k)
		}
		if got := strings.Join(s.items(), " "); got != tc.want {
			t.Errorf("%v + %d: got %q, want %q", tc.pre, tc.n, got, tc.want)
		}
		if got := len(s.m.table); got != tc.tableSize {
			t.Errorf("%v + %d: table size %d, want %d", tc.pre, tc.n, got, tc.tableSize)
		}
	}
}
