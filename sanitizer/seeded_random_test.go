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
	"slices"
	"testing"
)

// seededRandom is a 48-bit linear congruential generator (multiplier
// 0x5DEECE66D, addend 11).  The fuzz tests draw from it so that a seed
// reproduces the same inputs as the recorded expectations were made with.
type seededRandom struct {
	seed int64
}

const (
	seededRandomMultiplier = 0x5DEECE66D
	seededRandomAddend     = 0xB
	seededRandomMask       = 1<<48 - 1
)

// newSeededRandom returns a generator with the given seed, scrambled with the
// multiplier.
func newSeededRandom(seed int64) *seededRandom {
	return &seededRandom{(seed ^ seededRandomMultiplier) & seededRandomMask}
}

// next advances the generator and returns its top bits bits.
func (r *seededRandom) next(bits int) int32 {
	r.seed = (r.seed*seededRandomMultiplier + seededRandomAddend) & seededRandomMask
	return int32(r.seed >> (48 - bits))
}

// nextInt returns 32 random bits.
func (r *seededRandom) nextInt() int32 { return r.next(32) }

// nextIntN returns a value in [0, bound), rejecting draws that would bias
// the result.
func (r *seededRandom) nextIntN(bound int32) int32 {
	n := r.next(31)
	m := bound - 1
	if bound&m == 0 {
		return int32((int64(bound) * int64(n)) >> 31)
	}
	for u := n; ; u = r.next(31) {
		n = u % bound
		if u-n+m >= 0 {
			return n
		}
	}
}

// nextBoolean returns one random bit.
func (r *seededRandom) nextBoolean() bool { return r.next(1) != 0 }

func TestSeededRandomSequence(t *testing.T) {
	// Reference values for seed 42.
	r := newSeededRandom(42)
	got := []int32{r.nextInt(), r.nextIntN(10), r.nextIntN(16), r.nextIntN(1000)}
	if r.nextBoolean() {
		got = append(got, 1)
	} else {
		got = append(got, 0)
	}
	want := []int32{-1170105035, 3, 10, 884, 0}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
