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

// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/HtmlSanitizerFuzzerTest.java.

package sanitizer

import (
	"bufio"
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// htmlSanitizerFuzzerTestSeed seeds the generator, so that every run throws
// the same inputs.
const htmlSanitizerFuzzerTestSeed = 20261011

// htmlSanitizerFuzzerTestAwkwardChars are characters that the sanitizer
// strips, normalizes, writes as references or treats as whitespace,
// including the halves of surrogate pairs for the noncharacters at the end of
// the supplementary planes.  They are UTF-16 code units.
var htmlSanitizerFuzzerTestAwkwardChars = []uint16{
	0x0000, 0x0001, '\t', '\n', 0x000b, '\f', '\r', 0x001c, 0x001f,
	' ', 0x007f, 0x0080, 0x0085, 0x009f, 0x00a0, 0x2028,
	0x3000, 0xd800, 0xd83f, 0xdbff, 0xdc00, 0xdffe, 0xdfff,
	0xfdd0, 0xfdef, 0xfe64, 0xfeff, 0xff1c, 0xfffd, 0xfffe,
	0xffff,
}

// htmlSanitizerFuzzerTestRandom adds Random.nextGaussian to seededRandom.
type htmlSanitizerFuzzerTestRandom struct {
	*seededRandom
	nextNextGaussian     float64
	haveNextNextGaussian bool
}

// nextDouble is Random.nextDouble().
func (r *htmlSanitizerFuzzerTestRandom) nextDouble() float64 {
	return float64(int64(r.next(26))<<27+int64(r.next(27))) * 0x1.0p-53
}

// nextGaussian is Random.nextGaussian(), the polar method.
func (r *htmlSanitizerFuzzerTestRandom) nextGaussian() float64 {
	if r.haveNextNextGaussian {
		r.haveNextNextGaussian = false
		return r.nextNextGaussian
	}
	var v1, v2, s float64
	for {
		v1 = 2*r.nextDouble() - 1 // between -1 and 1
		v2 = 2*r.nextDouble() - 1 // between -1 and 1
		s = v1*v1 + v2*v2
		if s < 1 && s != 0 {
			break
		}
	}
	multiplier := math.Sqrt(-2 * math.Log(s) / s)
	r.nextNextGaussian = v2 * multiplier
	r.haveNextNextGaussian = true
	return v1 * multiplier
}

// htmlSanitizerFuzzerTestReadLinesJoined reads a file as UTF-8 and joins its
// lines without their terminators, as BufferedReader.lines() and
// Collectors.joining() do.
func htmlSanitizerFuzzerTestReadLinesJoined(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(nil, len(content)+1)
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		// A line ends at "\n", "\r" or "\r\n".
		for i, b := range data {
			switch b {
			case '\n':
				return i + 1, data[:i], nil
			case '\r':
				if i+1 < len(data) {
					if data[i+1] == '\n' {
						return i + 2, data[:i], nil
					}
					return i + 1, data[:i], nil
				}
				if atEOF {
					return i + 1, data[:i], nil
				}
				return 0, nil, nil
			}
		}
		if atEOF && len(data) != 0 {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	for scanner.Scan() {
		sb.Write(scanner.Bytes())
	}
	return sb.String(), scanner.Err()
}

// TestFuzzHTMLParser throws malformed inputs at the HTML sanitizer to try and
// crash it.  A failure reports the input it failed on.
func TestFuzzHTMLParser(t *testing.T) {
	html, err := htmlSanitizerFuzzerTestReadLinesJoined(
		filepath.Join("testdata", "benchmark-data", "Yahoo!.html"))
	if err != nil {
		t.Fatalf("Unable to resolve required resource: benchmark-data/Yahoo!.html: %v", err)
	}
	original := utf16Units(html)
	length := int32(len(original))

	fuzzyHTML0 := make([]uint16, length)
	fuzzyHTML1 := make([]uint16, length)

	rnd := &htmlSanitizerFuzzerTestRandom{seededRandom: newSeededRandom(htmlSanitizerFuzzerTestSeed)}
	doNothingPolicy := &hstReceiverFuncs{}

	const runCount = 1000
	// Run the inputs on a pool of workers, so that an infinite loop shows up
	// as a timeout rather than hanging the test run.
	inputs := make(chan string)
	var failures []string
	var failuresMu sync.Mutex
	var workers sync.WaitGroup
	for w := 0; w < 10; w++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for fuzzyHTML := range inputs {
				func() {
					defer func() {
						if r := recover(); r != nil {
							failuresMu.Lock()
							failures = append(failures, fmt.Sprintf(
								"Failed on <<<%s>>>: %v", fuzzyHTML, r))
							failuresMu.Unlock()
						}
					}()
					Sanitize(fuzzyHTML, doNothingPolicy, nil)
				}()
			}
		}()
	}

	for run := runCount; run > 0; run-- {
		copy(fuzzyHTML0, original)
		for fuzz := 1 + rnd.nextIntN(25); fuzz > 0; fuzz-- {
			if rnd.nextBoolean() {
				// Half of the time pick a character that the sanitizer strips,
				// normalizes or treats as whitespace, since dropping a
				// character is where two harmless tokens can join into a
				// harmful one.
				i := rnd.nextIntN(length)
				if rnd.nextBoolean() {
					fuzzyHTML0[i] = uint16(rnd.nextIntN(0x10000))
				} else {
					fuzzyHTML0[i] = htmlSanitizerFuzzerTestAwkwardChars[rnd.nextIntN(
						int32(len(htmlSanitizerFuzzerTestAwkwardChars)))]
				}
				continue
			}
			s0 := rnd.nextIntN(length - 1)
			d := math.Abs(rnd.nextGaussian()) / 3.0
			e0 := s0 + int32(float64(rnd.nextIntN(length-s0))*d)
			if e0 >= length {
				e0 = s0 + 1
			}

			s1 := rnd.nextIntN(length - 1)
			d = math.Abs(rnd.nextGaussian()) / 3.0
			e1 := s1 + int32(float64(rnd.nextIntN(length-s1))*d)
			if e1 >= length {
				e1 = s1 + 1
			}

			if s0 > s1 {
				s0, e0, s1, e1 = s1, e1, s0, e0
			}

			if e0 > s1 {
				e0 = s1
			}

			// Swap the ranges [s0, e0) and [s1, e1) into fuzzyHTML1.
			i1 := copy(fuzzyHTML1, fuzzyHTML0[:s0])
			i1 += copy(fuzzyHTML1[i1:], fuzzyHTML0[s1:e1])
			i1 += copy(fuzzyHTML1[i1:], fuzzyHTML0[e0:s1])
			i1 += copy(fuzzyHTML1[i1:], fuzzyHTML0[s0:e0])
			copy(fuzzyHTML1[i1:], fuzzyHTML0[e1:])
			// Swap the two buffers.
			fuzzyHTML0, fuzzyHTML1 = fuzzyHTML1, fuzzyHTML0
		}
		inputs <- fromUTF16Units(fuzzyHTML0)
	}
	close(inputs)

	done := make(chan struct{})
	go func() {
		workers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(runCount * 4 * time.Second):
		t.Fatal("fuzz runs did not finish in time")
	}
	if len(failures) != 0 {
		t.Fatalf("seed %d: %s", htmlSanitizerFuzzerTestSeed, failures[0])
	}
}
