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

// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/HtmlPolicyBuilderFuzzerTest.java.

package sanitizer

import (
	"strings"
	"testing"
)

// The fuzz test throws random policy calls to find evidence against the
// claim that the security of the policy is decoupled from that of the parser.
// It checks the DOM that a browser-conformant HTML parser (validator.nu)
// builds from each output.  Go's standard library has no such parser, so the
// test was replayed once against the reference implementation with
// htmlPolicyBuilderFuzzerTestSeed and the elements of every DOM recorded, keyed by the output, in
// testdata/html_policy_builder_fuzzer_test_doms.json.gz: one list per element
// in document order, its name followed by its attribute names and values.
// The Go test draws the same calls from the same seed, so an output that is
// not recorded is one the reference implementation never produced, which is
// itself a failure.
const (
	htmlPolicyBuilderFuzzerTestSeed     = 20261011
	htmlPolicyBuilderFuzzerTestDOMsFile = "html_policy_builder_fuzzer_test_doms.json.gz"
)

var htmlPolicyBuilderFuzzerTestChunks = []string{
	"Hello, World!", "<b>", "</b>",
	"<a onclick='doEvil()' href=javascript:alert(1337)>", "</a>",
	"<script>", "</script>", "<xmp>", "</xmp>", "javascript:alert(1337)",
	"<style>", "</style>", "<plaintext>", "<!--", "-->", "<![CDATA[", "]]>",
}

var htmlPolicyBuilderFuzzerTestElementNames = []string{
	"a", "A",
	"b", "B",
	"script", "SCRipT",
	"style", "STYLE",
	"object", "Object",
	"noscript", "noScript",
	"xmp", "XMP",
}

var htmlPolicyBuilderFuzzerTestAttrNames = []string{
	"href", "id", "class", "onclick", "checked", "style",
}

// TestFuzzedOutput checks that whatever sequence of calls the policy gets,
// a browser finds only the allowed elements and attributes in its output.
func TestFuzzedOutput(t *testing.T) {
	policyFactory := hstFactory(t, NewHTMLPolicyBuilder().
		AllowElements("a", "b", "xmp", "pre").
		AllowAttributes("href").OnElements("a").
		AllowAttributes("title").Globally().
		AllowStandardURLProtocols())

	var doms map[string][][]string
	if err := hstLoadGzippedJSON(htmlPolicyBuilderFuzzerTestDOMsFile, &doms); err != nil {
		t.Fatalf("loading recorded DOMs: %v", err)
	}

	rnd := newSeededRandom(htmlPolicyBuilderFuzzerTestSeed)
	for i := 1000; i > 0; i-- {
		var sb strings.Builder
		policy := policyFactory.Apply(
			NewHTMLStreamRendererToBuilder(&sb, DoNothing[string]))
		policy.OpenDocument()
		var attributes []string
		for j := 50; j > 0; j-- {
			switch r := rnd.nextIntN(3); r {
			case 0:
				attributes = attributes[:0]
				if rnd.nextBoolean() {
					for k := rnd.nextIntN(4); k > 0; k-- {
						attributes = append(attributes,
							htmlPolicyBuilderFuzzerTestPick(rnd, htmlPolicyBuilderFuzzerTestAttrNames),
							htmlPolicyBuilderFuzzerTestPickChunk(rnd))
					}
				}
				policy.OpenTag(
					htmlPolicyBuilderFuzzerTestPick(rnd, htmlPolicyBuilderFuzzerTestElementNames),
					attributes)
			case 1:
				policy.CloseTag(
					htmlPolicyBuilderFuzzerTestPick(rnd, htmlPolicyBuilderFuzzerTestElementNames))
			case 2:
				policy.Text(htmlPolicyBuilderFuzzerTestPickChunk(rnd))
			default:
				t.Fatalf("Randomly chosen number in [0-3) was %d", r)
			}
		}
		policy.CloseDocument()

		html := sb.String()
		elements, ok := doms[html]
		if !ok {
			t.Fatalf("seed %d: no DOM recorded for %q: the reference run never produced it",
				htmlPolicyBuilderFuzzerTestSeed, html)
		}
		htmlPolicyBuilderFuzzerTestCheckSafe(t, elements, html)
	}
}

// htmlPolicyBuilderFuzzerTestCheckSafe checks the elements of a DOM, each its
// name followed by its attribute names and values.
func htmlPolicyBuilderFuzzerTestCheckSafe(t *testing.T, elements [][]string, html string) {
	t.Helper()
	for _, element := range elements {
		name := element[0]
		if name != "a" && name != "b" && name != "pre" {
			t.Fatalf("Illegal element name %s : %s", name, html)
		}
		for i := 1; i+1 < len(element); i += 2 {
			attrName, attrValue := element[i], element[i+1]
			if attrName == "href" {
				hstAssertEqual(t, "a", name, html)
				hstAssertFalse(t,
					strings.Contains(stringsToLowerCase(attrValue), "script:"), html)
			}
		}
	}
}

func htmlPolicyBuilderFuzzerTestPick(rnd *seededRandom, choices []string) string {
	return choices[rnd.nextIntN(int32(len(choices)))]
}

func htmlPolicyBuilderFuzzerTestPickChunk(rnd *seededRandom) string {
	chunk := htmlPolicyBuilderFuzzerTestPick(rnd, htmlPolicyBuilderFuzzerTestChunks)
	start := int32(0)
	end := int32(len(chunk))
	if rnd.nextBoolean() {
		start = rnd.nextIntN(end - 1)
	}
	if end-start < 2 && rnd.nextBoolean() {
		end = start + rnd.nextIntN(end-start)
	}
	return chunk[start:end]
}
