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

// Ported from examples/src/main/java/org/owasp/html/examples/SlashdotPolicyExample.java.

package examples

import (
	"io"

	"github.com/OWASP/java-html-sanitizer/sanitizer"
)

// SlashdotPolicy is a policy definition that matches
// the minimal HTML that Slashdot allows.  It is based on the AntiSamy Slashdot
// example
// (http://www.owasp.org/index.php/Category:OWASP_AntiSamy_Project#Stage_2_-_Choosing_a_base_policy_file):
//
//	Slashdot (http://www.slashdot.org/) is a techie news site that allows
//	users to respond anonymously to news posts with very limited HTML
//	markup. Now Slashdot is not only one of the coolest sites around, it's
//	also one that's been subject to many different successful attacks. Even
//	more unfortunate is the fact that most of the attacks led users to the
//	infamous goatse.cx picture (please don't go look it up). The rules for
//	Slashdot are fairly strict: users can only submit the following HTML
//	tags and no CSS: <b>, <u>, <i>, <a>, <blockquote>.
//
//	Accordingly, we've built a policy file that allows fairly similar
//	functionality. All text-formatting tags that operate directly on the
//	font, color or emphasis have been allowed.
var SlashdotPolicy = examplesMustFactory(sanitizer.NewHTMLPolicyBuilder().
	AllowStandardURLProtocols().
	// Allow title="..." on any element.
	AllowAttributes("title").Globally().
	// Allow href="..." on <a> elements.
	AllowAttributes("href").OnElements("a").
	// Defeat link spammers.
	RequireRelNofollowOnLinks().
	// Allow lang= with an alphabetic value on any element.
	AllowAttributes("lang").MatchingPattern(examplesWholeMatch(`[a-zA-Z]{2,20}`)).
	Globally().
	// The align attribute on <p> elements can have any value below.
	AllowAttributes("align").
	MatchingValues(true, "center", "left", "right", "justify", "char").
	OnElements("p").
	// These elements are allowed.
	AllowElements(
		"a", "p", "div", "i", "b", "em", "blockquote", "tt", "strong",
		"br", "ul", "ol", "li").
	// Custom slashdot tags.
	// These could be rewritten in the sanitizer using an ElementPolicy.
	AllowElements("quote", "ecode"))

// RunSlashdotPolicy reads HTML from in and writes content sanitized by
// SlashdotPolicy to out.  in is decoded as UTF-8 and
// its lines are joined with '\n', so line terminators are normalized and a
// trailing one is dropped.
//
// It returns the first error writing to out, or an error carrying the
// message of the first alert the renderer raises on truly bizarre input;
// either stops the sanitization.
func RunSlashdotPolicy(in io.Reader, out io.Writer) error {
	return examplesRunTestBed(in, out, SlashdotPolicy)
}
