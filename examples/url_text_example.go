// Copyright (c) 2013, Mike Samuel
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

// Ported from examples/src/main/java/org/owasp/html/examples/UrlTextExample.java.

package examples

import (
	"io"
	"strings"

	"github.com/OWASP/java-html-sanitizer/sanitizer"
)

// urlTextExampleAppendDomainAfterText is an event receiver that emits the
// domain of a link or image after it.
type urlTextExampleAppendDomainAfterText struct {
	sanitizer.HTMLStreamEventReceiverWrapper
	// pendingText is a stack holding, for each open element, the text to emit
	// after its close tag, if any.
	pendingText []*string
}

// newURLTextExampleAppendDomainAfterText returns a receiver that sends events
// to underlying, adding domains after links and images.
func newURLTextExampleAppendDomainAfterText(underlying sanitizer.HTMLStreamEventReceiver) *urlTextExampleAppendDomainAfterText {
	return &urlTextExampleAppendDomainAfterText{
		HTMLStreamEventReceiverWrapper: sanitizer.HTMLStreamEventReceiverWrapper{Underlying: underlying},
	}
}

// OpenTag passes the start tag on and arranges for the domain of the URL of
// a link or image to follow the element.
func (r *urlTextExampleAppendDomainAfterText) OpenTag(elementName string, attribs []string) {
	r.Underlying.OpenTag(elementName, attribs)

	var trailingText *string

	if len(attribs) != 0 {
		// Figure out which attribute we should look for.
		urlAttrName := ""
		switch elementName {
		case "a":
			urlAttrName = "href"
		case "img":
			urlAttrName = "src"
		}
		if urlAttrName != "" {
			// Look for the attribute, and after it for its value.
			for i := 0; i < len(attribs); i += 2 {
				if attribs[i] == urlAttrName {
					url := urlTextExampleTrim(attribs[i+1])
					if domain, ok := urlTextExampleDomainOf(url); ok {
						text := " - " + domain
						trailingText = &text
					}
					break
				}
			}
		}
	}
	if sanitizer.IsVoidElement(elementName) {
		// A void element like <img> will not have a corresponding CloseTag
		// call.
		if trailingText != nil {
			r.Text(*trailingText)
		}
	} else {
		// Push the trailing text onto a stack so when we see the corresponding
		// close tag, we can emit the text.
		r.pendingText = append(r.pendingText, trailingText)
	}
}

// CloseTag passes the end tag on, followed by any domain pending for the
// element it closes.
func (r *urlTextExampleAppendDomainAfterText) CloseTag(elementName string) {
	r.Underlying.CloseTag(elementName)
	// Pull the trailing text for the recently closed element off the stack.
	if n := len(r.pendingText); n != 0 {
		trailingText := r.pendingText[n-1]
		r.pendingText = r.pendingText[:n-1]
		if trailingText != nil {
			r.Text(*trailingText)
		}
	}
}

// URLTextPolicy returns the policy RunURLTextExample sanitizes with:
// common formatting, block and table elements, links and images with the
// standard URL protocols, and a postprocessor that emits the domain of a link
// or inline image after the link or image.
func URLTextPolicy() (*sanitizer.PolicyFactory, error) {
	return sanitizer.NewHTMLPolicyBuilder().
		AllowAttributes("src").OnElements("img").
		AllowAttributes("href").OnElements("a").
		// Allow some URLs through.
		AllowStandardURLProtocols().
		AllowElements(
			"a", "label", "h1", "h2", "h3", "h4", "h5", "h6",
			"p", "i", "b", "u", "strong", "em", "small", "big", "pre", "code",
			"cite", "samp", "sub", "sup", "strike", "center", "blockquote",
			"hr", "br", "col", "font", "span", "div", "img",
			"ul", "ol", "li", "dd", "dt", "dl", "tbody", "thead", "tfoot",
			"table", "td", "th", "tr", "colgroup", "fieldset", "legend",
		).
		WithPostprocessor(sanitizer.HTMLStreamEventProcessorFunc(
			func(sink sanitizer.HTMLStreamEventReceiver) sanitizer.HTMLStreamEventReceiver {
				return newURLTextExampleAppendDomainAfterText(sink)
			})).
		ToFactory()
}

// RunURLTextExample sanitizes inputs, joined with '\n', to out with
// URLTextPolicy.  It returns any error writing to out.
func RunURLTextExample(out io.Writer, inputs ...string) error {
	policy, err := URLTextPolicy()
	if err != nil {
		return err
	}
	_, err = io.WriteString(out, policy.Sanitize(strings.Join(inputs, "\n")))
	return err
}

// urlTextExampleDomainOf returns the domain (actually authority component) of
// an HTML5 URL, or false if it has none.  If the input is not hierarchical,
// then the result is undefined.
func urlTextExampleDomainOf(url string) (string, bool) {
	var start int
	if strings.HasPrefix(url, "//") {
		start = 2
	} else if start = strings.Index(url, "://"); start >= 0 {
		start += 3
	} else {
		return "", false
	}
	for i := 0; i < start-3; i++ {
		switch url[i] {
		case '/', '?', '#':
			return "", false
		}
	}
	end := len(url)
	for i := start; i < end; i++ {
		switch url[i] {
		case '/', '?', '#':
			end = i
		}
	}
	if start < end {
		return url[start:end], true
	}
	return "", false
}

// urlTextExampleTrim removes the characters at or below U+0020 from both ends
// of s, like a classic trim.
func urlTextExampleTrim(s string) string {
	start, end := 0, len(s)
	for start < end && s[start] <= ' ' {
		start++
	}
	for start < end && s[end-1] <= ' ' {
		end--
	}
	return s[start:end]
}
