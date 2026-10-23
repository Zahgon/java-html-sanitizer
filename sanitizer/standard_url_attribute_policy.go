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

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/StandardUrlAttributePolicy.java.

package sanitizer

// standardURLAttributePolicy is a URL checker optimized to avoid allocation
// for the common case: http, https, mailto.
type standardURLAttributePolicy struct{}

// standardURLAttributePolicyInstance is the only standardURLAttributePolicy.
var standardURLAttributePolicyInstance = &standardURLAttributePolicy{}

// Apply returns the normalized URL if it names no protocol, or one of http,
// https and mailto in any case.
func (*standardURLAttributePolicy) Apply(elementName, attributeName, value string) (string, bool) {
	url := stringsStripHTMLSpaces(value)

protocolLoop:
	for i := 0; i < len(url); i++ {
		switch url[i] {
		case '/', '#', '?': // No protocol.
			break protocolLoop
		case ':':
			switch i {
			case 4:
				if !stringsRegionMatchesIgnoreCase("http", 0, url, 0, 4) {
					return "", false
				}
			case 5:
				if !stringsRegionMatchesIgnoreCase("https", 0, url, 0, 5) {
					return "", false
				}
			case 6:
				if !stringsRegionMatchesIgnoreCase("mailto", 0, url, 0, 6) {
					return "", false
				}
			default:
				return "", false
			}
			break protocolLoop
		}
	}
	return filterURLByProtocolAttributePolicyNormalizeUri(url), true
}
