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

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/FilterUrlByProtocolAttributePolicy.java.

package sanitizer

import (
	"strings"
	"unicode/utf8"
)

// FilterURLByProtocolAttributePolicy is an attribute policy for attributes
// whose values are URLs that requires that the value have no protocol or have
// an allowed protocol.
//
// URLs with protocols must match the protocol set passed to the constructor.
// URLs without protocols but which specify an origin different from the
// containing page (e.g. //example.org, including the equivalent slash and
// backslash spellings browsers recognize) are only allowed if the policy
// allows both http and https which are normally used to serve HTML (see
// AllowProtocolRelativeURLs).  Same-origin URLs, URLs without any protocol or
// authority part are always allowed.
//
// This type assumes that URLs are either hierarchical, or are opaque, but do
// not look like they contain an authority portion.
type FilterURLByProtocolAttributePolicy struct {
	protocols map[string]struct{}
}

// NewFilterURLByProtocolAttributePolicy returns a policy that allows the
// given protocols, which must be lower-case protocol names without any
// trailing colon (":").
func NewFilterURLByProtocolAttributePolicy(protocols []string) *FilterURLByProtocolAttributePolicy {
	set := make(map[string]struct{}, len(protocols))
	for _, protocol := range protocols {
		set[protocol] = struct{}{}
	}
	return &FilterURLByProtocolAttributePolicy{protocols: set}
}

// Apply returns the normalized URL if it names no protocol, or an allowed
// one, and does not introduce a disallowed authority.
func (p *FilterURLByProtocolAttributePolicy) Apply(elementName, attributeName, value string) (string, bool) {
	url := stringsStripHTMLSpaces(value)
	// When resolving against an HTTP(S) page, browsers treat backslashes as
	// slashes.  Each of these pairs introduces an authority: //, /\, \/, \\.
	if len(url) >= 2 &&
		filterURLByProtocolAttributePolicyIsURLSlash(url[0]) &&
		filterURLByProtocolAttributePolicyIsURLSlash(url[1]) &&
		!p.AllowProtocolRelativeURLs() {
		return "", false
	}
protocolLoop:
	for i := 0; i < len(url); i++ {
		switch url[i] {
		case '/', '#', '?': // No protocol.
			break protocolLoop
		case ':':
			protocol := stringsToLowerCase(url[:i])
			if _, ok := p.protocols[protocol]; !ok {
				return "", false
			}
			break protocolLoop
		}
	}
	return filterURLByProtocolAttributePolicyNormalizeUri(url), true
}

// filterURLByProtocolAttributePolicyIsURLSlash reports whether a browser
// resolving against an HTTP(S) page treats ch as a slash.
func filterURLByProtocolAttributePolicyIsURLSlash(ch byte) bool {
	return ch == '/' || ch == '\\'
}

// AllowProtocolRelativeURLs reports whether URLs like //example.org that
// name an authority but no protocol are allowed, which they are when both
// http and https are.
func (p *FilterURLByProtocolAttributePolicy) AllowProtocolRelativeURLs() bool {
	_, http := p.protocols["http"]
	_, https := p.protocols["https"]
	return http && https
}

// filterURLByProtocolAttributePolicyNormalizeUri percent encodes anything
// that looks like a colon, or a parenthesis.
func filterURLByProtocolAttributePolicyNormalizeUri(s string) string {
	colonsIrrelevant := false
	for i, ch := range s {
		switch ch {
		case '/', '#', '?', ':':
			colonsIrrelevant = true
		case '(', ')', '{', '}':
			return filterURLByProtocolAttributePolicyNormalizeUriFrom(s, i, colonsIrrelevant)
		case '։', '׃', '∶', '：':
			if !colonsIrrelevant {
				return filterURLByProtocolAttributePolicyNormalizeUriFrom(s, i, false)
			}
		default:
			if ch <= 0x20 {
				return filterURLByProtocolAttributePolicyNormalizeUriFrom(s, i, false)
			}
		}
	}
	return s
}

// filterURLByProtocolAttributePolicyNormalizeUriFrom encodes s from the byte
// offset start on, where the first character needing encoding is.
func filterURLByProtocolAttributePolicyNormalizeUriFrom(s string, start int, colonsIrrelevant bool) string {
	var sb strings.Builder
	sb.Grow(len(s) + 16)
	pos := 0
	for i := start; i < len(s); {
		ch, width := utf8.DecodeRuneInString(s[i:])
		repl, hasRepl := "", false
		switch ch {
		case '(':
			repl, hasRepl = "%28", true
		case ')':
			repl, hasRepl = "%29", true
		case '{':
			repl, hasRepl = "%7b", true
		case '}':
			repl, hasRepl = "%7d", true
		default:
			if ch >= 0x100 && !colonsIrrelevant {
				// Other colon like characters.
				switch ch {
				case '։':
					repl, hasRepl = "%d6%89", true
				case '׃':
					repl, hasRepl = "%d7%83", true
				case '∶':
					repl, hasRepl = "%e2%88%b6", true
				case '：':
					repl, hasRepl = "%ef%bc%9a", true
				}
			} else if ch <= 0x20 {
				repl, hasRepl = filterURLByProtocolAttributePolicyControlRepl[ch], true
			}
		}
		if hasRepl {
			sb.WriteString(s[pos:i])
			sb.WriteString(repl)
			pos = i + width
		}
		i += width
	}
	sb.WriteString(s[pos:])
	return sb.String()
}

// equals reports whether o is a FilterURLByProtocolAttributePolicy that
// allows the same protocols.
func (p *FilterURLByProtocolAttributePolicy) equals(o any) bool {
	q, ok := o.(*FilterURLByProtocolAttributePolicy)
	return ok && policyStringSetsEqual(p.protocols, q.protocols)
}

// policyStringSetsEqual reports whether a and b hold the same strings.
func policyStringSetsEqual(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for s := range a {
		if _, ok := b[s]; !ok {
			return false
		}
	}
	return true
}

// filterURLByProtocolAttributePolicyControlRepl holds the replacements for
// control characters.
var filterURLByProtocolAttributePolicyControlRepl = [...]string{
	"", "%01", "%02", "%03", "%04", "%05", "%06", "%07",
	"%08", "%09", "%0a", "%0b", "%0c", "%0d", "%0e", "%0f",
	"%10", "%11", "%12", "%13", "%14", "%15", "%16", "%17",
	"%18", "%19", "%1a", "%1b", "%1c", "%1d", "%1e", "%1f",
	"%20",
}
