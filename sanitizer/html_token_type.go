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

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/HtmlTokenType.java.

package sanitizer

import "strconv"

// htmlTokenType is the type of an HTML token.
type htmlTokenType int

const (
	// htmlTokenTypeAttrname is an HTML or XML attribute name consisting of
	// characters other than whitespace, =, or specials.
	htmlTokenTypeAttrname htmlTokenType = iota
	// htmlTokenTypeAttrvalue is an HTML value, possibly a quoted string.
	htmlTokenTypeAttrvalue
	// htmlTokenTypeQmarkmeta is an HTML bogus comment, XML Prologue, or XML
	// processing instruction like <? content >.
	htmlTokenTypeQmarkmeta
	// htmlTokenTypeComment is an HTML or XML style comment,
	// <!-- for example -->.
	htmlTokenTypeComment
	// htmlTokenTypeDirective is a directive such as a DOCTYPE declaration.
	htmlTokenTypeDirective
	// htmlTokenTypeUnescaped is unescaped text, for instance, inside a
	// script, or xmp tag.
	htmlTokenTypeUnescaped
	// htmlTokenTypeQstring is a quoted string.  Should not show up in well
	// formed HTML, but may where there is an attribute value without a
	// corresponding name.
	htmlTokenTypeQstring
	// htmlTokenTypeTagbegin is the beginning of a tag -- not to be confused
	// with a start tag.  Valid tag beginnings include <a and </a.  The rest
	// of the tag is a series of attribute names, values, and the tag end.
	htmlTokenTypeTagbegin
	// htmlTokenTypeTagend is the end of a tag.  Either > or />.
	htmlTokenTypeTagend
	// htmlTokenTypeText is a block of text, either inside a tag, or as
	// element content.
	htmlTokenTypeText
	// htmlTokenTypeIgnorable is an ignorable whitespace node.
	htmlTokenTypeIgnorable
	// htmlTokenTypeServercode is a server side script block a la php or jsp.
	htmlTokenTypeServercode
)

// htmlTokenTypeNames are the upper-case names of the token types, by value.
var htmlTokenTypeNames = [...]string{
	htmlTokenTypeAttrname:   "ATTRNAME",
	htmlTokenTypeAttrvalue:  "ATTRVALUE",
	htmlTokenTypeQmarkmeta:  "QMARKMETA",
	htmlTokenTypeComment:    "COMMENT",
	htmlTokenTypeDirective:  "DIRECTIVE",
	htmlTokenTypeUnescaped:  "UNESCAPED",
	htmlTokenTypeQstring:    "QSTRING",
	htmlTokenTypeTagbegin:   "TAGBEGIN",
	htmlTokenTypeTagend:     "TAGEND",
	htmlTokenTypeText:       "TEXT",
	htmlTokenTypeIgnorable:  "IGNORABLE",
	htmlTokenTypeServercode: "SERVERCODE",
}

// String returns the upper-case name of the token type, such as "TAGBEGIN".
func (t htmlTokenType) String() string {
	if 0 <= t && int(t) < len(htmlTokenTypeNames) {
		return htmlTokenTypeNames[t]
	}
	return "htmlTokenType(" + strconv.Itoa(int(t)) + ")"
}
