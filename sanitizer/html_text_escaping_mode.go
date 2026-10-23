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

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/HtmlTextEscapingMode.java.

package sanitizer

import "strconv"

// HTMLTextEscapingMode describes how an element's content is parsed, from
// section 8.1.2.6 of http://www.whatwg.org/specs/web-apps/current-work/
//
// The text in CDATA and RCDATA elements must not contain any occurrences of
// the string "</" (U+003C LESS-THAN SIGN, U+002F SOLIDUS) followed by
// characters that case-insensitively match the tag name of the element
// followed by one of U+0009 CHARACTER TABULATION, U+000A LINE FEED (LF),
// U+000B LINE TABULATION, U+000C FORM FEED (FF), U+0020 SPACE, U+003E
// GREATER-THAN SIGN (>), or U+002F SOLIDUS (/), unless that string is part
// of an escaping text span.
//
// See also
// http://www.whatwg.org/specs/web-apps/current-work/#cdata-rcdata-restrictions
// for the elements which fall in each category.
type HTMLTextEscapingMode int

const (
	// HTMLTextEscapingModePcdata is normally escaped character data that
	// breaks around comments and tags.
	HTMLTextEscapingModePcdata HTMLTextEscapingMode = iota
	// HTMLTextEscapingModeCdata is a span of text where HTML special
	// characters are interpreted literally, as in a SCRIPT tag.
	HTMLTextEscapingModeCdata
	// HTMLTextEscapingModeCdataSometimes is like HTMLTextEscapingModeCdata
	// but only for certain browsers.
	HTMLTextEscapingModeCdataSometimes
	// HTMLTextEscapingModeRcdata is a span of text and character entity
	// references where HTML special characters are interpreted literally, as
	// in a TITLE tag.
	HTMLTextEscapingModeRcdata
	// HTMLTextEscapingModePlainText is a span of text where HTML special
	// characters are interpreted literally, where there is no end tag.
	// PLAIN_TEXT runs until the end of the file.
	HTMLTextEscapingModePlainText
	// HTMLTextEscapingModeVoid cannot contain data.
	HTMLTextEscapingModeVoid
)

// String returns the upper-case name of the mode, such as "PCDATA".
func (m HTMLTextEscapingMode) String() string {
	switch m {
	case HTMLTextEscapingModePcdata:
		return "PCDATA"
	case HTMLTextEscapingModeCdata:
		return "CDATA"
	case HTMLTextEscapingModeCdataSometimes:
		return "CDATA_SOMETIMES"
	case HTMLTextEscapingModeRcdata:
		return "RCDATA"
	case HTMLTextEscapingModePlainText:
		return "PLAIN_TEXT"
	case HTMLTextEscapingModeVoid:
		return "VOID"
	}
	return "HTMLTextEscapingMode(" + strconv.Itoa(int(m)) + ")"
}

// htmlTextEscapingModeEscapingModes maps canonical element names to the mode
// of their content, for every element whose mode is not PCDATA.
var htmlTextEscapingModeEscapingModes = map[string]HTMLTextEscapingMode{
	"iframe": HTMLTextEscapingModeCdata,
	// HTML5 does not treat listing as CDATA and treats XMP as deprecated,
	// but HTML2 does at
	// http://www.w3.org/MarkUp/1995-archive/NonStandard.html
	// Listing is not supported by browsers.
	"listing": HTMLTextEscapingModeCdataSometimes,
	"xmp":     HTMLTextEscapingModeCdata,

	// Technically, noembed, noscript and noframes are CDATA_SOMETIMES but
	// we can only be hurt by allowing tag content that looks like text so
	// we treat them as regular..
	// The IE-only comment element is not here either: no current browser
	// reads its content as raw text, so treating it so let markup inside
	// it reach the browser unvetted and unescaped.  It is an unknown
	// element, whose content is parsed and escaped like any other.

	// Runs till end of file.
	"plaintext": HTMLTextEscapingModePlainText,

	"script": HTMLTextEscapingModeCdata,
	"style":  HTMLTextEscapingModeCdata,

	// Textarea and Title are RCDATA, not CDATA, so decode entity references.
	"textarea": HTMLTextEscapingModeRcdata,
	"title":    HTMLTextEscapingModeRcdata,

	// Nodes that can't contain content.
	// http://www.w3.org/TR/html-markup/syntax.html#void-elements
	"area":    HTMLTextEscapingModeVoid,
	"base":    HTMLTextEscapingModeVoid,
	"br":      HTMLTextEscapingModeVoid,
	"col":     HTMLTextEscapingModeVoid,
	"command": HTMLTextEscapingModeVoid,
	"embed":   HTMLTextEscapingModeVoid,
	"hr":      HTMLTextEscapingModeVoid,
	"img":     HTMLTextEscapingModeVoid,
	"input":   HTMLTextEscapingModeVoid,
	"keygen":  HTMLTextEscapingModeVoid,
	"link":    HTMLTextEscapingModeVoid,
	"meta":    HTMLTextEscapingModeVoid,
	"param":   HTMLTextEscapingModeVoid,
	"source":  HTMLTextEscapingModeVoid,
	"track":   HTMLTextEscapingModeVoid,
	"wbr":     HTMLTextEscapingModeVoid,

	// EMPTY per http://www.w3.org/TR/REC-html32#basefont
	"basefont": HTMLTextEscapingModeVoid,
	"isindex":  HTMLTextEscapingModeVoid,
}

// EscapingModeForTag returns the mode used for content
// following a start tag with the given canonical name.
func EscapingModeForTag(canonTagName string) HTMLTextEscapingMode {
	if mode, ok := htmlTextEscapingModeEscapingModes[canonTagName]; ok {
		return mode
	}
	return HTMLTextEscapingModePcdata
}

// IsTagFollowedByLiteralContent reports whether content
// immediately following the start tag must be treated as special CDATA so
// that <'s are not treated as starting tags, comments or directives.
func IsTagFollowedByLiteralContent(canonTagName string) bool {
	mode := EscapingModeForTag(canonTagName)
	return mode != HTMLTextEscapingModePcdata && mode != HTMLTextEscapingModeVoid
}

// IsVoidElement reports whether the tag cannot contain
// any content -- will an HTML parser consider the element to have ended
// immediately after the start tag.
func IsVoidElement(canonTagName string) bool {
	return EscapingModeForTag(canonTagName) == HTMLTextEscapingModeVoid
}
