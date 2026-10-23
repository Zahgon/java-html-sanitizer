/*
 * Copyright (c) 2007-2010, Arshan Dabirsiaghi, Jason Li
 *
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * Neither the name of OWASP nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// Ported from owasp-java-html-sanitizer/src/test/java/org/owasp/html/AntiSamyTest.java.

package sanitizer

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// These tests check AntiSamy functionality and the basic policy file which
// should be immune to XSS and CSS phishing attacks.
//
// Author: Arshan Dabirsiaghi

// astRunKnownFailures turns on the cases that are known to fail.
const astRunKnownFailures = false

// astMakePolicy returns the policy the tests share, writing to buffer and
// failing the test if the renderer reports bad HTML.
func astMakePolicy(t testing.TB, buffer *strings.Builder) HTMLSanitizerPolicy {
	t.Helper()
	renderer := NewHTMLStreamRenderer(
		buffer,
		Propagate,
		func(errorMessage string) { t.Error(errorMessage) })

	policy, err := NewHTMLPolicyBuilder().
		AllowElements(
			"a", "b", "br", "div", "font", "i", "img", "input", "li",
			"ol", "p", "span", "td", "ul").
		AllowAttributes("checked", "type").OnElements("input").
		AllowAttributes("color").OnElements("font").
		AllowAttributes("href").OnElements("a").
		AllowAttributes("src").OnElements("img").
		AllowAttributes("class", "id", "title").Globally().
		AllowAttributes("char").
		Matching(AttributePolicyFunc(
			func(elementName, attributeName, value string) (string, bool) {
				return value, utf16Length(value) == 1
			})).
		OnElements("td").
		AllowStandardURLProtocols().
		RequireRelNofollowOnLinks().
		AllowStyling().
		Build(renderer)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return policy
}

// astSanitize sanitizes html with the shared policy.
func astSanitize(t testing.TB, html string) string {
	t.Helper()
	var sb strings.Builder

	Sanitize(html, astMakePolicy(t, &sb), nil)

	return sb.String()
}

var astBase64BadXMLStrings = []string{
	// first string is
	// "<a - href=\"http://www.owasp.org\">click here</a>"
	"PGEgLSBocmVmPSJodHRwOi8vd3d3Lm93YXNwLm9yZyI+Y2xpY2sgaGVyZTwvYT4=",
	// the rest are randomly generated 300 byte sequences which generate
	// parser errors, turned into Strings
	"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",
}

// astDecodeUTF8 decodes b as UTF-8 in which each maximal ill-formed
// subsequence becomes one U+FFFD.
func astDecodeUTF8(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); {
		if r, size := utf8.DecodeRune(b[i:]); r != utf8.RuneError || size != 1 {
			sb.WriteRune(r)
			i += size
			continue
		}
		sb.WriteRune(utf8.RuneError)
		i += astMaximalSubpart(b[i:])
	}
	return sb.String()
}

// astMaximalSubpart returns the length of the maximal prefix of b, which
// starts with an ill-formed sequence, that is a prefix of some well-formed
// sequence, or 1 if there is none.
func astMaximalSubpart(b []byte) int {
	lo, hi, need := byte(0x80), byte(0xbf), 0
	switch lead := b[0]; {
	case 0xc2 <= lead && lead <= 0xdf:
		need = 1
	case lead == 0xe0:
		lo, need = 0xa0, 2
	case lead == 0xed:
		hi, need = 0x9f, 2
	case 0xe1 <= lead && lead <= 0xef:
		need = 2
	case lead == 0xf0:
		lo, need = 0x90, 3
	case 0xf1 <= lead && lead <= 0xf3:
		need = 3
	case lead == 0xf4:
		hi, need = 0x8f, 3
	default:
		return 1
	}
	n := 1
	for ; n <= need && n < len(b); n++ {
		if b[n] < lo || b[n] > hi {
			break
		}
		lo, hi = 0x80, 0xbf
	}
	return n
}

// Test basic XSS cases.

func TestScriptAttacks(t *testing.T) {
	astAssertSanitizedDoesNotContain(t, "test<script>alert(document.cookie)</script>", "script")
	astAssertSanitizedDoesNotContain(t, "test<script>alert(document.cookie)</script>", "script")

	astAssertSanitizedDoesNotContain(t, "<<<><<script src=http://fake-evil.ru/test.js>", "<script")
	astAssertSanitizedDoesNotContain(t, "<<<><<script src=http://fake-evil.ru/test.js>", "<script")

	astAssertSanitizedDoesNotContain(t, "<script<script src=http://fake-evil.ru/test.js>>", "<script")
	astAssertSanitizedDoesNotContain(t, "<script<script src=http://fake-evil.ru/test.js>>", "<script")

	astAssertSanitizedDoesNotContain(t, "<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script")
	astAssertSanitizedDoesNotContain(t, "<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script")

	astAssertSanitizedDoesNotContain(t, "<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>", "onload")
	astAssertSanitizedDoesNotContain(t, "<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>", "onload")

	astAssertSanitizedDoesNotContain(t, "<BODY ONLOAD=alert('XSS')>", "alert")
	astAssertSanitizedDoesNotContain(t, "<BODY ONLOAD=alert('XSS')>", "alert")

	astAssertSanitizedDoesNotContain(t, "<iframe src=http://ha.ckers.org/scriptlet.html <", "<iframe")
	astAssertSanitizedDoesNotContain(t, "<iframe src=http://ha.ckers.org/scriptlet.html <", "<iframe")

	astAssertSanitizedDoesNotContain(t, "<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">", "src")
	astAssertSanitizedDoesNotContain(t, "<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">", "src")

	astAssertSanitizedDoesNotContain(t, "<a onblur=\"alert(secret)\" href=\"http://www.google.com\">Google</a>", "alert")
	astAssertSanitizedDoesNotContain(t, "<a onblur=\"alert(secret)\" href=\"http://www.google.com\">Google</a>", "alert")
}

func TestImgAttacks(t *testing.T) {
	astAssertSanitizedDoesContain(t, "<img src=\"http://www.myspace.com/img.gif\"/>", "<img")
	astAssertSanitizedDoesContain(t, "<img src=\"http://www.myspace.com/img.gif\"/>", "<img")

	astAssertSanitizedDoesNotContain(t, "<img src=javascript:alert(document.cookie)>", "<img")

	astAssertSanitizedDoesNotContain(t, "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>", "<img")
	astAssertSanitizedDoesNotContain(t, "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>", "<img")

	astAssertSanitizedDoesNotContain(t, "<IMG SRC='&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041'>", "src")
	astAssertSanitizedDoesNotContain(t, "<IMG SRC='&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041'>", "src")

	astAssertSanitizedDoesNotContain(t, "<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">", "alert")
	astAssertSanitizedDoesNotContain(t, "<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">", "alert")

	s := "<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>"
	if astSanitize(t, s) != "" {
		astAssertSanitizedDoesContain(t, s, "&amp;")
	}
	s = "<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>"
	if astSanitize(t, s) != "" {
		astAssertSanitizedDoesContain(t, s, "&amp;")
	}

	astSanitize(t, "<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>")
	astSanitize(t, "<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>")

	astAssertSanitizedDoesNotContain(t, "<IMG SRC=\"javascript:alert('XSS')\"", "javascript")
	astAssertSanitizedDoesNotContain(t, "<IMG SRC=\"javascript:alert('XSS')\"", "javascript")

	astAssertSanitizedDoesNotContain(t, "<IMG LOWSRC=\"javascript:alert('XSS')\">", "javascript")
	astAssertSanitizedDoesNotContain(t, "<IMG LOWSRC=\"javascript:alert('XSS')\">", "javascript")

	astAssertSanitizedDoesNotContain(t, "<BGSOUND SRC=\"javascript:alert('XSS');\">", "javascript")
	astAssertSanitizedDoesNotContain(t, "<BGSOUND SRC=\"javascript:alert('XSS');\">", "javascript")
}

func TestHrefAttacks(t *testing.T) {
	astAssertSanitizedDoesNotContain(t, "<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">", "href")
	astAssertSanitizedDoesNotContain(t, "<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">", "href")

	astAssertSanitizedDoesNotContain(t, "<LINK REL=\"stylesheet\" HREF=\"http://ha.ckers.org/xss.css\">", "href")
	astAssertSanitizedDoesNotContain(t, "<LINK REL=\"stylesheet\" HREF=\"http://ha.ckers.org/xss.css\">", "href")

	astAssertSanitizedDoesNotContain(t, "<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>", "ha.ckers.org")
	astAssertSanitizedDoesNotContain(t, "<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>", "ha.ckers.org")

	astAssertSanitizedDoesNotContain(t, "<STYLE>BODY{-moz-binding:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}</STYLE>", "ha.ckers.org")
	astAssertSanitizedDoesNotContain(t, "<STYLE>BODY{-moz-binding:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}</STYLE>", "ha.ckers.org")

	astAssertSanitizedDoesNotContain(t, "<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\");}</STYLE><UL><LI>XSS", "javascript")
	astAssertSanitizedDoesNotContain(t, "<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\");}</STYLE><UL><LI>XSS", "javascript")

	astAssertSanitizedDoesNotContain(t, "<IMG SRC='vbscript:msgbox(\"XSS\")'>", "vbscript")
	astAssertSanitizedDoesNotContain(t, "<IMG SRC='vbscript:msgbox(\"XSS\")'>", "vbscript")

	astAssertSanitizedDoesNotContain(t, "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS');\">", "<meta")
	astAssertSanitizedDoesNotContain(t, "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS');\">", "<meta")

	astAssertSanitizedDoesNotContain(t, "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">", "<meta")
	astAssertSanitizedDoesNotContain(t, "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">", "<meta")

	astAssertSanitizedDoesNotContain(t, "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">", "<meta")
	astAssertSanitizedDoesNotContain(t, "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">", "<meta")

	astAssertSanitizedDoesNotContain(t, "<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>", "iframe")
	astAssertSanitizedDoesNotContain(t, "<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>", "iframe")

	astAssertSanitizedDoesNotContain(t, "<FRAMESET><FRAME SRC=\"javascript:alert('XSS');\"></FRAMESET>", "javascript")
	astAssertSanitizedDoesNotContain(t, "<FRAMESET><FRAME SRC=\"javascript:alert('XSS');\"></FRAMESET>", "javascript")

	astAssertSanitizedDoesNotContain(t, "<TABLE BACKGROUND=\"javascript:alert('XSS')\">", "background")
	astAssertSanitizedDoesNotContain(t, "<TABLE BACKGROUND=\"javascript:alert('XSS')\">", "background")

	astAssertSanitizedDoesNotContain(t, "<TABLE><TD BACKGROUND=\"javascript:alert('XSS')\">", "background")
	astAssertSanitizedDoesNotContain(t, "<TABLE><TD BACKGROUND=\"javascript:alert('XSS')\">", "background")

	astAssertSanitizedDoesNotContain(t, "<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">", "javascript")
	astAssertSanitizedDoesNotContain(t, "<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">", "javascript")

	astAssertSanitizedDoesNotContain(t, "<DIV STYLE=\"width: expression(alert('XSS'));\">", "alert")
	astAssertSanitizedDoesNotContain(t, "<DIV STYLE=\"width: expression(alert('XSS'));\">", "alert")

	astAssertSanitizedDoesNotContain(t, "<IMG STYLE=\"xss:expr/*XSS*/ession(alert('XSS'))\">", "alert")
	astAssertSanitizedDoesNotContain(t, "<IMG STYLE=\"xss:expr/*XSS*/ession(alert('XSS'))\">", "alert")

	astAssertSanitizedDoesNotContain(t, "<STYLE>@im\\port'\\ja\\vasc\\ript:alert(\"XSS\")';</STYLE>", "ript:alert")
	astAssertSanitizedDoesNotContain(t, "<STYLE>@im\\port'\\ja\\vasc\\ript:alert(\"XSS\")';</STYLE>", "ript:alert")

	astAssertSanitizedDoesNotContain(t, "<BASE HREF=\"javascript:alert('XSS');//\">", "javascript")
	astAssertSanitizedDoesNotContain(t, "<BASE HREF=\"javascript:alert('XSS');//\">", "javascript")

	astAssertSanitizedDoesNotContain(t, "<BaSe hReF=\"http://arbitrary.com/\">", "<base")
	astAssertSanitizedDoesNotContain(t, "<BaSe hReF=\"http://arbitrary.com/\">", "<base")

	astAssertSanitizedDoesNotContain(t, "<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://ha.ckers.org/scriptlet.html\"></OBJECT>", "<object")
	astAssertSanitizedDoesNotContain(t, "<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://ha.ckers.org/scriptlet.html\"></OBJECT>", "<object")

	astAssertSanitizedDoesNotContain(t, "<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>", "javascript")

	astAssertSanitizedDoesNotContain(t, "<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>", "javascript")

	astAssertSanitizedDoesNotContain(t, "<EMBED SRC=\"http://ha.ckers.org/xss.swf\" AllowScriptAccess=\"always\"></EMBED>", "<embed")
	astAssertSanitizedDoesNotContain(t, "<EMBED SRC=\"http://ha.ckers.org/xss.swf\" AllowScriptAccess=\"always\"></EMBED>", "<embed")

	astAssertSanitizedDoesNotContain(t, "<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>", "<embed")
	astAssertSanitizedDoesNotContain(t, "<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>", "<embed")

	astAssertSanitizedDoesNotContain(t, "<SCRIPT a=\">\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script")
	astAssertSanitizedDoesNotContain(t, "<SCRIPT a=\">\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script")

	astAssertSanitizedDoesNotContain(t, "<SCRIPT a=\">\" '' SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script")
	astAssertSanitizedDoesNotContain(t, "<SCRIPT a=\">\" '' SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script")

	astAssertSanitizedDoesNotContain(t, "<SCRIPT a=`>` SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script")
	astAssertSanitizedDoesNotContain(t, "<SCRIPT a=`>` SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script")

	astAssertSanitizedDoesNotContain(t, "<SCRIPT a=\">'>\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script")
	astAssertSanitizedDoesNotContain(t, "<SCRIPT a=\">'>\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "<script")

	astAssertSanitizedDoesNotContain(t, "<SCRIPT>document.write(\"<SCRI\");</SCRIPT>PT SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "script")
	astAssertSanitizedDoesNotContain(t, "<SCRIPT>document.write(\"<SCRI\");</SCRIPT>PT SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", "script")

	astAssertSanitizedDoesNotContain(t, "<SCRIPT SRC=http://ha.ckers.org/xss.js", "<script")
	astAssertSanitizedDoesNotContain(t, "<SCRIPT SRC=http://ha.ckers.org/xss.js", "<script")

	astAssertSanitizedDoesNotContain(t, "<div/style=&#92&#45&#92&#109&#111&#92&#122&#92&#45&#98&#92&#105&#92&#110&#100&#92&#105&#110&#92&#103:&#92&#117&#114&#108&#40&#47&#47&#98&#117&#115&#105&#110&#101&#115&#115&#92&#105&#92&#110&#102&#111&#46&#99&#111&#46&#117&#107&#92&#47&#108&#97&#98&#115&#92&#47&#120&#98&#108&#92&#47&#120&#98&#108&#92&#46&#120&#109&#108&#92&#35&#120&#115&#115&#41&>", "style")
	astAssertSanitizedDoesNotContain(t, "<div/style=&#92&#45&#92&#109&#111&#92&#122&#92&#45&#98&#92&#105&#92&#110&#100&#92&#105&#110&#92&#103:&#92&#117&#114&#108&#40&#47&#47&#98&#117&#115&#105&#110&#101&#115&#115&#92&#105&#92&#110&#102&#111&#46&#99&#111&#46&#117&#107&#92&#47&#108&#97&#98&#115&#92&#47&#120&#98&#108&#92&#47&#120&#98&#108&#92&#46&#120&#109&#108&#92&#35&#120&#115&#115&#41&>", "style")

	astAssertSanitizedDoesNotContain(t, "<a href='aim: &c:\\windows\\system32\\calc.exe' ini='C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\pwnd.bat'>", "aim.exe")
	astAssertSanitizedDoesNotContain(t, "<a href='aim: &c:\\windows\\system32\\calc.exe' ini='C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\pwnd.bat'>", "aim.exe")

	astAssertSanitizedDoesNotContain(t, "<!--\n<A href=\n- --><a href=javascript:alert:document.domain>test-->", "javascript")
	astAssertSanitizedDoesNotContain(t, "<!--\n<A href=\n- --><a href=javascript:alert:document.domain>test-->", "javascript")

	astAssertSanitizedDoesNotContain(t, "<a></a style=\"\"xx:expr/**/ession(document.appendChild(document.createElement('script')).src='http://h4k.in/i.js')\">", "document")
	astAssertSanitizedDoesNotContain(t, "<a></a style=\"\"xx:expr/**/ession(document.appendChild(document.createElement('script')).src='http://h4k.in/i.js')\">", "document")
}

// Test CSS protections.

func TestCssAttacks(t *testing.T) {

	astAssertSanitizedDoesNotContain(t, "<div style=\"position:absolute\">", "position")
	astAssertSanitizedDoesNotContain(t, "<div style=\"position:absolute\">", "position")

	astAssertSanitizedDoesNotContain(t, "<style>b { position:absolute }</style>", "position")
	astAssertSanitizedDoesNotContain(t, "<style>b { position:absolute }</style>", "position")

	astAssertSanitizedDoesNotContain(t, "<div style=\"z-index:25\">test</div>", "z-index")
	astAssertSanitizedDoesNotContain(t, "<div style=\"z-index:25\">test</div>", "z-index")

	astAssertSanitizedDoesNotContain(t, "<style>z-index:25</style>", "z-index")
	astAssertSanitizedDoesNotContain(t, "<style>z-index:25</style>", "z-index")
}

// TestIllegalXML tests a bunch of strings that have tweaked the XML parsing
// capabilities of NekoHTML.
func TestIllegalXML(t *testing.T) {
	for _, badXML := range astBase64BadXMLStrings {
		decoded, err := base64.StdEncoding.DecodeString(badXML)
		if err != nil {
			t.Fatalf("decoding %q: %v", badXML, err)
		}
		testStr := astDecodeUTF8(decoded)
		astSanitize(t, testStr)
		astSanitize(t, testStr)
	}

	// These fail in AntiSamy due to a bug in NekoHTML
	hstAssertEqual(t,
		"<a href=\"http://www.test.com\" rel=\"nofollow\"></a>",
		astSanitize(t, "<a . href=\"http://www.test.com\">"))
	hstAssertEqual(t,
		"<a href=\"http://www.test.com\" rel=\"nofollow\"></a>",
		astSanitize(t, "<a - href=\"http://www.test.com\">"))

	// Sanitizing must complete.
	astSanitize(t, "<style>")
}

// astSpace is whitespace including the vertical tab, which Go's \s lacks.
const astSpace = `[ \t\n\x0B\f\r]`

// astNotLineTerminator matches any character but a line terminator.
const astNotLineTerminator = `[^\n\r\x{85}\x{2028}\x{2029}]`

var (
	// astEmptyStrong matches a whole input that contains an empty <strong/>,
	// across lines.
	astEmptyStrong = regexp.MustCompile(`(?s)^.*<strong(` + astSpace + `*)/>.*$`)
	// astEmptyB, astEmptyI and astEmptyHr match a whole single-line input
	// that contains an empty <b/>, <i/> or <hr/>.
	astEmptyB  = astWholeLinePattern("b")
	astEmptyI  = astWholeLinePattern("i")
	astEmptyHr = astWholeLinePattern("hr")
)

// astWholeLinePattern matches a whole single-line input that contains an
// empty <name/>, with optional whitespace before the slash.
func astWholeLinePattern(name string) *regexp.Regexp {
	return regexp.MustCompile(`^` + astNotLineTerminator + `*<` + name + `(` +
		astSpace + `*)/>` + astNotLineTerminator + `*$`)
}

func TestPreviousBugs(t *testing.T) {

	/*
	 * issues 12 (and 36, which was similar). empty tags cause display
	 * problems/"formjacking"
	 */

	{
		s1 := astSanitize(t, "<br ><strong></strong><a>hello world</a><b /><i/><hr>")
		s2 := astSanitize(t, "<br ><strong></strong><a>hello world</a><b /><i/><hr>")

		hstAssertFalse(t, astEmptyStrong.MatchString(s1))

		hstAssertFalse(t, astEmptyB.MatchString(s1))
		hstAssertFalse(t, astEmptyB.MatchString(s2))

		hstAssertFalse(t, astEmptyI.MatchString(s1))
		hstAssertFalse(t, astEmptyI.MatchString(s2))

		hstAssertFalse(t, astEmptyHr.MatchString(s1))
		hstAssertFalse(t, astEmptyHr.MatchString(s2))
	}

	/* issue #20 */
	astAssertSanitizedDoesNotContain(t, "<b><i>Some Text</b></i>", "<i />")

	astAssertSanitizedDoesNotContain(t, "<b><i>Some Text</b></i>", "<i />")

	/* issue #25 */
	hstAssertEqual(t,
		"<div>Test</div>", astSanitize(t, "<div style=\"margin: -5em\">Test</div>"))

	/* issue #28 */
	astAssertSanitizedDoesContain(t,
		"<div style=\"font-family: Geneva, Arial, courier new, sans-serif\">Test</div>",
		"font-family:&#39;geneva&#39; , &#39;arial&#39; , &#39;courier new&#39; , sans-serif")

	/* issue #29 - missing quotes around properties with spaces */
	if astRunKnownFailures {
		s := "<style type=\"text/css\"><![CDATA[P {\n     font-family: \"Arial Unicode MS\";\n}\n]]></style>"
		hstAssertEqual(t, s, astSanitize(t, s))
	}

	/* issue #30 */
	if astRunKnownFailures {
		s := "<style type=\"text/css\"><![CDATA[P { margin-bottom: 0.08in; } ]]></style>"

		astSanitize(t, s)

		// followup - does the patch fix multiline CSS?
		s2 := "<style type=\"text/css\"><![CDATA[\r\nP {\r\n margin-bottom: 0.08in;\r\n}\r\n]]></style>"
		hstAssertEqual(t, "<style type=\"text/css\"><![CDATA[P {\n\tmargin-bottom: 0.08in;\n}\n]]></style>", astSanitize(t, s2))

		// next followup - does non-CDATA parsing still work?

		s3 := "<style>P {\n\tmargin-bottom: 0.08in;\n}\n"
		hstAssertEqual(t, "<style>P {\n\tmargin-bottom: 0.08in;\n}\n</style>\n", astSanitize(t, s3))

		// for other
		// tests
	}

	/* issue #32 - nekos problem */
	{
		s := "<SCRIPT =\">\" SRC=\"\"></SCRIPT>"
		astSanitize(t, s)
		astSanitize(t, s)
	}

	/* issue #37 - OOM */
	{
		dirty := "<a onblur=\"try {parent.deselectBloggerImageGracefully();}" + "catch(e) {}\"" +
			"href=\"http://www.charityadvantage.com/ChildrensmuseumEaston/images/BookswithBill.jpg\"><img" + "style=\"FLOAT: right; MARGIN: 0px 0px 10px 10px; WIDTH: 150px; CURSOR:" +
			"hand; HEIGHT: 100px\" alt=\"\"" + "src=\"http://www.charityadvantage.com/ChildrensmuseumEaston/images/BookswithBill.jpg\"" +
			"border=\"0\" /></a><br />Poor Bill, couldn't make it to the Museum's <span" + "class=\"blsp-spelling-corrected\" id=\"SPELLING_ERROR_0\">story time</span>" +
			"today, he was so busy shoveling! Well, we sure missed you Bill! So since" + "ou were busy moving snow we read books about snow. We found a clue in one" +
			"book which revealed a snowplow at the end of the story - we wish it had" + "driven to your driveway Bill. We also read a story which shared fourteen" +
			"<em>Names For Snow. </em>We'll catch up with you next week....wonder which" + "hat Bill will wear?<br />Jane"

		// Sanitizing must complete.
		astSanitize(t, dirty)
	}

	/* issue #38 - color problem/color combinations */
	{
		s := "<font color=\"#fff\">Test</font>"
		expected := "<font color=\"#fff\">Test</font>"
		hstAssertEqual(t, expected, astSanitize(t, s))
		hstAssertEqual(t, expected, astSanitize(t, s))

		s = "<div style=\"color: #fff\">Test 3 letter code</div>"
		expected = "<div style=\"color:#fff\">Test 3 letter code</div>"
		hstAssertEqual(t, expected, astSanitize(t, s))
		hstAssertEqual(t, expected, astSanitize(t, s))

		s = "<font color=\"red\">Test</font>"
		expected = "<font color=\"red\">Test</font>"
		hstAssertEqual(t, expected, astSanitize(t, s))
		hstAssertEqual(t, expected, astSanitize(t, s))

		s = "<font color=\"neonpink\">Test</font>"
		expected = s
		hstAssertEqual(t, expected, astSanitize(t, s))
		hstAssertEqual(t, expected, astSanitize(t, s))

		if astRunKnownFailures {
			s = "<font color=\"#0000\">Test</font>"
			expected = "<font>Test</font>"
			hstAssertEqual(t, expected, astSanitize(t, s))
			hstAssertEqual(t, expected, astSanitize(t, s))
		}

		if astRunKnownFailures {
			s = "<div style=\"color: #0000\">Test</div>"
			expected = "<div>Test</div>"
			hstAssertEqual(t, expected, astSanitize(t, s))
			hstAssertEqual(t, expected, astSanitize(t, s))
		}

		s = "<font color=\"#000000\">Test</font>"
		expected = "<font color=\"#000000\">Test</font>"
		hstAssertEqual(t, expected, astSanitize(t, s))
		hstAssertEqual(t, expected, astSanitize(t, s))

		s = "<div style=\"color: #000000\">Test</div>"
		expected = "<div style=\"color:#000000\">Test</div>"
		hstAssertEqual(t, expected, astSanitize(t, s))
		hstAssertEqual(t, expected, astSanitize(t, s))

		s = "<b><u>foo<style><script>alert(1)</script></style>@import 'x';</u>bar"
		astSanitize(t, s)
	}

	/* issue #40 - handling <style> media attributes right */

	if astRunKnownFailures {
		astAssertSanitizedDoesContain(t, "<style media=\"print, projection, screen\"> P { margin: 1em; }</style>", "print, projection, screen")
	}

	/* issue #41 - comment handling */

	{
		hstAssertEqual(t, "text ", astSanitize(t, "text <!-- comment -->"))
		hstAssertEqual(t, "text ", astSanitize(t, "text <!-- comment -->"))

		hstAssertEqual(t, "<div>text </div>", astSanitize(t, "<div>text <!-- comment --></div>"))
		hstAssertEqual(t, "<div>text </div>", astSanitize(t, "<div>text <!-- comment --></div>"))

		hstAssertEqual(t, "<div>text </div>", astSanitize(t, "<div>text <!--[if IE]> comment <[endif]--></div>"))
		hstAssertEqual(t, "<div>text </div>", astSanitize(t, "<div>text <!--[if IE]> comment <[endif]--></div>"))

		/*
		 * Check to see how nested conditional comments are handled. This is
		 * not very clean but the main goal is to avoid any tags. Not sure
		 * on encodings allowed in comments.
		 */
		input := "<div>text <!--[if IE]> <!--[if gte 6]> comment <[endif]--><[endif]--></div>"
		expected := "<div>text &lt;[endif]--&gt;</div>"
		output := astSanitize(t, input)
		hstAssertEqual(t, expected, output)

		input = "<div>text <!--[if IE]> <!--[if gte 6]> comment <[endif]--><[endif]--></div>"
		expected = "<div>text &lt;[endif]--&gt;</div>"
		output = astSanitize(t, input)
		hstAssertEqual(t, expected, output)

		/*
		 * Regular comment nested inside conditional comment. Test makes
		 * sure
		 */
		hstAssertEqual(t, "<div>text  comment &lt;[endif]--&gt;</div>", astSanitize(t, "<div>text <!--[if IE]> <!-- IE specific --> comment <[endif]--></div>"))

		/*
		 * These play with whitespace and have invalid comment syntax.
		 */
		hstAssertEqual(t, "<div>text </div>", astSanitize(t, "<div>text <!-- [ if lte 6 ]>\ncomment <[ endif\n]--></div>"))
		hstAssertEqual(t, "<div>text  comment </div>", astSanitize(t, "<div>text <![if !IE]> comment <![endif]></div>"))
		hstAssertEqual(t, "<div>text  comment </div>", astSanitize(t, "<div>text <![ if !IE]> comment <![endif]></div>"))

		attack := "[if lte 8]<script>"
		spacer := "<![if IE]>"

		var sb strings.Builder

		sb.WriteString("<div>text<!")

		for i := 0; i < len(attack); i++ {
			sb.WriteByte(attack[i])
			sb.WriteString(spacer)
		}

		sb.WriteString("<![endif]>")

		s := sb.String()

		astAssertSanitizedDoesNotContain(t, s, "<script")
		astAssertSanitizedDoesNotContain(t, s, "<script")
	}

	/*
	 * issue #44 - childless nodes of non-allowed elements won't cause an error
	 */
	{
		s := "<iframe src='http://foo.com/'></iframe>" + "<script src=''></script>" + "<link href='/foo.css'>"
		hstAssertEqual(t, "", astSanitize(t, s), s)
	}

	/* issue #51 - offsite urls with () are found to be invalid */
	astAssertSanitizedDoesNotContain(t,
		"<a href='http://subdomain.domain/(S(ke0lpq54bw0fvp53a10e1a45))/MyPage.aspx'>test</a>", "(")

	/* issue #56 - unnecessary spaces */
	{
		s := "<SPAN style='font-weight: bold;'>Hello World!</SPAN>"
		hstAssertEqual(t,
			"<span style=\"font-weight:bold\">Hello World!</span>",
			astSanitize(t, s))
	}

	/* issue #58 - input not in list of allowed-to-be-empty tags */
	{
		s := "tgdan <input/> g  h"
		hstAssertEqual(t, "tgdan  g  h", astSanitize(t, s))
	}

	/* issue #61 - input has newline appended if ends with an accepted tag */
	{
		dirtyInput := "blah <b>blah</b>."
		s := astSanitize(t, dirtyInput)
		hstAssertEqual(t, dirtyInput, s)
	}

	/* issue #69 - char attribute should allow single char or entity ref */

	{
		s := "<td char='.'>test</td>"
		astAssertSanitizedDoesContain(t, s, "char")
		astAssertSanitizedDoesContain(t, s, "char")

		s = "<td char='..'>test</td>"
		astAssertSanitizedDoesNotContain(t, s, "char")
		astAssertSanitizedDoesNotContain(t, s, "char")

		s = "<td char='&quot;'>test</td>"
		astAssertSanitizedDoesContain(t, s, "char")
		astAssertSanitizedDoesContain(t, s, "char")

		s = "<td char='&quot;a'>test</td>"
		astAssertSanitizedDoesNotContain(t, s, "char")
		astAssertSanitizedDoesNotContain(t, s, "char")

		s = "<td char='&quot;&amp;'>test</td>"
		astAssertSanitizedDoesNotContain(t, s, "char")
		astAssertSanitizedDoesNotContain(t, s, "char")
	}

	/* privately disclosed issue - cdata bypass */
	{
		malInput := "<![CDATA[]><script>alert(1)</script>]]>"

		astAssertSanitizedDoesNotContain(t, malInput, "<script")
	}

	/* this test is for confirming literal-lists work as
	 * advertised. it turned out to be an invalid / non-
	 * reproducible bug report but the test seemed useful
	 * enough to keep.
	 */
	{
		malInput := "hello<p align='invalid'>world</p>"
		astAssertSanitizedDoesNotContain(t, malInput, "invalid")

		goodInput := "hello<p align='left'>world</p>"
		if astRunKnownFailures {
			astAssertSanitizedDoesContain(t, goodInput, "left")
		}
	}
}

// TestNofollowAnchors tests cases dealing with nofollowAnchors directive.
// Assumes anchor tags have an action set to "validate" (may be implicit) in
// the policy file.
func TestNofollowAnchors(t *testing.T) {
	// adds when not present
	astAssertSanitized(t, "<a href=\"blah\">link</a>", "<a href=\"blah\" rel=\"nofollow\">link</a>")

	// adds properly even with bad attr
	astAssertSanitized(t, "<a href=\"blah\" bad=\"true\">link</a>", "<a href=\"blah\" rel=\"nofollow\">link</a>")

	// rel with bad value gets corrected
	astAssertSanitized(t, "<a href=\"blah\" rel=\"blh\">link</a>", "<a href=\"blah\" rel=\"nofollow\">link</a>")

	// correct attribute doesnt get messed with
	astAssertSanitized(t, "<a href=\"blah\" rel=\"nofollow\">link</a>", "<a href=\"blah\" rel=\"nofollow\">link</a>")

	// if two correct attributes, only one remaining after scan
	astAssertSanitized(t, "<a href=\"blah\" rel=\"nofollow\" rel=\"nofollow\">link</a>", "<a href=\"blah\" rel=\"nofollow\">link</a>")

	// test if value is off - does it add?
	astAssertSanitizedDoesNotContain(t, "a href=\"blah\">link</a>", "nofollow")
}

func TestValidateParamAsEmbed(t *testing.T) {
	// let's start with a YouTube embed
	input := "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&hl=en&fs=1&\"></param><param name=\"allowFullScreen\" value=\"true\"></param><param name=\"allowscriptaccess\" value=\"always\"></param><embed src=\"http://www.youtube.com/v/IyAyd4WnvhU&hl=en&fs=1&\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\"></embed></object>"
	expectedOutput := "<object height=\"340\" width=\"560\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" /><param name=\"allowFullScreen\" value=\"true\" /><param name=\"allowscriptaccess\" value=\"always\" /><embed allowfullscreen=\"true\" allowscriptaccess=\"always\" height=\"340\" src=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" type=\"application/x-shockwave-flash\" width=\"560\" /></object>"
	if astRunKnownFailures {
		astAssertSanitizedDoesContain(t, input, expectedOutput)
	} else {
		astAssertSanitized(t, input, "")
	}

	saxExpectedOutput := "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\"><param name=\"allowFullScreen\" value=\"true\"><param name=\"allowscriptaccess\" value=\"always\"><embed src=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\"></embed></object>"
	if astRunKnownFailures {
		astAssertSanitizedDoesContain(t, input, saxExpectedOutput)
	} else {
		astAssertSanitized(t, input, "")
	}

	// now what if someone sticks malicious URL in the value of the
	// value attribute in the param tag? remove that param tag
	input = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://supermaliciouscode.com/badstuff.swf\"></param><param name=\"allowFullScreen\" value=\"true\"></param><param name=\"allowscriptaccess\" value=\"always\"></param><embed src=\"http://www.youtube.com/v/IyAyd4WnvhU&hl=en&fs=1&\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\"></embed></object>"
	expectedOutput = "<object height=\"340\" width=\"560\"><param name=\"allowFullScreen\" value=\"true\" /><param name=\"allowscriptaccess\" value=\"always\" /><embed allowfullscreen=\"true\" allowscriptaccess=\"always\" height=\"340\" src=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" type=\"application/x-shockwave-flash\" width=\"560\" /></object>"
	saxExpectedOutput = "<object width=\"560\" height=\"340\"><param name=\"allowFullScreen\" value=\"true\"><param name=\"allowscriptaccess\" value=\"always\"><embed src=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\"></embed></object>"
	if astRunKnownFailures {
		astAssertSanitizedDoesContain(t, input, expectedOutput)
	} else {
		astAssertSanitized(t, input, "")
	}

	if astRunKnownFailures {
		hstAssertTrue(t, astSanitize(t, input) == saxExpectedOutput)
	} else {
		astAssertSanitized(t, input, "")
	}

	// now what if someone sticks malicious URL in the value of the src
	// attribute in the embed tag? remove that embed tag
	input = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&hl=en&fs=1&\"></param><param name=\"allowFullScreen\" value=\"true\"></param><param name=\"allowscriptaccess\" value=\"always\"></param><embed src=\"http://hereswhereikeepbadcode.com/ohnoscary.swf\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\"></embed></object>"
	expectedOutput = "<object height=\"340\" width=\"560\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" /><param name=\"allowFullScreen\" value=\"true\" /><param name=\"allowscriptaccess\" value=\"always\" /></object>"
	saxExpectedOutput = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\"><param name=\"allowFullScreen\" value=\"true\"><param name=\"allowscriptaccess\" value=\"always\"></object>"

	if astRunKnownFailures {
		astAssertSanitizedDoesContain(t, input, expectedOutput)
	} else {
		astAssertSanitized(t, input, "")
	}

	if astRunKnownFailures {
		astAssertSanitizedDoesContain(t, input, saxExpectedOutput)
	} else {
		astAssertSanitized(t, input, "")
	}
}

// astAssertSanitizedDoesNotContain asserts that the sanitized html does not
// contain dangerousContent, ignoring the case of ASCII letters.
func astAssertSanitizedDoesNotContain(t testing.TB, html, dangerousContent string) {
	t.Helper()
	sanitized := astSanitize(t, html)
	index := strings.Index(
		stringsToLowerCase(sanitized), stringsToLowerCase(dangerousContent))
	hstAssertEqual(t,
		-1,
		index, "`"+sanitized+"` from `"+html+"` contains `"+
			dangerousContent+"`")
}

// astAssertSanitizedDoesContain asserts that the sanitized html contains
// dangerousContent, ignoring the case of ASCII letters.
func astAssertSanitizedDoesContain(t testing.TB, html, dangerousContent string) {
	t.Helper()
	sanitized := astSanitize(t, html)
	index := strings.Index(
		stringsToLowerCase(sanitized), stringsToLowerCase(dangerousContent))
	hstAssertTrue(t,
		index >= 0,
		"`"+sanitized+"` from `"+html+"` does not contain `"+
			dangerousContent+"`")
}

// astAssertSanitized asserts that html sanitizes to sanitized.
func astAssertSanitized(t testing.TB, html, sanitized string) {
	t.Helper()
	hstAssertEqual(t, sanitized, astSanitize(t, html))
}
