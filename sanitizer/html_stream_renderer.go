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

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/HtmlStreamRenderer.java.

package sanitizer

import (
	"io"
	"strings"
)

// HTMLStreamRenderer writes valid, normalized HTML to an output, given a
// series of HTML events.
//
// The output will have well-defined tag boundaries, but there may be orphaned
// or missing close and open tags.  The result of two renderers can always be
// concatenated to produce a larger snippet of HTML, but if the first was
// called with OpenTag("plaintext", ...), then any tags in the second will not
// be interpreted as tags in the concatenated version.
//
// An HTMLStreamRenderer is not safe for concurrent use.
type HTMLStreamRenderer struct {
	output         io.Writer
	ioExHandler    Handler[error]
	badHTMLHandler Handler[string]
	// dropListener is told about dropped literal content; nil while nobody
	// is listening.
	dropListener     htmlStreamRendererDropListener
	lastTagOpened    string
	pendingUnescaped *wtf8Builder
	escapingMode     HTMLTextEscapingMode
	open             bool
	// foreignContentDepth is the count of
	// htmlStreamRendererForeignContentRootElementNames opened and not
	// subsequently closed.
	foreignContentDepth int
	// decodeTextBeforeEscaping is true when the current element is one whose
	// content the HTML lexer treats as raw text, so its text arrives with
	// character references undecoded, but it is inside foreign content where
	// browsers parse that content as markup.  Such text must be decoded
	// before it is escaped, otherwise character references would be encoded
	// twice.
	decodeTextBeforeEscaping bool
	// writeErr is the first error output returned during the current event.
	writeErr error
}

// NewHTMLStreamRenderer returns a renderer that streams HTML to output.
//
// ioExHandler is called with any error returned by output; the rest of the
// event that caused it is not written.  badHTMLHandler receives alerts when
// HTML cannot be rendered because there is no valid HTML tree that results
// from that series of calls.  E.g. it is not possible to create an HTML
// <style> element whose textual content is "</style>".  What the renderer
// leaves out on such an alert also reaches an HTMLChangeListener when the
// renderer is behind an HTMLChangeReporter, as it is in
// PolicyFactory.Sanitize.  Either handler may be nil to ignore the alerts.
//
// If output implements io.Closer, Close closes the document and then
// output.  If output has a Flush() error method, CloseDocument flushes it.
func NewHTMLStreamRenderer(
	output io.Writer, ioExHandler Handler[error], badHTMLHandler Handler[string],
) *HTMLStreamRenderer {
	return &HTMLStreamRenderer{
		output:         output,
		ioExHandler:    ioExHandler,
		badHTMLHandler: badHTMLHandler,
		escapingMode:   HTMLTextEscapingModePcdata,
	}
}

// NewHTMLStreamRendererToBuilder returns a renderer that streams HTML to
// output, which cannot fail.  badHTMLHandler is as for
// NewHTMLStreamRenderer.
func NewHTMLStreamRendererToBuilder(
	output *strings.Builder, badHTMLHandler Handler[string],
) *HTMLStreamRenderer {
	// Propagate since a strings.Builder does not return errors.
	return NewHTMLStreamRenderer(output, Propagate, badHTMLHandler)
}

// error is called when the series of calls make no sense.
//
// message is for human consumption, and identifier is an HTML identifier
// associated with the message.
func (r *HTMLStreamRenderer) error(message, identifier string) {
	if r.badHTMLHandler != nil {
		r.badHTMLHandler(message + " : " + identifier)
	}
}

// htmlStreamRendererDroppedTextListener carries literal content discarded by
// the policy or renderer to an HTMLChangeReporter, which reports the loss to
// its listener.
type htmlStreamRendererDroppedTextListener interface {
	// droppedText reports that text, the content of an element named
	// elementName, was dropped.
	droppedText(elementName, text string)
}

// htmlStreamRendererDropListener carries the renderer's other drops to an
// HTMLChangeReporter as well: a start tag it did not write, and an attribute
// it left off one it did.  Each also goes to the bad-HTML handler as a
// message, which is all there was before and which PolicyFactory.Sanitize
// wires to nobody, so without this a listener heard nothing of them.
type htmlStreamRendererDropListener interface {
	htmlStreamRendererDroppedTextListener

	// droppedTag reports a start tag the renderer did not write, because the
	// element's name is not one HTML allows or because it arrived inside
	// literal content that cannot hold a tag.  The matching end tag is
	// refused for the same reason when it comes, and is not reported: it is
	// the same loss.  elementName is the element's name as the renderer
	// received it.
	droppedTag(elementName string)

	// droppedAttribute reports an attribute left off a start tag the
	// renderer wrote, because its name is not one HTML allows.  elementName
	// is the element the tag opened, and name and value are the attribute's
	// as the renderer received them.
	droppedAttribute(elementName, name, value string)
}

// reportDropsTo sends what the renderer drops to listener, or to nobody if
// it is nil, until the next OpenDocument, which starts a document with nobody
// listening.
func (r *HTMLStreamRenderer) reportDropsTo(listener htmlStreamRendererDropListener) {
	r.dropListener = listener
}

// OpenDocument starts a document.  It panics if a document is already open.
func (r *HTMLStreamRenderer) OpenDocument() {
	if r.open {
		panic("HTMLStreamRenderer: document already open")
	}
	r.open = true
	// A listener is for one document; whoever wants this one's drops
	// registers after this, so an earlier document's cannot linger.
	r.dropListener = nil
}

// CloseDocument ends a document, closing any pending raw-text element and
// flushing the output if it has a Flush() error method.  It panics if no
// document is open.
func (r *HTMLStreamRenderer) CloseDocument() {
	if !r.open {
		panic("HTMLStreamRenderer: document not open")
	}
	if r.pendingUnescaped != nil {
		r.CloseTag(r.lastTagOpened)
	}
	r.open = false
	if f, ok := r.output.(interface{ Flush() error }); ok {
		if err := f.Flush(); err != nil {
			r.handleIOError(err)
		}
	}
}

// IsDocumentOpen reports whether OpenDocument has been called and
// CloseDocument has not subsequently been called.
func (r *HTMLStreamRenderer) IsDocumentOpen() bool {
	return r.open
}

// Close closes the document if it is open and then closes the output, if the
// output is an io.Closer.  For any other output it does nothing.
func (r *HTMLStreamRenderer) Close() error {
	closer, ok := r.output.(io.Closer)
	if !ok {
		return nil
	}
	if r.IsDocumentOpen() {
		r.CloseDocument()
	}
	return closer.Close()
}

// OpenTag writes a start tag.  attrs holds alternating attribute names and
// values.
func (r *HTMLStreamRenderer) OpenTag(elementName string, attrs []string) {
	r.writeOpenTag(elementName, attrs)
	r.finishEvent()
}

// write writes s to the output unless an earlier write in this event failed.
func (r *HTMLStreamRenderer) write(strs ...string) {
	if r.writeErr == nil {
		r.writeErr = encodingWriteStrings(r.output, strs...)
	}
}

// finishEvent reports the first write error of the event, if any, to the
// I/O error handler.
func (r *HTMLStreamRenderer) finishEvent() {
	if err := r.writeErr; err != nil {
		r.writeErr = nil
		r.handleIOError(err)
	}
}

// handleIOError passes err to the I/O error handler, if there is one.
func (r *HTMLStreamRenderer) handleIOError(err error) {
	if r.ioExHandler != nil {
		r.ioExHandler(err)
	}
}

func (r *HTMLStreamRenderer) writeOpenTag(unsafeElementName string, attrs []string) {
	if !r.open {
		panic("HTMLStreamRenderer: document not open")
	}
	elementName := htmlStreamRendererSafeName(unsafeElementName)
	if !htmlStreamRendererIsValidHTMLName(elementName) {
		r.error("Invalid element name", elementName)
		if r.dropListener != nil {
			r.dropListener.droppedTag(elementName)
		}
		return
	}
	if r.pendingUnescaped != nil {
		r.error("Tag content cannot appear inside CDATA element", elementName)
		if r.dropListener != nil {
			r.dropListener.droppedTag(elementName)
		}
		return
	}

	if _, ok := htmlStreamRendererForeignContentRootElementNames[elementName]; ok {
		r.foreignContentDepth++
	}

	inForeignContent := r.foreignContentDepth != 0
	tentativeEscapingMode := EscapingModeForTag(elementName)
	// The lexer delivers the content of a raw-text element without decoding
	// character references, but browsers parse that content as markup inside
	// foreign content, so decode it there before re-encoding.
	r.decodeTextBeforeEscaping = inForeignContent &&
		htmlStreamRendererEmitsContentLiterally(elementName, false)
	if !inForeignContent ||
		tentativeEscapingMode == HTMLTextEscapingModePcdata ||
		tentativeEscapingMode == HTMLTextEscapingModeVoid {
		r.escapingMode = tentativeEscapingMode
	} else {
		// Escape special characters but do not allow tags.
		r.escapingMode = HTMLTextEscapingModeRcdata
	}

	if htmlStreamRendererEmitsContentLiterally(elementName, inForeignContent) {
		r.lastTagOpened = elementName
		r.pendingUnescaped = &wtf8Builder{}
	}

	r.write("<", elementName)

	for i := 0; i < len(attrs) && r.writeErr == nil; i += 2 {
		name := attrs[i]
		value := attrs[i+1]
		name = htmlLexerCanonicalAttributeName(name)
		if !htmlStreamRendererIsValidHTMLName(name) {
			r.error("Invalid attr name", name)
			if r.dropListener != nil {
				r.dropListener.droppedAttribute(elementName, name, value)
			}
			continue
		}
		r.write(" ", name, "=\"")
		if r.writeErr == nil {
			r.writeErr = encodingEncodeHTMLAttribOnto(value, r.output)
		}
		if strings.IndexByte(value, '`') != -1 {
			// Apparently, in quirks mode, IE8 does a poor job producing
			// innerHTML values.  Given
			//     <div attr="``foo=bar">
			// we encode &#96; but if JavaScript does:
			//    nodeA.innerHTML = nodeB.innerHTML;
			// and nodeB contains the DIV above, then IE8 will produce
			//     <div attr=``foo=bar>
			// as the value of nodeB.innerHTML and assign it to nodeA.
			// IE8's HTML parser treats `` as a blank attribute value and
			// foo=bar becomes a separate attribute.
			// Adding a space at the end of the attribute prevents this by
			// forcing IE8 to put double quotes around the attribute when
			// computing nodeB.innerHTML.
			r.write(" ")
		}
		r.write("\"")
	}

	// Limit our output to the intersection of valid XML and valid HTML5 when
	// the output contains no special HTML5 elements like <title>, <script>,
	// or <textarea>.
	if IsVoidElement(elementName) {
		r.write(" /")
	}

	r.write(">")
}

// CloseTag writes an end tag.
func (r *HTMLStreamRenderer) CloseTag(elementName string) {
	r.writeCloseTag(htmlStreamRendererSafeName(elementName))
	r.finishEvent()
}

func (r *HTMLStreamRenderer) writeCloseTag(uncanonElementName string) {
	if !r.open {
		panic("HTMLStreamRenderer: document not open")
	}
	elementName := htmlLexerCanonicalElementName(uncanonElementName)
	if !htmlStreamRendererIsValidHTMLName(elementName) {
		r.error("Invalid element name", elementName)
		return
	}

	if r.foreignContentDepth != 0 {
		if _, ok := htmlStreamRendererForeignContentRootElementNames[elementName]; ok {
			r.foreignContentDepth--
		}
	}
	r.decodeTextBeforeEscaping = false

	if r.pendingUnescaped != nil {
		if r.lastTagOpened != elementName {
			r.error("Tag content cannot appear inside CDATA element", elementName)
			return
		}
		cdataContent := encodingStripBannedCodeunits(r.pendingUnescaped.String())
		r.pendingUnescaped = nil
		problemIndex := htmlStreamRendererCheckHTMLCdataCloseable(
			r.lastTagOpened, cdataContent)
		if problemIndex == -1 {
			r.write(cdataContent)
		} else {
			// The excerpt is up to ten UTF-16 code units long.
			excerpt := cdataContent[problemIndex:]
			if n := utf16Length(excerpt); n > 10 {
				excerpt = utf16Substring(excerpt, 0, 10)
			}
			r.error("Invalid CDATA text content", excerpt)
			if r.dropListener != nil {
				r.dropListener.droppedText(elementName, cdataContent)
			}
			// Still output the close tag.
		}
		if elementName == "plaintext" {
			return
		}
	}
	r.write("</", elementName, ">")
}

// Text writes a text node.
func (r *HTMLStreamRenderer) Text(text string) {
	r.writeText(text)
	r.finishEvent()
}

func (r *HTMLStreamRenderer) writeText(text string) {
	if !r.open {
		panic("HTMLStreamRenderer: document not open")
	}
	if r.pendingUnescaped != nil {
		_, _ = r.pendingUnescaped.WriteString(text)
	} else if r.escapingMode == HTMLTextEscapingModeRcdata {
		if r.decodeTextBeforeEscaping {
			text = DecodeHTML(text, false)
		}
		r.writeErr = EncodeRcdataOnto(text, r.output)
	} else {
		r.writeErr = encodingEncodePcdataOnto(text, r.output)
	}
}

// htmlStreamRendererCheckHTMLCdataCloseable returns the byte offset in sb of
// the first construct that would end the raw text element localName early
// or leave an escaping text span open, or -1 if there is none.
func htmlStreamRendererCheckHTMLCdataCloseable(localName, sb string) int {
	// www.w3.org/TR/html51/semantics-scripting.html#restrictions-for-contents-of-script-elements
	// www.w3.org/TR/html5/scripting-1.html#restrictions-for-contents-of-script-elements
	// 4.12.1.3. Restrictions for contents of script elements
	// The textContent of a script element must match the script production
	// in the following ABNF, the character set for which is Unicode. [ABNF]
	//
	// script = outer *( comment-open inner comment-close outer )
	//
	// outer = < any string that doesn’t contain a substring that matches
	//           not-in-outer >
	// not-in-outer = comment-open
	// inner = < any string that doesn’t contain a substring that matches
	//           not-in-inner >
	// not-in-inner = comment-close / script-open
	//
	// comment-open = "<!--"
	// comment-close = "-->"
	// script-open = "<" s c r i p t tag-end

	// We apply the above restrictions to all CDATA (modulo local name).
	innerStart := -1
	for i, n := 0, len(sb); i < n; i++ {
		switch sb[i] {
		case '<':
			if i+3 < n && sb[i+1] == '!' {
				if sb[i+2] == '-' && sb[i+3] == '-' {
					if innerStart >= 0 {
						return i // Nesting
					}
					innerStart = i
				}
			} else { // Look for embedded <script or </script
				start := i + 1
				if start+1 < n && sb[start] == '/' {
					start++
					// The end tag of an element that a browser reads as raw
					// text while the sanitizer treats it as a container would
					// end that element for the browser, wherever this content
					// sits, and hand it whatever follows as markup
					// (CVE-2025-66021).  The policy strips such tags; this
					// catches what reaches the renderer by any other route.
					for _, container := range htmlStreamRendererContainersRawTextToBrowsers {
						if htmlStreamRendererIsTagNameAt(sb, start, container) {
							return i
						}
					}
				} else if innerStart < 0 {
					break
				}
				// We don't need to do any suffix checks to preserve
				// concatenation safety since we buffer pending unescaped
				// above.
				end := start + len(localName)
				if end <= n &&
					stringsRegionMatchesIgnoreCase(sb, start, localName, 0, end-start) &&
					(end == n || htmlStreamRendererIsTagEnd(sb[end])) {
					return i
				}
			}
		case '>':
			if i >= 2 && sb[i-2] == '-' && sb[i-1] == '-' {
				if innerStart < 0 {
					return i - 2
				}
				// Merged start and end like <!--->
				if innerStart+6 > i {
					return innerStart
				}
				innerStart = -1
			}
		}
	}
	return innerStart
}

// htmlStreamRendererIsValidHTMLName reports whether name is a valid HTML
// element or attribute name: at most 128 ASCII letters, digits, '-', '_' and
// at most one ':', not starting with a digit, '-' or ':' and not ending with
// '-', '_' or ':'.
func htmlStreamRendererIsValidHTMLName(name string) bool {
	n := len(name)
	if n == 0 {
		return false
	}
	if n > 128 {
		return false
	}
	isNamespaced := false
	for i := 0; i < n; i++ {
		ch := name[i]
		switch ch {
		case ':':
			if isNamespaced {
				return false
			}
			isNamespaced = true
			if i == 0 || i+1 == n {
				return false
			}
		case '-':
			if i == 0 || i+1 == n {
				return false
			}
		case '_':
			if i+1 == n {
				return false
			}
		default:
			if ch <= '9' {
				if i == 0 || ch < '0' {
					return false
				}
			} else if 'A' <= ch && ch <= 'z' {
				if 'Z' < ch && ch < 'a' {
					return false
				}
			} else {
				return false
			}
		}
	}
	return true
}

// htmlStreamRendererEmitsContentLiterally reports whether the content of an
// element named canonElementName, written where inForeignContent says, is
// emitted as it is instead of being escaped, so that a tag in that content
// would reach the browser as written.
//
// This is the one place that decides it.  The renderer asks under the name
// it emits, which htmlStreamRendererSafeName may have substituted, and the
// element-and-attribute policy, whose filter has to run exactly where
// nothing escapes a tag for it, asks the same question about the receiver it
// writes to.
func htmlStreamRendererEmitsContentLiterally(
	canonElementName string, inForeignContent bool,
) bool {
	if inForeignContent {
		return false
	}
	switch EscapingModeForTag(canonElementName) {
	case HTMLTextEscapingModeCdata,
		HTMLTextEscapingModeCdataSometimes,
		HTMLTextEscapingModePlainText:
		return true
	default:
		return false
	}
}

// htmlStreamRendererSafeName canonicalizes the element name and possibly
// substitutes an alternative that has more consistent semantics.
func htmlStreamRendererSafeName(unsafeElementName string) string {
	elementName := htmlLexerCanonicalElementName(unsafeElementName)

	// Substitute a reliably non-raw-text element for raw-text and
	// plain-text elements.
	switch elementName {
	case "xmp", "listing", "plaintext":
		return "pre"
	}
	return elementName
}

// htmlStreamRendererTagEnds has bit c set for each character c that can end
// a tag name.
const htmlStreamRendererTagEnds uint64 = 1<<'\t' |
	1<<'\n' |
	1<<'\f' |
	1<<'\r' |
	1<<' ' |
	1<<'/' |
	1<<'>'

// htmlStreamRendererContainersRawTextToBrowsers are the elements the
// sanitizer treats as ordinary containers but that browsers read as raw
// text: noscript with scripting on, and noframes and noembed always.
var htmlStreamRendererContainersRawTextToBrowsers = [...]string{
	"noscript", "noframes", "noembed",
}

// htmlStreamRendererIsTagNameAt reports whether name sits at byte offset
// start in sb as a tag name.
func htmlStreamRendererIsTagNameAt(sb string, start int, name string) bool {
	end := start + len(name)
	return end <= len(sb) &&
		stringsRegionMatchesIgnoreCase(sb, start, name, 0, len(name)) &&
		(end == len(sb) || htmlStreamRendererIsTagEnd(sb[end]))
}

// htmlStreamRendererIsTagEnd reports whether ch can end a tag name.
func htmlStreamRendererIsTagEnd(ch byte) bool {
	return ch < 63 && htmlStreamRendererTagEnds&(1<<ch) != 0
}

// htmlStreamRendererForeignContentRootElementNames are the elements that
// root foreign content, inside which a browser parses the content of every
// element as markup, so that nothing there is literal.
var htmlStreamRendererForeignContentRootElementNames = map[string]struct{}{
	"svg":  {},
	"math": {},
}
