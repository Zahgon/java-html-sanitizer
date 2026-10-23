// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/HtmlStreamEventReceiverWrapper.java.

package sanitizer

import "io"

// HTMLStreamEventReceiverWrapper is an event receiver that delegates to an
// underlying receiver.  Embed it in a struct and define methods on that
// struct to do additional work for some events: the events the struct does
// not handle itself go straight to Underlying.
type HTMLStreamEventReceiverWrapper struct {
	// Underlying is delegated to.
	Underlying HTMLStreamEventReceiver
}

// NewHTMLStreamEventReceiverWrapper returns a wrapper that delegates to
// underlying.
func NewHTMLStreamEventReceiverWrapper(
	underlying HTMLStreamEventReceiver,
) HTMLStreamEventReceiverWrapper {
	return HTMLStreamEventReceiverWrapper{Underlying: underlying}
}

// OpenDocument delegates to the underlying receiver.
func (w HTMLStreamEventReceiverWrapper) OpenDocument() {
	w.Underlying.OpenDocument()
}

// CloseDocument delegates to the underlying receiver.
func (w HTMLStreamEventReceiverWrapper) CloseDocument() {
	w.Underlying.CloseDocument()
}

// OpenTag delegates to the underlying receiver.
func (w HTMLStreamEventReceiverWrapper) OpenTag(elementName string, attrs []string) {
	w.Underlying.OpenTag(elementName, attrs)
}

// CloseTag delegates to the underlying receiver.
func (w HTMLStreamEventReceiverWrapper) CloseTag(elementName string) {
	w.Underlying.CloseTag(elementName)
}

// Text delegates to the underlying receiver.
func (w HTMLStreamEventReceiverWrapper) Text(text string) {
	w.Underlying.Text(text)
}

// Close closes the underlying receiver if it is an io.Closer.
func (w HTMLStreamEventReceiverWrapper) Close() error {
	if c, ok := w.Underlying.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// Unwrap returns the underlying receiver.  A receiver that embeds
// HTMLStreamEventReceiverWrapper has this method too, so code that needs to
// see through wrappers to the receiver at the bottom can unwrap any receiver
// with an Unwrap method returning HTMLStreamEventReceiver.
func (w HTMLStreamEventReceiverWrapper) Unwrap() HTMLStreamEventReceiver {
	return w.Underlying
}
