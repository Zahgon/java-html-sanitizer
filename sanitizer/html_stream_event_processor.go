// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

// Ported from owasp-java-html-sanitizer/src/main/java/org/owasp/html/HtmlStreamEventProcessor.java.

package sanitizer

import "fmt"

// HTMLStreamEventProcessor receives the output sink to allow user-code to
// post-process events.
//
// Thread safety: a single processor is shared by every sanitization that
// uses the policy it was installed on, including concurrent ones, so a
// processor must be safe to call Wrap on from several goroutines.  Wrap is
// called once per sanitization, though, and the receiver it returns is used
// by that sanitization alone.  So per-document state -- "am I inside a
// <style> element?", a depth counter, a buffer -- belongs in the returned
// receiver, not in a field of the processor:
//
//	// Correct: the flag lives in the per-sanitization wrapper.
//	type styleTracker struct {
//		sanitizer.HTMLStreamEventReceiverWrapper
//		inStyle bool
//	}
//
//	processor := sanitizer.HTMLStreamEventProcessorFunc(
//		func(sink sanitizer.HTMLStreamEventReceiver) sanitizer.HTMLStreamEventReceiver {
//			return &styleTracker{
//				HTMLStreamEventReceiverWrapper: sanitizer.NewHTMLStreamEventReceiverWrapper(sink),
//			}
//		})
//
// A flag hoisted into the processor itself would be shared by concurrent
// sanitizations, which corrupts output rather than security: one document's
// events cannot escape the policy, but they can make another document's
// wrapper act on the wrong text.
type HTMLStreamEventProcessor interface {
	// Wrap takes sink, an HTML stream event receiver that can take events
	// from a sanitizer policy to build a safe output on an appropriate
	// buffer, and returns an HTML stream event receiver that does the same
	// by sending events to sink.  The result is used by one sanitization
	// only, so it is the right place for any state the processor needs to
	// keep.
	Wrap(sink HTMLStreamEventReceiver) HTMLStreamEventReceiver
}

// HTMLStreamEventProcessorFunc adapts a function to the
// HTMLStreamEventProcessor interface.
type HTMLStreamEventProcessorFunc func(sink HTMLStreamEventReceiver) HTMLStreamEventReceiver

// Wrap returns f(sink).
func (f HTMLStreamEventProcessorFunc) Wrap(sink HTMLStreamEventReceiver) HTMLStreamEventReceiver {
	return f(sink)
}

// htmlStreamEventProcessorIdentity is the type of
// IdentityProcessor.
type htmlStreamEventProcessorIdentity struct{}

// Wrap returns sink.
func (htmlStreamEventProcessorIdentity) Wrap(sink HTMLStreamEventReceiver) HTMLStreamEventReceiver {
	return sink
}

// String returns "[identity]".
func (htmlStreamEventProcessorIdentity) String() string {
	return "[identity]"
}

// IdentityProcessor is a post-processor that returns
// the sink without wrapping it to do any additional work.
var IdentityProcessor HTMLStreamEventProcessor = htmlStreamEventProcessorIdentity{}

// htmlStreamEventProcessorComposed wraps its input in f wrapped in g.
type htmlStreamEventProcessorComposed struct {
	g, f HTMLStreamEventProcessor
}

// Wrap returns g.Wrap(f.Wrap(sink)).
func (c htmlStreamEventProcessorComposed) Wrap(sink HTMLStreamEventReceiver) HTMLStreamEventReceiver {
	return c.g.Wrap(c.f.Wrap(sink))
}

// String returns "(g ∘ f)".
func (c htmlStreamEventProcessorComposed) String() string {
	return fmt.Sprintf("(%v \u2218 %v)", c.g, c.f)
}

// ComposeProcessors returns a processor that wraps
// its input in f wrapped in g.
func ComposeProcessors(
	g, f HTMLStreamEventProcessor,
) HTMLStreamEventProcessor {
	if f == IdentityProcessor {
		return g
	}
	if g == IdentityProcessor {
		return f
	}
	return htmlStreamEventProcessorComposed{g: g, f: f}
}
