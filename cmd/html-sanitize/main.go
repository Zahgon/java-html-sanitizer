// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

// Command html-sanitize sanitizes one HTML document with named or file-defined
// policies.
//
// Usage:
//
//	html-sanitize [flags] [FILE]
//	  -p, --policy NAME        a named policy (repeatable):
//	                             formatting, blocks, styles, links, tables, images
//	                                        the sanitizer.Sanitizers* policies
//	                             ebay       examples.EbayPolicy
//	                             slashdot   examples.SlashdotPolicy
//	                             urltext    examples.URLTextPolicy
//	  -f, --policy-file PFILE  a policy built from a JSON policy file (repeatable)
//	      --report             also report every change-listener event on stderr
//	  FILE                     the HTML to sanitize, read as UTF-8 (default: standard input)
//
// All policies (-p and -f, in command-line order) are combined left to right
// with PolicyFactory.And; at least one is required.  The input is sanitized
// with PolicyFactory.SanitizeWithListener, without a listener unless --report
// is given.
//
// A policy file is a JSON array of steps, applied in order to one new
// HTMLPolicyBuilder and finished with ToFactory.  Every step is an object with
// exactly one builder-method key:
//
//	{"allowElements": [NAME...]}            optional "renameTo": NAME maps every listed
//	                                        element to that name (AllowElementsWithPolicy)
//	{"disallowElements": [NAME...]}
//	{"allowCommonInlineFormattingElements": true}   {"allowCommonBlockElements": true}
//	{"allowTextIn": [NAME...]}              {"disallowTextIn": [NAME...]}
//	{"allowWithoutAttributes": [NAME...]}   {"disallowWithoutAttributes": [NAME...]}
//	{"allowAttributes": [NAME...], ...}     {"disallowAttributes": [NAME...], ...}
//	    plus exactly one of "globally": true or "onElements": [NAME...], and an
//	    optional "matching": [MATCHER...] applied in order; MATCHER is
//	    {"values": [VALUE...], "ignoreCase": BOOL}, "identity" or "reject"
//	{"requireRelNofollowOnLinks": true}   {"requireRelsOnLinks": [REL...]}   {"skipRelsOnLinks": [REL...]}
//	{"allowUrlProtocols": [P...]}   {"disallowUrlProtocols": [P...]}   {"allowStandardUrlProtocols": true}
//	{"allowOnlyRelativeUrls": true}
//	{"allowStyling": true}   {"allowStyling": SCHEMA}
//	{"allowUrlsInStyles": "identity" | "reject"}
//
// SCHEMA is "default", {"properties": [NAME...]}, {"define": {NAME: PROPERTY,
// ...}}, {"union": [SCHEMA...]}, {"intersection": [SCHEMA...]} or {"base":
// SCHEMA, "overrides": {NAME: PROPERTY, ...}}; PROPERTY is {"bits": INT,
// "literals": [S...], "functions": {FN: KEY, ...}} or {"like": NAME,
// "withLiterals": [S...], "withoutLiterals": [S...], "withFunctions": {FN: KEY,
// ...}}, a property of the default schema adjusted by the calls present, in
// that order.  Object members keep their file order.
//
// On success the sanitized HTML is written to stdout and the exit status is 0.
// With --report every listener call is one line on stderr: a JSON array of the
// method name and its string arguments, with '"' and '\' escaped by a
// backslash, characters from U+0020 to U+007E as is, and every other UTF-16
// code unit as a \u escape with four lower-case hex digits.  A policy the
// builder or the CSS schema rejects is reported as "html-sanitize: " and the
// error text on stderr, with exit status 1.  Usage errors exit with status 2.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/OWASP/java-html-sanitizer/examples"
	"github.com/OWASP/java-html-sanitizer/sanitizer"
)

func main() {
	var stdout, stderr bytes.Buffer
	code := run(os.Args[1:], ".", os.Stdin, &stdout, &stderr)
	if err := flush(os.Stdout, os.Stderr, &stdout, &stderr); err != nil {
		fmt.Fprintf(os.Stderr, "html-sanitize: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

// flush writes the buffered results of a run to the process's standard
// output and standard error, returning the first write error.
func flush(stdoutFile, stderrFile io.Writer, stdout, stderr *bytes.Buffer) error {
	if _, err := stdoutFile.Write(stdout.Bytes()); err != nil {
		return fmt.Errorf("writing standard output: %w", err)
	}
	if _, err := stderrFile.Write(stderr.Bytes()); err != nil {
		return fmt.Errorf("writing standard error: %w", err)
	}
	return nil
}

// usageError is a malformed command line or policy file (exit status 2).
type usageError struct{ msg string }

// Error returns the message.
func (e *usageError) Error() string { return e.msg }

// usagef returns a usageError with a formatted message.
func usagef(format string, args ...any) error {
	return &usageError{fmt.Sprintf(format, args...)}
}

// policyRef is one -p or -f argument.
type policyRef struct {
	name string // a named policy, or
	file string // a policy file path
}

// run executes one command line with relative paths resolved against dir and
// returns the exit status.  Output is only written once the run succeeds or
// fails as a whole, so a failure never leaves partial output.
func run(args []string, dir string, stdin io.Reader, stdout, stderr *bytes.Buffer) int {
	report := &bytes.Buffer{}
	out, err := sanitize(args, dir, stdin, report)
	if err != nil {
		var ue *usageError
		code := 1
		if errors.As(err, &ue) {
			code = 2
		}
		stderr.WriteString("html-sanitize: " + outputText(err.Error()) + "\n")
		return code
	}
	stdout.WriteString(outputText(out))
	stderr.Write(report.Bytes())
	return 0
}

// sanitize parses args, builds the combined policy and returns the sanitized
// input.  With --report it writes the listener events to report.
func sanitize(args []string, dir string, stdin io.Reader, report *bytes.Buffer) (string, error) {
	var policies []policyRef
	withReport := false
	file, haveFile := "", false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "-p", "--policy", "-f", "--policy-file":
			if i+1 >= len(args) {
				return "", usagef("flag %s needs a value", a)
			}
			i++
			if a == "-p" || a == "--policy" {
				policies = append(policies, policyRef{name: args[i]})
			} else {
				policies = append(policies, policyRef{file: args[i]})
			}
		case "--report":
			withReport = true
		default:
			if len(a) > 1 && a[0] == '-' {
				return "", usagef("unknown flag %s", a)
			}
			if haveFile {
				return "", usagef("expected at most one FILE argument")
			}
			file, haveFile = a, true
		}
	}
	if len(policies) == 0 {
		return "", usagef("no policy given")
	}
	var input []byte
	var err error
	if haveFile {
		input, err = os.ReadFile(resolve(dir, file))
	} else {
		input, err = io.ReadAll(stdin)
	}
	if err != nil {
		name := "standard input"
		if haveFile {
			name = file
		}
		return "", usagef("cannot read %s", name)
	}
	var factory *sanitizer.PolicyFactory
	for _, ref := range policies {
		var next *sanitizer.PolicyFactory
		if ref.file != "" {
			next, err = policyFromFile(resolve(dir, ref.file))
		} else {
			next, err = namedPolicy(ref.name)
		}
		if err != nil {
			return "", err
		}
		if factory == nil {
			factory = next
		} else {
			factory = factory.And(next)
		}
	}
	var listener sanitizer.HTMLChangeListener
	if withReport {
		listener = &reporter{out: report}
	}
	return factory.SanitizeWithListener(string(input), listener, nil), nil
}

// resolve returns path, resolved against dir unless it is absolute.
func resolve(dir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(dir, path)
}

// namedPolicy returns the built-in policy that a -p argument names.
func namedPolicy(name string) (*sanitizer.PolicyFactory, error) {
	switch name {
	case "formatting":
		return sanitizer.Formatting, nil
	case "blocks":
		return sanitizer.Blocks, nil
	case "styles":
		return sanitizer.Styles, nil
	case "links":
		return sanitizer.Links, nil
	case "tables":
		return sanitizer.Tables, nil
	case "images":
		return sanitizer.Images, nil
	case "ebay":
		return examples.EbayPolicy, nil
	case "slashdot":
		return examples.SlashdotPolicy, nil
	case "urltext":
		return examples.URLTextPolicy()
	}
	return nil, usagef("unknown policy %s", name)
}

// reporter writes each change-listener call as one JSON array line.
type reporter struct {
	out *bytes.Buffer
}

// line writes parts as one JSON array on its own line.
func (r *reporter) line(parts ...string) {
	r.out.WriteByte('[')
	for i, p := range parts {
		if i > 0 {
			r.out.WriteByte(',')
		}
		writeJSONString(r.out, p)
	}
	r.out.WriteString("]\n")
}

// DiscardedTag reports a dropped tag.
func (r *reporter) DiscardedTag(_ any, elementName string) {
	r.line("discardedTag", elementName)
}

// DiscardedAttributes reports attributes dropped from a kept tag.
func (r *reporter) DiscardedAttributes(_ any, tagName string, attributeNames ...string) {
	r.line(append([]string{"discardedAttributes", tagName}, attributeNames...)...)
}

// DiscardedAttribute reports the input value of one dropped attribute.
func (r *reporter) DiscardedAttribute(_ any, tagName, attributeName, attributeValue string) {
	r.line("discardedAttribute", tagName, attributeName, attributeValue)
}

// DiscardedText reports text dropped from a kept element.
func (r *reporter) DiscardedText(_ any, elementName, text string) {
	r.line("discardedText", elementName, text)
}

// writeJSONString writes s as a JSON string in the report's escaping: '"' and
// '\' escaped, printable ASCII as is, every other UTF-16 code unit as \uXXXX.
func writeJSONString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, unit := range utf16Units(s) {
		switch {
		case unit == '"' || unit == '\\':
			b.WriteByte('\\')
			b.WriteByte(byte(unit))
		case unit >= 0x20 && unit <= 0x7e:
			b.WriteByte(byte(unit))
		default:
			fmt.Fprintf(b, "\\u%04x", unit)
		}
	}
	b.WriteByte('"')
}
