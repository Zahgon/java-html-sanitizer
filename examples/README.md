<!-- SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause -->

# Examples

This package contains worked examples of building and applying sanitizer
policies.  The sources are meant to be read and adapted; the package is tested
with the rest of the module, and the `html-sanitize` command uses its
policies, but it is not part of the library's API, so applications should not
import `github.com/OWASP/java-html-sanitizer/examples`.

## Included examples

* [ebay_policy_example.go](ebay_policy_example.go) (`EbayPolicy`)
  demonstrates a rich-text policy with CSS and attribute rules.
* [slashdot_policy_example.go](slashdot_policy_example.go) (`SlashdotPolicy`)
  demonstrates a smaller policy, custom element names, and normalized attributes.
* [url_text_example.go](url_text_example.go) (`URLTextPolicy`)
  demonstrates a postprocessor that appends a URL's
  authority as visible text after links and images.

`RunEbayPolicy` and `RunSlashdotPolicy` read UTF-8 HTML from an `io.Reader`
and write sanitized HTML to an `io.Writer`; each buffers the complete input
before sanitizing.  `RunURLTextExample` takes its HTML as string arguments.
To run a policy on a document, use the
[html-sanitize](../cmd/html-sanitize/main.go) command, whose `ebay`,
`slashdot` and `urltext` policies are these:

```sh
go run ./cmd/html-sanitize -p ebay untrusted.html
```

## Build and test

The [tests](examples_test.go) exercise both accepted markup and hostile
input.  Run them from the repository root:

```sh
go test ./examples
```

Treat these policies as examples, not universal security profiles.  Start from
default deny, allow only the markup an application needs, restrict URL
protocols explicitly, and add negative tests for the application's threat
model.  The root [README](../README.md) and
[getting-started guide](../docs/getting_started.md) cover the supported public
API.
