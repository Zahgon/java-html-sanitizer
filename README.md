# OWASP Java HTML Sanitizer

[![Build](https://github.com/OWASP/java-html-sanitizer/actions/workflows/build.yml/badge.svg)](https://github.com/OWASP/java-html-sanitizer/actions/workflows/build.yml) [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/2602/badge)](https://www.bestpractices.dev/projects/2602) [![Go Reference](https://pkg.go.dev/badge/github.com/OWASP/java-html-sanitizer/sanitizer.svg)](https://pkg.go.dev/github.com/OWASP/java-html-sanitizer/sanitizer)


A fast and easy to configure HTML Sanitizer which lets you include HTML
authored by third-parties in your web application while protecting against
XSS.

The sanitizer was originally written in Java; it is now a Go module,
`github.com/OWASP/java-html-sanitizer`, that keeps the repository's name.
The library is the package
[`github.com/OWASP/java-html-sanitizer/sanitizer`](https://pkg.go.dev/github.com/OWASP/java-html-sanitizer/sanitizer).
It uses only the Go standard library, so it brings no third-party
dependencies into your build.

This code was written with security best practices in mind, has an
extensive test suite, and has undergone
[adversarial security review](docs/attack_review_ground_rules.md).

## Table Of Contents

*  [Getting Started](#getting-started)
*  [Repository Layout](#repository-layout)
*  [Prepackaged Policies](#prepackaged-policies)
*  [Crafting a policy](#crafting-a-policy)
*  [Custom policies](#custom-policies)
*  [Preprocessors](#preprocessors)
*  [Telemetry](#telemetry)
*  [Command-line sanitizer](#command-line-sanitizer)
*  [Building and testing](#building-and-testing)
*  [Questions\?](#questions)
*  [Contributing](#contributing)
*  [License](#license)
*  [Credits](#credits)

## Getting Started

Add the module to your Go module (Go 1.23 or newer):

```sh
go get github.com/OWASP/java-html-sanitizer@latest
```

and import the library package:

```go
import "github.com/OWASP/java-html-sanitizer/sanitizer"
```

[Getting Started](docs/getting_started.md) walks through the main APIs, and
[Using the Go module](docs/go.md) covers versions and imports.

## Repository Layout

* [sanitizer/](sanitizer/) is the library: HTML lexing, tag balancing,
  allowlist policy enforcement, CSS handling and rendering, with its tests and
  their data in `sanitizer/testdata/`.
* [cmd/html-sanitize/](cmd/html-sanitize/main.go) is a command that sanitizes
  an HTML document with prepackaged, example or JSON-defined policies.
* [examples/](examples/README.md) contains sample policies to read and copy;
  they are tested but are not part of the library's API.
* [empiricism/](empiricism/README.md) contains the browser experiments, and
  the generator, behind the sanitizer's HTML element tables.
* [docs/](docs/README.md) contains user, security, and historical documentation.

## Prepackaged Policies

You can use the
[prepackaged policies](https://pkg.go.dev/github.com/OWASP/java-html-sanitizer/sanitizer#pkg-variables)
`sanitizer.Formatting`, `Blocks`, `Styles`, `Links`, `Tables` and `Images`,
and combine them with `And`:

```go
policy := sanitizer.Formatting.And(sanitizer.Links)
safeHTML := policy.Sanitize(untrustedHTML)
```

## Crafting a policy

The
[tests](sanitizer/html_policy_builder_test.go)
show how to configure your own
[policy](https://pkg.go.dev/github.com/OWASP/java-html-sanitizer/sanitizer#HTMLPolicyBuilder):

```go
policy, err := sanitizer.NewHTMLPolicyBuilder().
	AllowElements("a").
	AllowURLProtocols("https").
	AllowAttributes("href").OnElements("a").
	RequireRelNofollowOnLinks().
	ToFactory()
if err != nil {
	log.Fatal(err) // the builder was misconfigured
}
safeHTML := policy.Sanitize(untrustedHTML)
```

`ToFactory` returns the first configuration error the builder recorded, such
as a `rel` value containing spaces.  The `*PolicyFactory` it returns is
immutable and safe for concurrent use, so build it once and share it.

## Custom Policies

You can write
[custom element policies](https://pkg.go.dev/github.com/OWASP/java-html-sanitizer/sanitizer#ElementPolicy)
to do things like changing `h1`s to `div`s with a certain class:

```go
policy, err := sanitizer.NewHTMLPolicyBuilder().
	AllowElements("p").
	AllowElementsWithPolicy(
		sanitizer.ElementPolicyFunc(func(elementName string, attrs *[]string) (string, bool) {
			// Add a class attribute.
			*attrs = append(*attrs, "class", "header-"+elementName)
			// Return the new element name and true to include it,
			// or false to drop it.
			return "div", true
		}),
		"h1", "h2", "h3", "h4", "h5", "h6").
	ToFactory()
```

Please note that the elements "a", "font", "img", "input" and "span"
need to be explicitly allowed using the `AllowWithoutAttributes()`
method if you want them to be allowed through the filter when these
elements do not include any attributes.

[Attribute policies](https://pkg.go.dev/github.com/OWASP/java-html-sanitizer/sanitizer#AttributePolicy) allow running custom code too.  Adding an attribute policy will not water down any default policy like `style` or URL attribute checks.

```go
myPolicy, err := sanitizer.NewHTMLPolicyBuilder().
	AllowElements("div", "span").
	AllowAttributes("data-foo").
	Matching(sanitizer.AttributePolicyFunc(
		func(elementName, attributeName, value string) (string, bool) {
			// Return the value to keep and true, or false to drop the
			// attribute.
			return value, true
		})).
	OnElements("div", "span").
	ToFactory()
```

## Preprocessors

Preprocessors allow inserting text and large scale structural changes.  A
receiver that embeds
[`HTMLStreamEventReceiverWrapper`](https://pkg.go.dev/github.com/OWASP/java-html-sanitizer/sanitizer#HTMLStreamEventReceiverWrapper)
passes on every event it does not handle itself:

```go
// linkOrigins provides users with info about links before they click.
//
//	Before:                       <a href="https://example.com/...">
//	After:  (https://example.com) <a href="https://example.com/...">
type linkOrigins struct {
	sanitizer.HTMLStreamEventReceiverWrapper
}

func (r linkOrigins) OpenTag(elementName string, attrs []string) {
	if elementName == "a" {
		for i := 0; i+1 < len(attrs); i += 2 {
			if attrs[i] != "href" {
				continue
			}
			origin := "about:invalid"
			if u, err := url.Parse(attrs[i+1]); err == nil {
				origin = ""
				if u.Scheme != "" {
					origin = u.Scheme + ":"
				}
				if u.Host != "" {
					origin += "//" + u.Host
				}
			}
			if origin != "" {
				r.Text(" (" + origin + ") ")
			}
		}
	}
	r.HTMLStreamEventReceiverWrapper.OpenTag(elementName, attrs)
}
```

```go
myPolicy, err := sanitizer.NewHTMLPolicyBuilder().
	WithPreprocessor(sanitizer.HTMLStreamEventProcessorFunc(
		func(sink sanitizer.HTMLStreamEventReceiver) sanitizer.HTMLStreamEventReceiver {
			return linkOrigins{sanitizer.NewHTMLStreamEventReceiverWrapper(sink)}
		})).
	AllowElements("a").
	AllowAttributes("href").OnElements("a").
	AllowStandardURLProtocols().
	ToFactory()
```

Preprocessing happens before a policy is applied, so cannot affect the security
of the output.

## Telemetry

When a policy rejects an element or attribute it notifies an [HTMLChangeListener](https://pkg.go.dev/github.com/OWASP/java-html-sanitizer/sanitizer#HTMLChangeListener).

You can use this to keep track of policy violation trends and find out when someone
is making an effort to breach your security.

```go
// requestContext is whatever you want to associate reports with.
type requestContext struct{ remoteAddr string }

// violationLogger embeds NopHTMLChangeListener, so it need only define the
// methods it uses.
type violationLogger struct {
	sanitizer.NopHTMLChangeListener
}

func (violationLogger) DiscardedTag(context any, elementName string) {
	log.Printf("%s: discarded <%s>", context.(*requestContext).remoteAddr, elementName)
}

func (violationLogger) DiscardedAttributes(context any, tagName string, attributeNames ...string) {
	log.Printf("%s: discarded %v from <%s>", context.(*requestContext).remoteAddr, attributeNames, tagName)
}
```

```go
sanitizedHTML := policy.SanitizeWithListener(
	unsanitizedHTML, violationLogger{}, &requestContext{remoteAddr: "192.0.2.1"})
```

`DiscardedAttributes` also fires for attributes rejected from an element that
was then dropped for having none left, such as a link whose only `href` was
rejected.  Two more methods carry more detail for listeners that define
them instead of taking `NopHTMLChangeListener`'s no-ops: `DiscardedAttribute`
receives each rejected attribute's value, and `DiscardedText` receives
tag-like content the policy removed from a kept literal-content element, and
content the renderer could not emit from one.

**Note**: If a string sanitizes with no change notifications, it is not the case
that the input string is necessarily safe to use. Only use the output of the sanitizer.

The sanitizer ensures that the output is in a sub-set of HTML that commonly
used HTML parsers will agree on the meaning of, but the absence of
notifications does not mean that the input is in such a sub-set,
only that it does not contain structural content that was removed.

See ["Why sanitize when you can validate"](https://github.com/OWASP/java-html-sanitizer/blob/main/docs/html-validation.md) for more on this topic.

## Command-line sanitizer

[`html-sanitize`](cmd/html-sanitize/main.go) sanitizes one HTML document,
read as UTF-8 from a file or standard input, and writes the result to
standard output.  Policies are named with `-p` (`formatting`, `blocks`,
`styles`, `links`, `tables`, `images`, and the example policies `ebay`,
`slashdot` and `urltext`) or defined in a JSON policy file with `-f`; several
are combined with `And`.  `--report` also writes every change-listener event
to standard error.

```sh
go install github.com/OWASP/java-html-sanitizer/cmd/html-sanitize@latest
html-sanitize -p formatting -p links untrusted.html
```

`go doc github.com/OWASP/java-html-sanitizer/cmd/html-sanitize` describes
the flags and the policy file format.  It is a convenient way to try a policy
against an input, for example when reviewing an attack.

## Building and testing

You need the Go toolchain named in [go.mod](go.mod) or newer.  From the
repository root:

```sh
go vet ./...
go test ./...
```

CI also checks that `gofmt -l .` lists no files.  The HTML element tables in
`sanitizer/html_element_tables_canned.go` are generated: see
[empiricism/](empiricism/README.md) for how `go generate ./sanitizer`
rebuilds them.

## Questions?

If you wish to report a vulnerability, please see the
[security policy](SECURITY.md) and the
[attack review ground rules](docs/attack_review_ground_rules.md).

Subscribe to the
[mailing list](https://groups.google.com/g/owasp-java-html-sanitizer-support)
or watch this repository's
[releases](https://github.com/OWASP/java-html-sanitizer/releases) and
[security advisories](https://github.com/OWASP/java-html-sanitizer/security/advisories)
to be notified of known [Vulnerabilities](docs/vulnerabilities.md) and important updates.

## Contributing

The project is led by [Jim Manico](https://github.com/jmanico).  Release
management and maintenance are shared with
[Abhishek](https://github.com/mrabhishek),
[Andres Almiray](https://github.com/aalmiray),
[Ben Evans](https://github.com/kittylyst),
[Erik Costlow](https://github.com/erikcostlow) and
[Brian Fox](https://github.com/brianf).
[Mike Samuel](https://github.com/mikesamuel) founded the project and wrote the
original sanitizer; he is no longer involved in day-to-day maintenance.

If you would like to contribute, open an
[issue](https://github.com/OWASP/java-html-sanitizer/issues) -- that is the
best way to reach the maintainers.

We welcome [issue reports](https://github.com/OWASP/java-html-sanitizer/issues) and PRs.
PRs that change behavior or that add functionality should include both positive and
[negative tests](https://www.guru99.com/negative-testing.html), and must pass
`gofmt`, `go vet ./...` and `go test ./...`.

Please be aware that contributions fall under the project's dual license:
`Apache-2.0 OR BSD-2-Clause`, at the recipient's option. See
[COPYING](https://github.com/OWASP/java-html-sanitizer/blob/main/COPYING).

## License

Dual licensed: **`Apache-2.0 OR BSD-2-Clause`**.  You may use this software
under either the [Apache License, Version 2.0](LICENSE) or the BSD 2-Clause
License, at your option -- you do not need to comply with both.

[COPYING](COPYING) is the authoritative statement of the grant and contains
the full text of both licenses.  `LICENSE` holds only the Apache-2.0 arm, so
that automated tooling which understands a single license file detects one;
it does not narrow the choice offered by `COPYING`.

Every source file carries an SPDX identifier.  AntiSamy-derived test code is
third-party code under `BSD-3-Clause`, listed under THIRD-PARTY CODE in
`COPYING`; it lives in `sanitizer/anti_samy_test.go`, a test file that is not
compiled into the library.

## Credits

[Thanks to everyone who has helped with criticism and code](docs/credits.md)
