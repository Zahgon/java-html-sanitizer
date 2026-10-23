# Getting Started

## Getting the module

Follow the [Go module](go.md) directions to add a dependency:

```sh
go get github.com/OWASP/java-html-sanitizer@latest
```

Or `git clone git@github.com:OWASP/java-html-sanitizer.git` and build and
test the latest source with `go vet ./...` and `go test ./...`.

Once the module is in your `go.mod` you should be able to add

```go
import "github.com/OWASP/java-html-sanitizer/sanitizer"
```

to one of your project's `.go` files and compile it.

## Using the APIs

```go
package main

import (
	"fmt"
	"log"

	"github.com/OWASP/java-html-sanitizer/sanitizer"
)

func main() {
	// Build a policy once, at start-up, and share it: a *PolicyFactory is
	// immutable and safe for concurrent use.
	policy, err := sanitizer.NewHTMLPolicyBuilder().
		AllowElements("p", "a").
		AllowAttributes("href").OnElements("a").
		AllowStandardURLProtocols().
		RequireRelNofollowOnLinks().
		ToFactory()
	if err != nil {
		log.Fatal(err)
	}
	// Prepackaged policies combine with And.
	policy = policy.And(sanitizer.Formatting)

	fmt.Println(policy.Sanitize(
		`<p onclick="steal()">Hi <b>there</b>, <a href="javascript:alert(1)">click</a>` +
			` or <a href="https://example.com/">here</a><script>alert(2)</script>`))
	// <p>Hi <b>there</b>, click or <a href="https://example.com/" rel="nofollow">here</a></p>
}
```

The
[examples](../examples/README.md)
include source code which defines a sanitization policy, and applies
it to HTML.  They are sample source to read and copy into your own
project, not part of the library's API: import only
`github.com/OWASP/java-html-sanitizer/sanitizer`.

The
[package documentation](https://pkg.go.dev/github.com/OWASP/java-html-sanitizer/sanitizer),
also available with `go doc github.com/OWASP/java-html-sanitizer/sanitizer`,
covers more detailed topics, including
[customization](https://pkg.go.dev/github.com/OWASP/java-html-sanitizer/sanitizer#HTMLPolicyBuilder).

Important types and values are:

  * [Formatting, Blocks, Styles, Links, Tables and Images](https://pkg.go.dev/github.com/OWASP/java-html-sanitizer/sanitizer#pkg-variables) are combinable pre-packaged policies.
  * [HTMLPolicyBuilder](https://pkg.go.dev/github.com/OWASP/java-html-sanitizer/sanitizer#HTMLPolicyBuilder), from `NewHTMLPolicyBuilder`, lets you easily build custom policies.
  * [PolicyFactory](https://pkg.go.dev/github.com/OWASP/java-html-sanitizer/sanitizer#PolicyFactory), from `HTMLPolicyBuilder.ToFactory`, sanitizes strings with `Sanitize` and `SanitizeWithListener`, and combines with other policies through `And`.

For advanced use, see:
  * [AttributePolicy](https://pkg.go.dev/github.com/OWASP/java-html-sanitizer/sanitizer#AttributePolicy) and [ElementPolicy](https://pkg.go.dev/github.com/OWASP/java-html-sanitizer/sanitizer#ElementPolicy) allow complex customization.
  * [HTMLChangeListener](https://pkg.go.dev/github.com/OWASP/java-html-sanitizer/sanitizer#HTMLChangeListener) reports what a policy removed.
  * [HTMLStreamEventReceiver](https://pkg.go.dev/github.com/OWASP/java-html-sanitizer/sanitizer#HTMLStreamEventReceiver) if you don't just want a `string` as output.

## Trying a policy from the command line

The [html-sanitize](../cmd/html-sanitize/main.go) command runs the sanitizer
locally against a policy of your choosing.  From a clone of the repository:

```sh
go run ./cmd/html-sanitize -p formatting -p links untrusted.html
```

`-p` names a prepackaged or example policy, and `-f` reads a policy from a
JSON file whose steps are `HTMLPolicyBuilder` calls, applied in order:

```json
[
  {"allowElements": ["a", "p"]},
  {"allowAttributes": ["href"], "onElements": ["a"]},
  {"allowStandardUrlProtocols": true},
  {"requireRelNofollowOnLinks": true}
]
```

```sh
go run ./cmd/html-sanitize -f policy.json --report < untrusted.html
```

`--report` writes every change-listener event to standard error, one JSON
array per line.  `go doc ./cmd/html-sanitize` lists every flag and policy
file step.

## Asking Questions

Feel free to post questions in
[GitHub Discussions](https://github.com/OWASP/java-html-sanitizer/discussions/categories/q-a)
and we'll do our best to help.
