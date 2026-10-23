# Using the Go module

The HTML Sanitizer is the Go module `github.com/OWASP/java-html-sanitizer`.
It needs Go 1.23 or newer and depends only on the Go standard library.

From your own module's directory, run

```sh
go get github.com/OWASP/java-html-sanitizer@latest
```

...to record the dependency in your `go.mod` and `go.sum`.  Then import the
library package, whose name is `sanitizer`:

```go
package main

import (
	"fmt"

	"github.com/OWASP/java-html-sanitizer/sanitizer"
)

func main() {
	policy := sanitizer.Formatting.And(sanitizer.Links)
	fmt.Println(policy.Sanitize(`<b>Hello</b> <a href="https://example.com/" onclick="evil()">World</a><script>alert(1)</script>`))
	// <b>Hello</b> <a href="https://example.com/" rel="nofollow">World</a>
}
```

The module has no other packages for applications to import: `examples/` holds
sample policies to read and copy, and `cmd/html-sanitize` is a command, which
you can install with

```sh
go install github.com/OWASP/java-html-sanitizer/cmd/html-sanitize@latest
```

## Versions

Go selects module versions from the repository's git tags, and `go get`
writes the version it chose into your `go.mod`.  `@latest` picks the newest
release tag, or the newest commit on the default branch as a pseudo-version
if there is no release tag yet; you can also ask for a specific version or
commit with `@<version>`.  Run `go get -u github.com/OWASP/java-html-sanitizer`
to move to a newer release.

Only the latest version is supported with security updates (see the
[security policy](../SECURITY.md)), so keep up to date.  The
[change log](../change_log.md) sheds light on the salient differences between
releases, and the [vulnerability list](vulnerabilities.md) lists published
advisories.

## Documentation

The API documentation is on
[pkg.go.dev](https://pkg.go.dev/github.com/OWASP/java-html-sanitizer/sanitizer),
and is also available offline from the toolchain:

```sh
go doc github.com/OWASP/java-html-sanitizer/sanitizer
go doc github.com/OWASP/java-html-sanitizer/sanitizer.HTMLPolicyBuilder
```

The [getting-started guide](getting_started.md) introduces the main types.
If you have questions that aren't answered by these pages, you can ask in
[GitHub Discussions](https://github.com/OWASP/java-html-sanitizer/discussions/categories/q-a).

Happy sanitizing...
