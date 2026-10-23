# AGENTS.md

Guidance for AI-assisted work in this repository. This is a security-critical library. When in doubt, do less and ask a maintainer.

## Project

OWASP Java HTML Sanitizer, now a Go module (`github.com/OWASP/java-html-sanitizer`; the repository keeps its name). Takes attacker-controlled HTML and produces HTML that is safe to embed in a web page. Allowlist policies are built with `HTMLPolicyBuilder` (`sanitizer.NewHTMLPolicyBuilder()`) and compiled by `ToFactory` into immutable `*PolicyFactory` values that are safe for concurrent use.

The module (`go.mod` at the root) holds:

- `sanitizer/` — the library, package `sanitizer`. Core code and its `_test.go` files live side by side; test fixtures are in `sanitizer/testdata/`. This is the only package applications import.
- `cmd/html-sanitize/` — a command that sanitizes one document with named or JSON-defined policies, optionally reporting every change-listener event. Its package doc is the reference for its flags and policy-file format.
- `empiricism/` — in-browser experiments that record how real browsers nest and balance tags, and the generator `empiricism/cmd/canned-tables`. They generate `sanitizer/html_element_tables_canned.go` through the `go:generate` directive in `sanitizer/html_element_tables.go`. Never hand-edit that file: change the probe or `empiricism/canned-data.json` and run `empiricism/rebuild.sh`, or `go generate ./sanitizer` to regenerate from `canned-data.json` alone.
- `examples/`, `docs/` — sample policies (a tested package, used by `cmd/html-sanitize`, but not public API) and documentation.

Primary threat: XSS, including mutation XSS (mXSS), namespace confusion, and browser parser quirks.

## Build and Test

- From the repository root: `gofmt -l .` (must print nothing), `go vet ./...`, and `go test ./...`. This is what CI runs, on the Go version named in `go.mod`.
- The module targets the Go version in `go.mod` (`go 1.23`). Do not use language features or standard-library APIs newer than that, and do not raise it.
- Standard library only. `go.mod` has no `require` lines; keep it that way, for tests and tools as well as the library.
- Tests use the standard `testing` package. Fuzzer tests (`*_fuzzer_test.go`) and the AntiSamy test suite (`sanitizer/anti_samy_test.go`) are part of the normal test run. The fuzzers use fixed seeds and report the seed on failure, so a failure reproduces on every run. A fuzzer failure is a real bug, never something to re-run until it passes.
- `go test ./empiricism/...` checks that the checked-in element tables match `empiricism/canned-data.json`; after changing the data, regenerate rather than edit.
- All tests must pass before proposing any change. No exceptions.

## Security Invariants

Hard rules. Never violate them, never refactor around them.

1. **Allowlist only.** Everything is denied unless a policy explicitly allows it. Never introduce denylist or strip-known-bad logic.
2. **Default deny for anything new.** New elements, attributes, URL protocols, or CSS properties are unsafe until a policy author explicitly allows them.
3. **Output must be safe in every HTML parsing context, not just the happy path:** foreign content (SVG, MathML), raw-text and RCDATA elements (`script`, `style`, `title`, `textarea`, `noscript`, `xmp`, `iframe`, `plaintext`), comments, CDATA. `HTMLTextEscapingMode` (`sanitizer/html_text_escaping_mode.go`) is the sanitizer's table of these. Browsers treat `noscript` as raw text when scripting is on even though the sanitizer deliberately does not; CVE-2025-66021 exploited that mismatch.
4. **Case sensitivity matters.** SVG and MathML element and attribute names are not lower-cased (see the mixed-case foreign name sets in `sanitizer/html_lexer.go`); SVG `textArea` is distinct from HTML `textarea`. Preserve this.
5. **Encoding and rendering are part of the security boundary.** Changes to encoding (`sanitizer/encoding.go`), `HTMLStreamRenderer`, `TagBalancingHTMLStreamEventReceiver`, `HTMLTextEscapingMode`, entity handling, or serialization are security changes and require adversarial tests.
6. **The prepackaged policies (`Formatting`, `Blocks`, `Styles`, `Links`, `Tables`, `Images` in `sanitizer/sanitizers.go`) are published safety promises.** Never widen what they allow.
7. **Round-trip safety:** sanitized output, re-parsed by a browser, must not mutate into a different, unsafe DOM (mXSS).
8. **Any input terminates, in bounded stack and in time and memory linear in its size.** Sanitizing must never panic, and never overflow the goroutine stack, which in Go is a fatal error that `recover` cannot catch, for input of any shape. Recursion whose depth follows the input is forbidden: bound it with a small constant and drop what exceeds the bound, as `cssGrammarMaxFunctionDepth` does, or walk with an explicit stack. Time and memory may grow only linearly with the input, and output only by a constant factor; the tag balancer's quadratic paths, and its formatting reconstruction that turned 70 KB into 17 MB, were both found the hard way. Memory in proportion to the input is unavoidable, so an input too big for the heap can still exhaust it; bounding input size is the caller's job, and that alone is not a bug. A crash, a hang, or a blow-up on hostile input is a denial of service and is handled as a vulnerability.

## Change Rules

- Small, single-purpose changes only. No drive-by refactors of parser, policy, or renderer code.
- Any change touching parsing, policy enforcement, rendering, encoding, URL handling, or CSS handling requires new regression tests with hostile payloads, not just benign inputs. Where the code walks the input recursively, keeps state per token, or re-scans what it has already seen, one of those tests runs at hostile size, hundreds of thousands of nested or repeated tokens, and shows no error and linear time. Tests must stay fast and bounded: such a test runs in seconds and in memory proportional to its input, a few hundred megabytes at most, so that `go test ./...` passes on small machines and CI runners alike.
- Never weaken, delete, or loosen an existing test to make a change pass. A failing security test means the change is wrong.
- No new dependencies. The module uses only the Go standard library, in the library, its tests, and its tools. Do not add a `require` to `go.mod`.
- Follow the Contributing section of `README.md`: open an issue first to reach the maintainers, and include both positive and negative tests in any PR that changes behavior or adds functionality.
- Preserve public API compatibility: do not rename or remove exported identifiers of package `sanitizer` or change their signatures. This library is embedded in a very large number of applications.
- Match the surrounding code: format Go with `gofmt`, and follow the Go file header convention. Every `.go` file starts with its licence header in `//` comments, followed by a blank line so that it is not taken for package documentation. A file ported from the Java sources keeps that file's header, its copyright and licence text if it had them, and always the line `// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause`; every new file starts with that SPDX line. The one exception is the AntiSamy-derived `sanitizer/anti_samy_test.go`, third-party code under `BSD-3-Clause` (see THIRD-PARTY CODE in `COPYING`) whose header is a block comment; do not copy its code into files under the project's licence. Never edit or strip existing licence or copyright text. Markdown files keep their `<!-- SPDX-License-Identifier: ... -->` line where they have one.
- Never hand-edit generated code. `sanitizer/html_element_tables_canned.go` comes from `go generate ./sanitizer`; commit the regenerated file together with the data change that produced it.
- Record user-visible changes as a bullet under the `* Next release` heading at the top of `change_log.md`. Maintainers turn that heading into the release entry; do not add release headings or edit released entries.
- Releases are maintainer-driven. Go modules are released by tagging; do not create or move tags, and do not modify the project version in `SECURITY.md` or `docs/vulnerabilities.md`.

## Vulnerability Handling

- If you find a possible bypass while working, report it privately per `SECURITY.md` so a GitHub security advisory can coordinate the fix.
- Regression tests for a vulnerability land publicly only after the advisory and fixed release are out.

## Known Bypass and Denial-of-Service Classes for Regression Testing

Use these as targets when touching parser, policy, or renderer code:

- Policy enforcement gaps on specific elements, e.g. `style` inside `option` and `select`: CVE-2021-42575 (`docs/cve202142575.md`)
- Raw-text and RCDATA content handling (`style`, `noscript`, and friends): CVE-2025-66021 (advisory GHSA-g9gq-3pfx-2gw2)
- mXSS via serialize and re-parse differences
- SVG and MathML namespace and case tricks
- `javascript:`, `data:`, and scheme-relative URLs in allowed attributes
- Entity and encoding edge cases: malformed entities, entities without semicolons, null bytes, mixed case, nested and unbalanced tags
- Denial of service: unbounded recursion over nested CSS functions (GHSA-x6fc-6qh4-g3wr), quadratic tag-balancer paths and unbounded formatting reconstruction (release 20260921.1, #490)
- Full history: `docs/vulnerabilities.md`

## Keeping This File Current

When a bug, a vulnerability, or a review finding shows that a rule was missing here, add the rule, judiciously: one that would have prevented the mistake, stated once, in the section it belongs to, in the voice of its neighbours. Do not log the incident; `change_log.md`, `docs/vulnerabilities.md` and the git history hold that. Do not add a rule for a one-off that no rule would have caught, and do not restate a rule that is already here.
