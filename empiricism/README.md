<!-- SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause -->

# Browser Parser Experiments

This module measures how browsers nest and balance HTML tags.  It converts
those observations into the element tables used by the sanitizer.

This is an internal maintenance tool.  Its generator,
[cmd/canned-tables](cmd/canned-tables/main.go), is a Go command in this module
that uses only the standard library, so it builds even when the tables it
replaces are stale; `go test ./empiricism/...` checks that the checked-in
tables are current.

## Files and data flow

1. [html-containment.html](html-containment.html) and
   [html-containment.js](html-containment.js) probe a browser's parser.
2. The probe emits JSON that is saved as [canned-data.json](canned-data.json).
3. [rebuild.sh](rebuild.sh) parses and formats that JSON into
   [canned-data.js](canned-data.js), then runs the
   [generator](cmd/canned-tables/main.go) through the `go:generate` directive
   in [html_element_tables.go](../sanitizer/html_element_tables.go).
4. The generator writes the library's
   [html_element_tables_canned.go](../sanitizer/html_element_tables_canned.go).

`canned-data.json`, `canned-data.js`, and `html_element_tables_canned.go` are
different representations of the same browser observations.  Never hand-edit
`html_element_tables_canned.go`.

## Regenerating the tables

You need a browser with JavaScript enabled, Bash, Python 3, Perl, and the Go
toolchain named in [go.mod](../go.mod).

1. Open the local `empiricism/html-containment.html` file in your browser and
   follow its `?rerun` link.  The full probe can take a long time; wait for it
   to finish.  Without `?rerun`, the page displays the saved observations.
2. Copy the complete JSON dump at the bottom of the page into
   `canned-data.json`.  Record the browser version used when describing the
   change.
3. From the repository root, run:

   ```sh
   ./empiricism/rebuild.sh
   ```

4. Review the diffs in `canned-data.json`, `canned-data.js`, and the generated
   Go file.  Explain changes in browser observations and add corresponding
   sanitizer tests where behavior changes.
5. Run every test before proposing the update:

   ```sh
   go test ./...
   ```

For a quick diagnostic run, use `?rerun&shortlist`.  Its output covers only a
subset of elements; do not use it to replace the complete `canned-data.json`.

Running `go generate ./sanitizer/html_element_tables.go` from the repository
root regenerates the tables from `canned-data.json` alone, without touching
`canned-data.js`.  A normal build uses the checked-in tables and does not run
browser experiments.

Because these tables affect parsing and balancing of attacker-controlled HTML,
treat every data change as security-sensitive.  Include adversarial cases for
raw-text elements, misnested tags, foreign SVG and MathML content, case
differences, and serialize/reparse mutation where relevant.
