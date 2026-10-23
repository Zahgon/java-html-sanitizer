// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	const notSelfContained = `html-sanitize: Property map is not self contained: "color" uses ` +
		`the function key "rgb()" which the map does not define.  Add it to the map, ` +
		`or build on a schema that already has it with CssSchema.withOverrides.` + "\n"

	tests := []struct {
		name     string
		args     []string
		files    map[string]string
		stdin    string
		wantCode int
		wantOut  string
		wantErr  string
	}{
		{
			name:    "named policy",
			args:    []string{"-p", "formatting", "in.html"},
			files:   map[string]string{"in.html": `<p>Hi <b>there</b><script>alert(1)</script> <a href="http://example.com/">link</a></p>`},
			wantOut: "Hi <b>there</b> link",
		},
		{
			name:    "stdin",
			args:    []string{"-p", "links"},
			stdin:   `<a href="http://example.com/" onclick="x()">link</a><a href="javascript:alert(1)">bad</a>`,
			wantOut: `<a href="http://example.com/" rel="nofollow">link</a>bad`,
		},
		{
			name:    "named policies combined",
			args:    []string{"-p", "formatting", "-p", "links"},
			stdin:   `<b><a href="http://example.com/">l</a></b><i>x</i>`,
			wantOut: `<b><a href="http://example.com/" rel="nofollow">l</a></b><i>x</i>`,
		},
		{
			name: "named policy and policy file combined",
			args: []string{"--policy", "formatting", "--policy-file", "p.json", "in.html"},
			files: map[string]string{
				"p.json": `[{"allowElements": ["a", "b"]},
					{"allowAttributes": ["href"], "onElements": ["a"]},
					{"allowStandardUrlProtocols": true},
					{"requireRelNofollowOnLinks": true}]`,
				"in.html": `<b>bold</b> <i>it</i> <a href="http://example.com/" title="t">l</a>`,
			},
			wantOut: `<b>bold</b> <i>it</i> <a href="http://example.com/" rel="nofollow">l</a>`,
		},
		{
			name:    "policy file with CSS schema",
			args:    []string{"-f", "p.json"},
			files:   map[string]string{"p.json": `[{"allowElements": ["p"]}, {"allowAttributes": ["style"], "globally": true}, {"allowStyling": {"properties": ["color"]}}]`},
			stdin:   `<p style="color: red; width: 10px">x</p>`,
			wantOut: `<p style="color:red">x</p>`,
		},
		{
			name:    "report",
			args:    []string{"-p", "formatting", "--report"},
			stdin:   `<b id="1" class="c">x</b><script>s</script>`,
			wantOut: "<b>x</b>",
			wantErr: `["discardedAttributes","b","id","class"]` + "\n" +
				`["discardedAttribute","b","id","1"]` + "\n" +
				`["discardedAttribute","b","class","c"]` + "\n" +
				`["discardedTag","script"]` + "\n",
		},
		{
			// '"' and '\' are escaped with a backslash, control and non-ASCII
			// characters become \u escapes, and a supplementary character
			// becomes the escapes of its surrogate pair.
			name:    "report escaping",
			args:    []string{"--report", "-p", "formatting"},
			stdin:   "<b title='q\"b\\c\td\ne\u00e9\U0001F600~'>x</b>",
			wantOut: "<b>x</b>",
			wantErr: `["discardedAttributes","b","title"]` + "\n" +
				`["discardedAttribute","b","title","q\"b\\c\u0009d\u000ae\u00e9\ud83d\ude00~"]` + "\n",
		},
		{
			name: "report with policy file",
			args: []string{"--report", "-f", "p.json", "in.html"},
			files: map[string]string{
				"p.json":  `[{"allowElements": ["p"]}, {"disallowTextIn": ["p"]}]`,
				"in.html": "<p>dropped</p><b>x</b>",
			},
			wantOut: "<p></p>x",
			wantErr: `["discardedTag","b"]` + "\n",
		},
		{
			name:     "builder error",
			args:     []string{"-f", "p.json"},
			files:    map[string]string{"p.json": `[{"requireRelsOnLinks": ["no follow"]}]`},
			stdin:    "x",
			wantCode: 1,
			wantErr:  `html-sanitize: spaces in input.  use f("foo", "bar") not f("foo bar")` + "\n",
		},
		{
			name:     "unknown CSS property",
			args:     []string{"-f", "p.json"},
			files:    map[string]string{"p.json": `[{"allowStyling": {"properties": ["color", "nosuch"]}}]`},
			stdin:    "x",
			wantCode: 1,
			wantErr:  "html-sanitize: nosuch\n",
		},
		{
			name:     "CSS property map not self contained",
			args:     []string{"-f", "p.json"},
			files:    map[string]string{"p.json": `[{"allowStyling": {"define": {"color": {"bits": 0, "functions": {"rgb(": "rgb()"}}}}}]`},
			stdin:    "x",
			wantCode: 1,
			wantErr:  notSelfContained,
		},
		{
			name:     "irreconcilable CSS union",
			args:     []string{"-f", "p.json"},
			files:    map[string]string{"p.json": `[{"allowStyling": {"union": [{"define": {"color": {"bits": 0}}}, {"properties": ["color"]}]}}]`},
			stdin:    "x",
			wantCode: 1,
			wantErr:  "html-sanitize: Duplicate irreconcilable definitions for color\n",
		},
		{
			name:     "no policy",
			stdin:    "x",
			wantCode: 2,
			wantErr:  "html-sanitize: no policy given\n",
		},
		{
			name:     "unknown flag",
			args:     []string{"-x", "-p", "formatting"},
			wantCode: 2,
			wantErr:  "html-sanitize: unknown flag -x\n",
		},
		{
			name:     "unknown policy",
			args:     []string{"-p", "nosuch"},
			wantCode: 2,
			wantErr:  "html-sanitize: unknown policy nosuch\n",
		},
		{
			name:     "flag without value",
			args:     []string{"-p"},
			wantCode: 2,
			wantErr:  "html-sanitize: flag -p needs a value\n",
		},
		{
			name:     "two input files",
			args:     []string{"-p", "formatting", "a", "b"},
			wantCode: 2,
			wantErr:  "html-sanitize: expected at most one FILE argument\n",
		},
		{
			name:     "missing input file",
			args:     []string{"-p", "formatting", "nosuch.html"},
			wantCode: 2,
			wantErr:  "html-sanitize: cannot read nosuch.html\n",
		},
		{
			name:     "malformed policy file",
			args:     []string{"-f", "p.json"},
			files:    map[string]string{"p.json": `[{`},
			wantCode: 2,
			wantErr:  "html-sanitize: policy file is not valid JSON\n",
		},
		{
			name:     "step with two builder methods",
			args:     []string{"-f", "p.json"},
			files:    map[string]string{"p.json": `[{"allowElements": ["a"], "disallowElements": ["b"]}]`},
			wantCode: 2,
			wantErr:  "html-sanitize: a policy step names more than one builder method\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range tt.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			var stdout, stderr bytes.Buffer
			code := run(tt.args, dir, strings.NewReader(tt.stdin), &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("exit status = %d, want %d", code, tt.wantCode)
			}
			if got := stdout.String(); got != tt.wantOut {
				t.Errorf("stdout = %q, want %q", got, tt.wantOut)
			}
			if got := stderr.String(); got != tt.wantErr {
				t.Errorf("stderr = %q, want %q", got, tt.wantErr)
			}
		})
	}
}

// failingWriter fails every write.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestFlushReportsWriteErrors(t *testing.T) {
	out, errOut := bytes.NewBufferString("x"), bytes.NewBufferString("y")
	var sink bytes.Buffer
	if err := flush(failingWriter{}, &sink, out, errOut); err == nil || err.Error() != "writing standard output: disk full" {
		t.Errorf("stdout failure: got %v", err)
	}
	if err := flush(&sink, failingWriter{}, out, errOut); err == nil || err.Error() != "writing standard error: disk full" {
		t.Errorf("stderr failure: got %v", err)
	}
	sink.Reset()
	if err := flush(&sink, &sink, out, errOut); err != nil || sink.String() != "xy" {
		t.Errorf("success: got %v, %q", err, sink.String())
	}
}
