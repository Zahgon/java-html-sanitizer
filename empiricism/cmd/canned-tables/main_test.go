// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

package main

import (
	"bytes"
	"os"
	"testing"
)

// TestGeneratedTablesAreCurrent checks that the checked-in tables are what
// the generator makes of the checked-in observations.
func TestGeneratedTablesAreCurrent(t *testing.T) {
	in, err := os.ReadFile("../../canned-data.json")
	if err != nil {
		t.Fatal(err)
	}
	obj, err := parseObject(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := generate(obj)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../../../sanitizer/html_element_tables_canned.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("sanitizer/html_element_tables_canned.go is stale: run go generate ./sanitizer")
	}
}
