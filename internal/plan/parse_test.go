package plan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseJSON_malformed(t *testing.T) {
	_, err := ParseJSON([]byte(`{"format_version":`))
	if err == nil {
		t.Fatal("expected error")
	}
	if pe, ok := err.(*ParseError); !ok || pe.Code != "PLAN_MALFORMED" {
		t.Fatalf("got %v", err)
	}
}

func TestParseJSON_missingResourceChanges(t *testing.T) {
	_, err := ParseJSON([]byte(`{"format_version":"1.2"}`))
	if err == nil {
		t.Fatal("expected error")
	}
	pe := err.(*ParseError)
	if pe.Code != "PLAN_SCHEMA_MISSING" {
		t.Fatalf("code=%s", pe.Code)
	}
}

func TestParseJSON_unsupportedVersion(t *testing.T) {
	_, err := ParseJSON([]byte(`{"format_version":"2.0","resource_changes":[]}`))
	if err == nil {
		t.Fatal("expected error")
	}
	if pe := err.(*ParseError); pe.Code != "PLAN_FORMAT_UNSUPPORTED" {
		t.Fatalf("code=%s", pe.Code)
	}
}

func TestParseJSON_tooDeep(t *testing.T) {
	depth := 70
	// Valid top-level plan with deeply nested object under a custom meta field (still walks full tree).
	inner := "1"
	for i := 0; i < depth; i++ {
		inner = `{"k":` + inner + `}`
	}
	doc := `{"format_version":"1.2","resource_changes":[],"_deep":` + inner + `}`
	_, err := ParseJSON([]byte(doc))
	if err == nil {
		t.Fatal("expected depth error")
	}
	if pe := err.(*ParseError); pe.Code != "PLAN_TOO_DEEP" {
		t.Fatalf("code=%s msg=%s", pe.Code, pe.Message)
	}
}

func TestReadPlan_fixturePass(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "fixtures", "pass_clean.synthetic.json")
	doc, err := ReadPlan(path)
	if err != nil {
		t.Fatal(err)
	}
	if doc.FormatVersion != "1.2" {
		t.Fatalf("version %s", doc.FormatVersion)
	}
}

func TestReadPlan_stdin(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	go func() {
		_, _ = w.Write([]byte(`{"format_version":"1.0","resource_changes":[]}`))
		_ = w.Close()
	}()
	doc, err := ReadPlan("-")
	if err != nil {
		t.Fatal(err)
	}
	if doc.FormatVersion != "1.0" {
		t.Fatal(doc.FormatVersion)
	}
}

func TestClassifyActions(t *testing.T) {
	cases := []struct {
		in   []string
		want ActionKind
	}{
		{[]string{"no-op"}, ActionNoop},
		{[]string{"create"}, ActionCreate},
		{[]string{"update"}, ActionUpdate},
		{[]string{"delete"}, ActionDelete},
		{[]string{"delete", "create"}, ActionReplace},
		{[]string{"create", "delete"}, ActionReplace},
		{[]string{"read"}, ActionUnsupported},
		{nil, ActionUnsupported},
	}
	for _, c := range cases {
		if got := ClassifyActions(c.in); got != c.want {
			t.Fatalf("%v -> %s want %s", c.in, got, c.want)
		}
	}
}
