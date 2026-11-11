package plan

import (
	"path/filepath"
	"testing"
)

func TestParse_fixtureFailClosed(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "fixtures")
	cases := []struct {
		file string
		code string
	}{
		{"fail_format_version.synthetic.json", "PLAN_FORMAT_UNSUPPORTED"},
		{"fail_missing_resource_changes.synthetic.json", "PLAN_SCHEMA_MISSING"},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			_, err := ReadPlan(filepath.Join(root, c.file))
			if err == nil {
				t.Fatal("expected error")
			}
			pe, ok := err.(*ParseError)
			if !ok || pe.Code != c.code {
				t.Fatalf("got %v", err)
			}
		})
	}
}
