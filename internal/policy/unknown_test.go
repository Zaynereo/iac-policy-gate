package policy

import (
	"encoding/json"
	"testing"

	"github.com/Zaynereo/iac-policy-gate/internal/plan"
)

func TestWalkUnknown_missingAfterUnknownOK(t *testing.T) {
	rc := plan.ResourceChange{
		Address: "aws_security_group.x",
		Type:    "aws_security_group",
		Change: plan.ChangeBlock{
			Actions:      []string{"create"},
			AfterUnknown: nil,
		},
	}
	var fs []Finding
	if err := walkUnknown(rc.Type, rc.Change.AfterUnknown, rc.Address, "create", &fs); err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("expected no findings: %v", fs)
	}
}

func TestWalkUnknown_malformedAfterUnknown(t *testing.T) {
	var fs []Finding
	err := walkUnknown("aws_security_group", json.RawMessage(`{`), "aws_security_group.x", "create", &fs)
	if err == nil {
		t.Fatal("expected parse error on malformed after_unknown JSON")
	}
}

func TestWalkUnknown_arrayElementMarker(t *testing.T) {
	raw := json.RawMessage(`{"ingress":[{"cidr_blocks":[true]}]}`)
	var fs []Finding
	if err := walkUnknown("aws_security_group", raw, "aws_security_group.x", "create", &fs); err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].RuleID != RulePlanUnknownValue {
		t.Fatalf("got %v", fs)
	}
	if fs[0].Path == "" {
		t.Fatal("expected path")
	}
}
