package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Zaynereo/iac-policy-gate/internal/plan"
)

func loadFixture(t *testing.T, name string) *plan.Document {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "fixtures", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(name, "synthetic") {
		t.Fatal("fixture name must contain synthetic")
	}
	doc, err := plan.ParseJSON(data)
	if err != nil {
		// Some fixtures are parse-fail by design
		t.Fatalf("parse %s: %v", name, err)
	}
	return doc
}

func TestEvaluate_passClean(t *testing.T) {
	doc := loadFixture(t, "pass_clean.synthetic.json")
	rep := Evaluate(doc)
	if !rep.Passed {
		t.Fatalf("expected pass: %+v", rep.Findings)
	}
}

func TestEvaluate_ruleIDs(t *testing.T) {
	cases := []struct {
		file   string
		pass   bool
		rules  []string
	}{
		{"fail_sg_ipv4_public.synthetic.json", false, []string{RuleAWSSGIngressIPv4Public}},
		{"fail_sg_ipv6_public.synthetic.json", false, []string{RuleAWSSGIngressIPv6Public}},
		{"fail_s3_encryption.synthetic.json", false, []string{RuleAWSS3EncryptionMissing}},
		{"fail_s3_public_access.synthetic.json", false, []string{RuleAWSS3PublicAccessOpen}},
		{"fail_tags_env.synthetic.json", false, []string{RuleAWSTagEnvMissing}},
		{"fail_secret_literal.synthetic.json", false, []string{RuleAWSSecretLiteralAfter}},
		{"fail_unknown_ingress.synthetic.json", false, []string{RulePlanUnknownValue}},
		{"fail_unsupported_aws_type.synthetic.json", false, []string{RulePlanUnsupportedResource}},
		{"fail_s3_acl_public.synthetic.json", false, []string{RuleAWSS3PublicAccessOpen}},
		{"fail_wrong_type_block.synthetic.json", false, []string{RuleAWSS3PublicAccessOpen}},
		{"pass_replace.synthetic.json", true, nil},
		{"warn_delete.synthetic.json", true, nil},
		{"fail_unsupported_action.synthetic.json", false, []string{RulePlanUnsupportedAction}},
		{"fail_non_aws_catalog.synthetic.json", false, []string{RulePlanUnsupportedResource}},
		{"fail_noop_public_sg.synthetic.json", false, []string{RuleAWSSGIngressIPv4Public}},
		{"fail_unknown_nested_array.synthetic.json", false, []string{RulePlanUnknownValue}},
		{"pass_exempt_data_mode.synthetic.json", true, nil},
		{"pass_exempt_terraform_data.synthetic.json", true, nil},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			doc := loadFixture(t, c.file)
			rep := Evaluate(doc)
			if rep.Passed != c.pass {
				t.Fatalf("passed=%v findings=%v", rep.Passed, rep.Findings)
			}
			seen := map[string]bool{}
			for _, f := range rep.Findings {
				seen[f.RuleID] = true
			}
			for _, want := range c.rules {
				if !seen[want] {
					t.Fatalf("missing rule %s in %v", want, rep.Findings)
				}
			}
		})
	}
}

func TestReport_JSONDeterministic(t *testing.T) {
	doc := loadFixture(t, "fail_sg_ipv4_public.synthetic.json")
	rep := Evaluate(doc)
	a, err := rep.JSONBytes()
	if err != nil {
		t.Fatal(err)
	}
	b, err := rep.JSONBytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("non-deterministic json")
	}
	var m map[string]any
	if err := json.Unmarshal(a, &m); err != nil {
		t.Fatal(err)
	}
}

func TestEvaluate_deleteWarningOnly(t *testing.T) {
	doc := loadFixture(t, "warn_delete.synthetic.json")
	rep := Evaluate(doc)
	if !rep.Passed {
		t.Fatal("delete should warn not fail")
	}
	for _, f := range rep.Findings {
		if f.Severity != SeverityWarn {
			t.Fatalf("want warn got %s", f.Severity)
		}
	}
}
