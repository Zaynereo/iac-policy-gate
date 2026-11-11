package output

import (
	"fmt"
	"strings"

	"github.com/Zaynereo/iac-policy-gate/internal/policy"
)

// WriteText renders deterministic line-oriented findings.
func WriteText(r policy.Report) string {
	var b strings.Builder
	if r.PlanLabel != "" {
		fmt.Fprintf(&b, "plan: %s\n", r.PlanLabel)
	}
	if r.Passed {
		b.WriteString("result: PASS\n")
	} else {
		b.WriteString("result: FAIL\n")
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "[%s] severity=%s", f.RuleID, f.Severity)
		if f.Resource != "" {
			fmt.Fprintf(&b, " resource=%s", f.Resource)
		}
		if f.Action != "" {
			fmt.Fprintf(&b, " action=%s", f.Action)
		}
		if f.Path != "" {
			fmt.Fprintf(&b, " path=%s", f.Path)
		}
		fmt.Fprintf(&b, " message=%q\n", f.Message)
	}
	if len(r.Findings) == 0 {
		b.WriteString("findings: (none)\n")
	}
	return b.String()
}
