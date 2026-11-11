package policy

import (
	"encoding/json"
	"sort"
)

// Finding is a deterministic policy result for one rule violation or advisory.
type Finding struct {
	RuleID   string   `json:"rule_id"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	Resource string   `json:"resource,omitempty"`
	Action   string   `json:"action,omitempty"`
	Path     string   `json:"path,omitempty"`
}

// Report holds sorted findings for text/JSON output.
type Report struct {
	PlanLabel string    `json:"plan_label,omitempty"`
	Passed    bool      `json:"passed"`
	Findings  []Finding `json:"findings"`
}

// SortFindings orders findings deterministically by rule_id, resource, path, message.
func SortFindings(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Resource != b.Resource {
			return a.Resource < b.Resource
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Message < b.Message
	})
}

// JSONBytes returns indented JSON for the report (deterministic key order via struct tags).
func (r Report) JSONBytes() ([]byte, error) {
	cp := r
	SortFindings(cp.Findings)
	return json.MarshalIndent(cp, "", "  ")
}
