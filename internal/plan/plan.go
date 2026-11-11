package plan

import "encoding/json"

// Document is a minimal subset of Terraform/OpenTofu `terraform show -json` plan output
// that this tool evaluates. It is not a full Terraform schema.
type Document struct {
	FormatVersion string            `json:"format_version"`
	TerraformVer  string            `json:"terraform_version,omitempty"`
	ResourceChanges []ResourceChange `json:"resource_changes"`
}

// ResourceChange mirrors the documented resource_changes entry shape.
type ResourceChange struct {
	Address      string          `json:"address"`
	Type         string          `json:"type"`
	Name         string          `json:"name"`
	ProviderName string          `json:"provider_name,omitempty"`
	Mode         string          `json:"mode,omitempty"`
	Change       ChangeBlock     `json:"change"`
}

// ChangeBlock holds planned change actions and values.
type ChangeBlock struct {
	Actions      []string        `json:"actions"`
	Before       json.RawMessage `json:"before"`
	After        json.RawMessage `json:"after"`
	AfterUnknown json.RawMessage `json:"after_unknown"`
	BeforeSensitive json.RawMessage `json:"before_sensitive,omitempty"`
	AfterSensitive  json.RawMessage `json:"after_sensitive,omitempty"`
}

// ActionKind classifies Terraform change actions for policy semantics.
type ActionKind string

const (
	ActionNoop        ActionKind = "noop"
	ActionCreate      ActionKind = "create"
	ActionUpdate      ActionKind = "update"
	ActionDelete      ActionKind = "delete"
	ActionReplace     ActionKind = "replace"
	ActionUnsupported ActionKind = "unsupported"
)

// ClassifyActions maps the actions array to a single semantic kind (fail-closed on unknown combos).
func ClassifyActions(actions []string) ActionKind {
	if len(actions) == 0 {
		return ActionUnsupported
	}
	only := func(want string) bool {
		if len(actions) != 1 {
			return false
		}
		return actions[0] == want
	}
	if only("no-op") {
		return ActionNoop
	}
	if only("create") {
		return ActionCreate
	}
	if only("update") {
		return ActionUpdate
	}
	if only("delete") {
		return ActionDelete
	}
	if len(actions) == 2 {
		a, b := actions[0], actions[1]
		if (a == "delete" && b == "create") || (a == "create" && b == "delete") {
			return ActionReplace
		}
	}
	return ActionUnsupported
}
