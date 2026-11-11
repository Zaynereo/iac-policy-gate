package catalog

import "strings"

// Documented fail-closed exceptions: resources outside the policy catalog that may appear
// in real plans without triggering PLAN-UNSUPPORTED-RESOURCE.
var exemptResourceTypes = map[string]struct{}{
	"terraform_data": {},
}

// IsCatalogExempt reports whether a resource change is deliberately excluded from catalog enforcement.
func IsCatalogExempt(typ, mode string) bool {
	if strings.EqualFold(strings.TrimSpace(mode), "data") {
		return true
	}
	_, ok := exemptResourceTypes[typ]
	return ok
}
