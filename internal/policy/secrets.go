package policy

import "strings"

// secretFieldNames lists conservative exact attribute name matches (not a detect-all-secrets claim).
var secretFieldNames = map[string]struct{}{
	"password":       {},
	"secret":         {},
	"api_key":        {},
	"apikey":         {},
	"client_secret":  {},
	"private_key":    {},
	"access_key":     {},
	"master_password": {},
}

// IsSecretFieldName reports whether the final path segment is a documented secret-like field.
func IsSecretFieldName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	_, ok := secretFieldNames[name]
	return ok
}
