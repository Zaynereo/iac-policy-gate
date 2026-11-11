package plan

import (
	"fmt"
	"strconv"
	"strings"
)

// SupportedFormatVersions lists format_version values accepted by the parser (exact semantic match).
var SupportedFormatVersions = []string{"1.0", "1.1", "1.2"}

// ValidateFormatVersion returns an error if version is outside the documented supported set.
func ValidateFormatVersion(version string) error {
	version = strings.TrimSpace(version)
	if version == "" {
		return fmt.Errorf("format_version is required")
	}
	for _, v := range SupportedFormatVersions {
		if version == v {
			return nil
		}
	}
	// Reject arbitrary prefix matches (e.g. "1.0-beta") even if they start with a supported value.
	if strings.HasPrefix(version, "1.") {
		if _, err := parseSemverTriple(version); err == nil {
			return fmt.Errorf("format_version %q is not in supported set %v (exact match required)", version, SupportedFormatVersions)
		}
	}
	return fmt.Errorf("format_version %q is not in supported set %v", version, SupportedFormatVersions)
}

func parseSemverTriple(s string) ([3]int, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return [3]int{}, fmt.Errorf("not a three-part version")
	}
	var out [3]int
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return [3]int{}, err
		}
		out[i] = n
	}
	return out, nil
}
