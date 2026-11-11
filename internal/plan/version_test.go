package plan

import "testing"

func TestValidateFormatVersion_exactOnly(t *testing.T) {
	for _, v := range SupportedFormatVersions {
		if err := ValidateFormatVersion(v); err != nil {
			t.Fatalf("expected %q supported: %v", v, err)
		}
	}
	reject := []string{"", "1.0.0", "1.0-rc1", "1.3", "2.0", "1.02.0"}
	for _, v := range reject {
		if err := ValidateFormatVersion(v); err == nil {
			t.Fatalf("expected reject %q", v)
		}
	}
}
