package plan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Zaynereo/iac-policy-gate/internal/limits"
)

// ParseError indicates fail-closed plan ingestion errors.
type ParseError struct {
	Code    string
	Message string
}

func (e *ParseError) Error() string {
	return e.Message
}

// ReadPlan reads up to limits.MaxPlanBytes from path ("-" for stdin) and parses a plan document.
func ReadPlan(path string) (*Document, error) {
	var r io.Reader
	if path == "-" {
		r = io.LimitReader(os.Stdin, limits.MaxPlanBytes+1)
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, &ParseError{Code: "PLAN_READ", Message: err.Error()}
		}
		defer f.Close()
		r = io.LimitReader(f, limits.MaxPlanBytes+1)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, &ParseError{Code: "PLAN_READ", Message: err.Error()}
	}
	if int64(len(data)) > limits.MaxPlanBytes {
		return nil, &ParseError{Code: "PLAN_TOO_LARGE", Message: fmt.Sprintf("plan exceeds %d byte limit", limits.MaxPlanBytes)}
	}
	return ParseJSON(data)
}

// ParseJSON parses plan JSON with documented bounds. It does not validate full Terraform schemas.
func ParseJSON(data []byte) (*Document, error) {
	if !json.Valid(data) {
		return nil, &ParseError{Code: "PLAN_MALFORMED", Message: "invalid JSON"}
	}
	var raw any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, &ParseError{Code: "PLAN_MALFORMED", Message: err.Error()}
	}
	if err := checkDepth(raw, 0); err != nil {
		return nil, err
	}
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, &ParseError{Code: "PLAN_MALFORMED", Message: err.Error()}
	}
	if err := ValidateFormatVersion(doc.FormatVersion); err != nil {
		return nil, &ParseError{Code: "PLAN_FORMAT_UNSUPPORTED", Message: err.Error()}
	}
	if doc.ResourceChanges == nil {
		return nil, &ParseError{Code: "PLAN_SCHEMA_MISSING", Message: "resource_changes is required"}
	}
	return &doc, nil
}

func checkDepth(v any, depth int) error {
	if depth > limits.MaxJSONDepth {
		return &ParseError{Code: "PLAN_TOO_DEEP", Message: fmt.Sprintf("JSON nesting exceeds %d levels", limits.MaxJSONDepth)}
	}
	switch t := v.(type) {
	case map[string]any:
		for _, child := range t {
			if err := checkDepth(child, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range t {
			if err := checkDepth(child, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
