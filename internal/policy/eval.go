package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Zaynereo/iac-policy-gate/internal/catalog"
	"github.com/Zaynereo/iac-policy-gate/internal/plan"
)

// Evaluate runs the documented policy set over a parsed plan (synthetic or real-shaped JSON).
func Evaluate(doc *plan.Document) Report {
	var findings []Finding
	for _, rc := range doc.ResourceChanges {
		if catalog.IsCatalogExempt(rc.Type, rc.Mode) {
			continue
		}
		action := plan.ClassifyActions(rc.Change.Actions)
		if action == plan.ActionUnsupported {
			findings = append(findings, Finding{
				RuleID:   RulePlanUnsupportedAction,
				Severity: SeverityError,
				Message:  fmt.Sprintf("unsupported action sequence %v", rc.Change.Actions),
				Resource: rc.Address,
				Action:   strings.Join(rc.Change.Actions, ","),
			})
			continue
		}
		actionStr := string(action)
		switch action {
		case plan.ActionDelete:
			findings = append(findings, Finding{
				RuleID:   RulePlanUnsupportedAction,
				Severity: SeverityWarn,
				Message:  "delete action requires explicit operator review (not auto-approved)",
				Resource: rc.Address,
				Action:   actionStr,
			})
			continue
		}

		if !catalog.IsCatalogType(rc.Type) {
			findings = append(findings, Finding{
				RuleID:   RulePlanUnsupportedResource,
				Severity: SeverityError,
				Message:  fmt.Sprintf("resource type %q is outside the documented catalog (fail closed)", rc.Type),
				Resource: rc.Address,
				Action:   actionStr,
			})
			continue
		}

		values := effectiveChangeValues(rc.Change)

		if err := walkUnknown(rc.Type, rc.Change.AfterUnknown, rc.Address, actionStr, &findings); err != nil {
			findings = append(findings, Finding{
				RuleID:   RulePlanUnknownValue,
				Severity: SeverityError,
				Message:  err.Error(),
				Resource: rc.Address,
				Action:   actionStr,
			})
		}

		afterObj, _ := parseObject(values)
		switch rc.Type {
		case "aws_security_group":
			checkSecurityGroup(rc, afterObj, actionStr, &findings)
		case "aws_s3_bucket_server_side_encryption_configuration":
			checkS3Encryption(rc, afterObj, actionStr, &findings)
		case "aws_s3_bucket_public_access_block":
			checkS3PublicAccessBlock(rc, afterObj, actionStr, &findings)
		case "aws_s3_bucket":
			checkS3BucketTagsAndSecrets(rc, afterObj, actionStr, &findings)
		}
		root := "after"
		if action == plan.ActionNoop {
			root = "effective"
		}
		scanSecretLiterals(values, rc.Address, actionStr, root, &findings)
	}

	SortFindings(findings)
	passed := true
	for _, f := range findings {
		if f.Severity == SeverityError {
			passed = false
		}
	}
	return Report{Passed: passed, Findings: findings}
}

func effectiveChangeValues(ch plan.ChangeBlock) json.RawMessage {
	if len(ch.After) > 0 && string(ch.After) != "null" {
		return ch.After
	}
	return ch.Before
}

func parseObject(raw json.RawMessage) (map[string]any, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, false
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, false
	}
	return m, true
}

func walkUnknown(typ string, raw json.RawMessage, address, action string, findings *[]Finding) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("after_unknown is not valid JSON")
	}
	paths := collectUnknownTrue(v, "")
	for _, p := range paths {
		if !isRelevantUnknownPath(typ, p) {
			continue
		}
		*findings = append(*findings, Finding{
			RuleID:   RulePlanUnknownValue,
			Severity: SeverityError,
			Message:  fmt.Sprintf("unknown after apply at %s", p),
			Resource: address,
			Action:   action,
			Path:     p,
		})
	}
	return nil
}

func isRelevantUnknownPath(typ, path string) bool {
	switch typ {
	case "aws_security_group":
		return path == "ingress" || strings.HasPrefix(path, "ingress[")
	case "aws_s3_bucket_server_side_encryption_configuration":
		return path == "rule" || strings.HasPrefix(path, "rule[")
	case "aws_s3_bucket_public_access_block":
		return path == "block_public_acls" || path == "block_public_policy" ||
			path == "ignore_public_acls" || path == "restrict_public_buckets"
	case "aws_s3_bucket":
		return path == "tags" || strings.HasPrefix(path, "tags.") || path == "acl"
	default:
		return false
	}
}

func collectUnknownTrue(v any, prefix string) []string {
	var out []string
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			if b, ok := child.(bool); ok && b {
				out = append(out, p)
				continue
			}
			out = append(out, collectUnknownTrue(child, p)...)
		}
	case []any:
		for i, child := range t {
			p := fmt.Sprintf("%s[%d]", prefix, i)
			if prefix == "" {
				p = fmt.Sprintf("[%d]", i)
			}
			if b, ok := child.(bool); ok && b {
				out = append(out, p)
				continue
			}
			out = append(out, collectUnknownTrue(child, p)...)
		}
	}
	return out
}

func checkSecurityGroup(rc plan.ResourceChange, after map[string]any, action string, findings *[]Finding) {
	ingress, ok := after["ingress"].([]any)
	if !ok {
		return
	}
	for i, item := range ingress {
		block, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if cidrs, ok := block["cidr_blocks"].([]any); ok {
			for _, c := range cidrs {
				if s, ok := c.(string); ok && s == "0.0.0.0/0" {
					*findings = append(*findings, Finding{
						RuleID:   RuleAWSSGIngressIPv4Public,
						Severity: SeverityError,
						Message:  "ingress allows public IPv4 0.0.0.0/0",
						Resource: rc.Address,
						Action:   action,
						Path:     fmt.Sprintf("ingress[%d].cidr_blocks", i),
					})
				}
			}
		}
		if cidrs, ok := block["ipv6_cidr_blocks"].([]any); ok {
			for _, c := range cidrs {
				if s, ok := c.(string); ok && (s == "::/0" || s == "0.0.0.0/0") {
					*findings = append(*findings, Finding{
						RuleID:   RuleAWSSGIngressIPv6Public,
						Severity: SeverityError,
						Message:  "ingress allows public IPv6 ::/0",
						Resource: rc.Address,
						Action:   action,
						Path:     fmt.Sprintf("ingress[%d].ipv6_cidr_blocks", i),
					})
				}
			}
		}
	}
}

func checkS3Encryption(rc plan.ResourceChange, after map[string]any, action string, findings *[]Finding) {
	rules, ok := after["rule"].([]any)
	if !ok || len(rules) == 0 {
		*findings = append(*findings, Finding{
			RuleID:   RuleAWSS3EncryptionMissing,
			Severity: SeverityError,
			Message:  "no server-side encryption rule in planned after values",
			Resource: rc.Address,
			Action:   action,
			Path:     "rule",
		})
		return
	}
	for i, item := range rules {
		block, ok := item.(map[string]any)
		if !ok {
			continue
		}
		def, _ := block["apply_server_side_encryption_by_default"].(map[string]any)
		if def == nil {
			*findings = append(*findings, Finding{
				RuleID:   RuleAWSS3EncryptionMissing,
				Severity: SeverityError,
				Message:  "encryption rule missing apply_server_side_encryption_by_default",
				Resource: rc.Address,
				Action:   action,
				Path:     fmt.Sprintf("rule[%d]", i),
			})
			continue
		}
		if algo, _ := def["sse_algorithm"].(string); algo == "" {
			*findings = append(*findings, Finding{
				RuleID:   RuleAWSS3EncryptionMissing,
				Severity: SeverityError,
				Message:  "sse_algorithm must be set (e.g. AES256, aws:kms)",
				Resource: rc.Address,
				Action:   action,
				Path:     fmt.Sprintf("rule[%d].apply_server_side_encryption_by_default.sse_algorithm", i),
			})
		}
	}
}

func checkS3PublicAccessBlock(rc plan.ResourceChange, after map[string]any, action string, findings *[]Finding) {
	checkBool := func(field string, want bool) {
		v, ok := after[field]
		if !ok {
			*findings = append(*findings, Finding{
				RuleID:   RuleAWSS3PublicAccessOpen,
				Severity: SeverityError,
				Message:  fmt.Sprintf("%s must be present in plan after values", field),
				Resource: rc.Address,
				Action:   action,
				Path:     field,
			})
			return
		}
		b, ok := v.(bool)
		if !ok {
			*findings = append(*findings, Finding{
				RuleID:   RuleAWSS3PublicAccessOpen,
				Severity: SeverityError,
				Message:  fmt.Sprintf("%s must be a boolean", field),
				Resource: rc.Address,
				Action:   action,
				Path:     field,
			})
			return
		}
		if b != want {
			*findings = append(*findings, Finding{
				RuleID:   RuleAWSS3PublicAccessOpen,
				Severity: SeverityError,
				Message:  fmt.Sprintf("%s=%v does not meet required %v", field, b, want),
				Resource: rc.Address,
				Action:   action,
				Path:     field,
			})
		}
	}
	checkBool("block_public_acls", true)
	checkBool("block_public_policy", true)
	checkBool("ignore_public_acls", true)
	checkBool("restrict_public_buckets", true)
}

func checkS3BucketTagsAndSecrets(rc plan.ResourceChange, after map[string]any, action string, findings *[]Finding) {
	tags, ok := after["tags"].(map[string]any)
	if !ok || tags == nil {
		*findings = append(*findings, Finding{
			RuleID:   RuleAWSTagEnvMissing,
			Severity: SeverityError,
			Message:  "tags map missing or null; Environment tag required",
			Resource: rc.Address,
			Action:   action,
			Path:     "tags",
		})
		return
	}
	env, _ := tags["Environment"].(string)
	if strings.TrimSpace(env) == "" {
		*findings = append(*findings, Finding{
			RuleID:   RuleAWSTagEnvMissing,
			Severity: SeverityError,
			Message:  "Environment tag must be non-empty",
			Resource: rc.Address,
			Action:   action,
			Path:     "tags.Environment",
		})
	}
	if acl, _ := after["acl"].(string); acl == "public-read" || acl == "public-read-write" {
		*findings = append(*findings, Finding{
			RuleID:   RuleAWSS3PublicAccessOpen,
			Severity: SeverityError,
			Message:  fmt.Sprintf("bucket acl %q exposes public access", acl),
			Resource: rc.Address,
			Action:   action,
			Path:     "acl",
		})
	}
}

func scanSecretLiterals(raw json.RawMessage, address, action, root string, findings *[]Finding) {
	if len(raw) == 0 || string(raw) == "null" {
		return
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return
	}
	walkStrings(v, root, func(path, s string) {
		seg := path
		if idx := strings.LastIndex(path, "."); idx >= 0 {
			seg = path[idx+1:]
		}
		if seg == "" {
			return
		}
		if !IsSecretFieldName(seg) {
			return
		}
		trim := strings.TrimSpace(s)
		if trim == "" || trim == "(sensitive value)" {
			return
		}
		// Conservative: non-empty literal in secret-named field
		*findings = append(*findings, Finding{
			RuleID:   RuleAWSSecretLiteralAfter,
			Severity: SeverityError,
			Message:  "non-empty literal in secret-named attribute (use references, not literals)",
			Resource: address,
			Action:   action,
			Path:     path,
		})
	})
}

func walkStrings(v any, prefix string, fn func(path, s string)) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			walkStrings(child, p, fn)
		}
	case []any:
		for i, child := range t {
			p := fmt.Sprintf("%s[%d]", prefix, i)
			walkStrings(child, p, fn)
		}
	case string:
		fn(prefix, t)
	}
}
