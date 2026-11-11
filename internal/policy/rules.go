package policy

// RuleID values are stable identifiers for findings and tests.
const (
	RulePlanFormatUnsupported = "PLAN-FORMAT-UNSUPPORTED"
	RulePlanSchemaMissing     = "PLAN-SCHEMA-MISSING"
	RulePlanUnknownValue      = "PLAN-UNKNOWN-VALUE"
	RulePlanUnsupportedResource = "PLAN-UNSUPPORTED-RESOURCE"
	RulePlanUnsupportedAction = "PLAN-UNSUPPORTED-ACTION"

	RuleAWSSGIngressIPv4Public = "AWS-SG-INGRESS-IPV4-PUBLIC"
	RuleAWSSGIngressIPv6Public = "AWS-SG-INGRESS-IPV6-PUBLIC"
	RuleAWSS3EncryptionMissing = "AWS-S3-ENCRYPTION-MISSING"
	RuleAWSS3PublicAccessOpen  = "AWS-S3-PUBLIC-ACCESS-OPEN"
	RuleAWSTagEnvMissing       = "AWS-TAG-ENV-MISSING"
	RuleAWSSecretLiteralAfter  = "AWS-SECRET-LITERAL-AFTER"
)

// Severity for findings.
type Severity string

const (
	SeverityError Severity = "error"
	SeverityWarn  Severity = "warn"
)
