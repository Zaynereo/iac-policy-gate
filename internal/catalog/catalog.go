// Package catalog documents the AWS-shaped resource subset evaluated by policy rules.
package catalog

// ResourceSpec describes one supported Terraform resource type and which attributes rules inspect.
type ResourceSpec struct {
	Type        string
	Description string
	Attributes  []string // documented paths rules may read (not exhaustive Terraform schema)
}

// SupportedAWSTypes is the closed policy catalog for managed resources (any other type fails closed unless exempt).
var SupportedAWSTypes = map[string]ResourceSpec{
	"aws_security_group": {
		Type:        "aws_security_group",
		Description: "VPC security group ingress (IPv4/IPv6 public CIDR checks)",
		Attributes:  []string{"ingress", "ingress.cidr_blocks", "ingress.ipv6_cidr_blocks"},
	},
	"aws_s3_bucket": {
		Type:        "aws_s3_bucket",
		Description: "S3 bucket tags and coarse public ACL flags when present on bucket object",
		Attributes:  []string{"tags", "acl", "grant"},
	},
	"aws_s3_bucket_server_side_encryption_configuration": {
		Type:        "aws_s3_bucket_server_side_encryption_configuration",
		Description: "Bucket SSE rules (algorithm must be present when managed)",
		Attributes:  []string{"rule", "rule.apply_server_side_encryption_by_default"},
	},
	"aws_s3_bucket_public_access_block": {
		Type:        "aws_s3_bucket_public_access_block",
		Description: "Account/bucket public access block booleans",
		Attributes:  []string{
			"block_public_acls",
			"block_public_policy",
			"ignore_public_acls",
			"restrict_public_buckets",
		},
	},
}

// IsCatalogType reports whether typ is explicitly supported (exact type string).
func IsCatalogType(typ string) bool {
	_, ok := SupportedAWSTypes[typ]
	return ok
}

// IsAWSProviderType is a coarse filter for provider-scoped unsupported detection.
func IsAWSProviderType(typ string) bool {
	return len(typ) > 4 && typ[:4] == "aws_"
}
