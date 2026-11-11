# iac-policy-gate

Go CLI portfolio project (**Habib Noor**) for infrastructure / backend / security interviews. It evaluates a **documented, minimal policy set** over **Terraform / OpenTofu `show -json` plan JSON** using **synthetic fixtures only**—no cloud credentials, no `apply`, no deploy, and no paid services.

> **Evidence model:** Core validation uses **hand-authored synthetic plan JSON** (see `testdata/fixtures/*.synthetic.json`). These files are **not** real AWS account plans and must not be treated as live-state or cloud audit evidence.

## Quick start

```bash
go build -o iac-policy-gate ./cmd/iac-policy-gate

# Text findings (exit 0 = pass, 1 = policy fail, 3 = plan parse fail-closed)
./iac-policy-gate -plan testdata/fixtures/pass_clean.synthetic.json

# JSON output
./iac-policy-gate -json -plan testdata/fixtures/fail_sg_ipv4_public.synthetic.json
```

Docker (from repo root):

```bash
docker build -t iac-policy-gate:local .
docker run --rm -v "$PWD/testdata/fixtures:/fixtures:ro" iac-policy-gate:local \
  -plan /fixtures/pass_clean.synthetic.json
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Policy passed (warnings such as `delete` review may be present) |
| `1` | One or more **error**-severity findings |
| `2` | CLI usage error |
| `3` | Fail-closed plan read/parse (unsupported `format_version`, missing required fields, size/depth limits) |
| `4` | Internal error |

## Architecture

```text
stdin/file ──► plan.Parse (bounded size + depth) ──► policy.Evaluate ──► text/JSON report
                      │                                    │
                      └ format_version exact match         └ stable Rule IDs + deterministic sort
```

Packages:

- `internal/plan` — JSON ingestion, `format_version` gate, action classification
- `internal/catalog` — closed **AWS-shaped** resource list (fail closed on other `aws_*` types)
- `internal/policy` — rules, findings, evaluation
- `cmd/iac-policy-gate` — CLI

## Documented policy catalog (exact coverage)

| Resource type | Rule IDs | Attributes inspected |
|---------------|----------|----------------------|
| `aws_security_group` | `AWS-SG-INGRESS-IPV4-PUBLIC`, `AWS-SG-INGRESS-IPV6-PUBLIC` | `ingress[].cidr_blocks`, `ingress[].ipv6_cidr_blocks` |
| `aws_s3_bucket_server_side_encryption_configuration` | `AWS-S3-ENCRYPTION-MISSING` | `rule[].apply_server_side_encryption_by_default.sse_algorithm` |
| `aws_s3_bucket_public_access_block` | `AWS-S3-PUBLIC-ACCESS-OPEN` | All four block booleans must be `true` |
| `aws_s3_bucket` | `AWS-TAG-ENV-MISSING`, `AWS-S3-PUBLIC-ACCESS-OPEN`, `AWS-SECRET-LITERAL-AFTER` | `tags.Environment`, `acl`, conservative secret **field names** in `after` |
| (plan-wide) | `PLAN-UNKNOWN-VALUE` | Relevant `after_unknown` paths per catalog type |
| (plan-wide) | `PLAN-UNSUPPORTED-RESOURCE` | Any `aws_*` type **not** in the catalog |
| (plan-wide) | `PLAN-UNSUPPORTED-ACTION` | Unknown action tuples; `delete` emits **warn** and skips `after` checks |

**Supported `format_version` (exact, not prefix):** `1.0`, `1.1`, `1.2`

**Change actions:** `no-op` (skip), `create` / `update` / replace (`delete`+`create`), `delete` (warn + skip `after` rules). Unsupported sequences fail closed.

**Secrets:** Conservative literal scan on documented field names (`password`, `api_key`, …)—**not** a “detect all secrets” claim. Empty / `(sensitive value)` placeholders are ignored.

## Parser limits (not full Terraform schema validation)

| Limit | Value |
|-------|-------|
| Max plan bytes | 10 MiB (`internal/limits`) |
| Max JSON nesting depth | 64 |

Invalid JSON, unsupported format versions, and missing `resource_changes` fail closed with exit `3`.

## Optional Terraform fmt/validate

`modules/terraform_data/` is a **provider-free** stub for optional local/CI `terraform fmt` / `validate` only (see `.github/workflows/ci.yml`). No provider download or network init in the main policy path.

## Design decisions

1. **Fail closed** on unknown `format_version`, schema gaps, catalog-unknown `aws_*` resources, and security-relevant `after_unknown`.
2. **Closed catalog** keeps the interview scope small and testable; expanding coverage is explicit code change.
3. **Determinism:** sorted findings, stable rule IDs, synthetic fixtures only in CI/unit tests.
4. **No cloud SDK** at runtime—pure JSON in memory.

## Limitations

- Does **not** validate complete Terraform provider schemas or evaluate real AWS accounts.
- Does **not** run `terraform plan` or access remote state.
- Secret detection is **name-based and conservative**; structured secret scanning is out of scope.
- Non-AWS resources are ignored (not in policy scope).

## Tests

```bash
go test -race ./...
```

Fixtures are named `*.synthetic.json` and include `_fixture_meta.synthetic` where applicable.

## AI assistance disclosure

This repository was **built with AI coding assistance** (Cursor Cloud Agent) as an interview portfolio artifact. It should **not** be claimed that Habib personally reviewed every line or ran production cloud validation unless he has done so independently.

## License

MIT — see [LICENSE](LICENSE).
