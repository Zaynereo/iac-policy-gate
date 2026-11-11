# Interview notes — iac-policy-gate (Habib Noor portfolio)

**Purpose:** Walking document for infra / backend / security interviews. Evidence is **synthetic plan JSON only**—not a live AWS audit.

---

## 1. One-minute pitch

`iac-policy-gate` is a fail-closed Go CLI that ingests Terraform/OpenTofu plan JSON and returns deterministic policy findings before anything reaches an apply pipeline. It intentionally scopes to a **tiny AWS-shaped catalog** so rules, tests, and exit codes stay explainable in an interview. No cloud credentials, no provider plugins at runtime.

---

## 2. Command walkthrough (talk track)

```bash
go build -o iac-policy-gate ./cmd/iac-policy-gate
./iac-policy-gate -plan testdata/fixtures/pass_clean.synthetic.json
./iac-policy-gate -json -plan testdata/fixtures/fail_sg_ipv4_public.synthetic.json
echo $?   # 1 on policy fail, 3 on parse fail
```

Narrative: *“CI uploads the plan artifact; this binary gates merges with stable rule IDs that security and platform teams can track over time.”*

---

## 3. Architecture tradeoffs

| Choice | Why | Cost |
|--------|-----|------|
| Closed `aws_*` catalog | Fail closed on unknown types—no silent skip | Must extend catalog for new resources |
| Parse subset only | Fast, no provider graph | Not a substitute for `terraform validate` |
| `after_unknown` on relevant paths | Honest about unknown security fields | May false-fail plans that defer ingress to apply |
| Delete → warn only | Surfaces destructive changes without null `after` noise | Does not auto-approve deletes |
| 10 MiB / depth 64 bounds | DoS resistance on shared runners | Huge plans rejected |

---

## 4. Break experiments (intentional)

1. **Add `0.0.0.0/0` to SG fixture** → `AWS-SG-INGRESS-IPV4-PUBLIC`.
2. **Set `format_version` to `1.0-beta`** → parse fail (exact match, not prefix).
3. **Insert `aws_instance`** → `PLAN-UNSUPPORTED-RESOURCE`.
4. **Put literal in `password` attribute** → `AWS-SECRET-LITERAL-AFTER` (synthetic placeholder only).
5. **Nest JSON >64 deep** → `PLAN_TOO_DEEP`.

Run: `go test -race ./...` after each tweak; revert before commit unless extending tests.

---

## 5. Ownership proposals (how I’d run it on a team)

- **Platform eng:** owns parser limits, format version allowlist, CLI semver.
- **Security / GRC:** owns rule IDs, severity, exception workflow (out of scope here).
- **App teams:** fix plans or request catalog expansion via PR + synthetic fixture.
- **SRE:** wires gate into plan artifact stage (`terraform show -json` → gate → apply).

---

## 6. Thirty interview Q&As

1. **What problem does this solve?** Pre-apply guardrails on plan JSON with deterministic, automatable findings.
2. **Why plan JSON vs HCL?** Plans are the signed intent of what Terraform will do; JSON is easy to gate in CI without re-planning.
3. **Why fail closed?** Silent passes on unknown formats or resources create false confidence in security interviews and production.
4. **Why a closed catalog?** Bounded scope proves rule design; “support all AWS” is a different product.
5. **How do you handle `after_unknown`?** Flag security-relevant paths listed per resource type; ignore unrelated unknowns.
6. **What’s not validated?** Full provider schemas, computed fields outside paths, non-AWS resources.
7. **Exit code 0 with warnings?** Yes—`delete` emits warn for human/process review, not auto-approve.
8. **How are rule IDs used?** Metrics, allowlists, ticketing integrations (`AWS-SG-INGRESS-IPV4-PUBLIC`).
9. **Why synthetic fixtures?** Reproducible CI without cloud spend or credential risk.
10. **How do you label synthetics?** `*.synthetic.json` + `_fixture_meta.synthetic` in files.
11. **OpenTofu support?** Same `show -json` shape for the parsed subset; format versions explicitly listed.
12. **Why exact `format_version`?** Prevents `1.0` prefix matching `1.0.0` or prereleases incorrectly.
13. **Replacement detection?** `delete`+`create` action pair classified as `replace`.
14. **No-op handling?** Skipped—no planned change to evaluate.
15. **Unsupported actions?** Error finding—e.g. fictional `read` action in tests.
16. **IPv6 public rule?** `::/0` on `ipv6_cidr_blocks`.
17. **S3 encryption rule?** Requires non-empty `rule` with `sse_algorithm`.
18. **Public access block?** All four booleans must be `true` in planned `after`.
19. **Environment tag?** Required non-empty `tags.Environment` on `aws_s3_bucket` creates/updates.
20. **Secret literals?** Conservative field names only; not full entropy detection.
21. **Input bounds?** 10 MiB, nesting depth 64—documented in README.
22. **Race detector in CI?** `go test -race` catches concurrent map issues if we extend parser.
23. **Docker image?** Distroless static nonroot binary from Go 1.22.12.
24. **Why no providers in tests?** Keeps portfolio lean; optional `terraform_data` module only.
25. **How would you add RDS?** Extend `catalog.SupportedAWSTypes`, rules, and a synthetic fixture test.
26. **False positives on unknown ingress?** Tradeoff of fail-closed vs deferred rules—tune paths or allowlist.
27. **JSON output contract?** `passed`, sorted `findings` with `rule_id`, `severity`, `resource`, `path`.
28. **How is determinism tested?** Double `JSONBytes()` comparison in `eval_test.go`.
29. **What would you do in prod that’s missing here?** OPA integration, signed plans, exception DB, multi-tenant RBAC.
30. **Did Habib run this in AWS?** README states AI-built portfolio; live cloud validation is a separate exercise.

---

## 7. Security talking points

- **Fail closed** beats “best effort” for policy gates.
- **No credentials** in CLI reduces blast radius for a demo repo.
- **Conservative secret names** avoid claiming magic detection.
- **Delete warnings** acknowledge destructive ops without pretending `after` values exist.

---

## 8. Known caveats (honest)

- Catalog is **tiny** by design.
- `terraform fmt/validate` CI steps are optional / may be skipped if Terraform isn’t installed on a given runner context.
- Docker build wasn’t executed in every local sandbox; CI job `docker` is the reference check.

---

## 9. References in repo

- Rule IDs: `internal/policy/rules.go`
- Catalog: `internal/catalog/catalog.go`
- Parser: `internal/plan/parse.go`, `internal/limits/limits.go`
- Fixtures: `testdata/fixtures/`
