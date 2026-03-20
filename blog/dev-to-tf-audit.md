---
title: "I Built tf-audit: A Terraform Configuration Auditor with 55+ Security Rules"
published: true
description: "A Python CLI tool that scans your Terraform (.tf) files for security misconfigurations, naming violations, module quality issues, and best practices across AWS, Azure, and GCP."
tags: terraform, security, devops, python
cover_image: ""
---

## The Problem

You've written your Terraform configurations. They `terraform plan` successfully. They even `terraform apply` without errors. But are they **secure**? Are they following **best practices**?

Common Terraform misconfigurations that make it to production:
- S3 buckets with public ACLs
- Security groups open to `0.0.0.0/0`
- RDS instances publicly accessible
- IAM policies with wildcard `*` permissions
- Variables named `db_password` without `sensitive = true`
- Modules pulled from Git without version pinning

I built **tf-audit** to catch these issues before they become incidents.

## What is tf-audit?

**tf-audit** is a Python CLI tool that audits Terraform `.tf` files for security, naming, module quality, and best practices. It uses the `python-hcl2` library to properly parse HCL2 syntax and runs **55+ rules** across 7 categories.

```
╭─────────────── 🔍 tf-audit — Terraform Configuration Auditor ────────────────╮
│ 📂 Path:  ./infrastructure                                                   │
│ 📄 Files: 5 Terraform files                                                  │
│ 📦 Resources: 16 resources scanned                                           │
│ 🔌 Providers: aws, azurerm, tls                                              │
╰──────────────────────────────────────────────────────────────────────────────╯

  Grade: F  (0/100)

  Issue Summary:
    🔴 CRITICAL:  4
    🟠     HIGH:  14
    🟡   MEDIUM:  23
    🔵      LOW:  10
    ⚪     INFO:  4
```

## Architecture

```
tf_audit/
├── models.py            # Severity, Category, Issue, AuditReport
├── parser.py            # HCL2 parser → TfFile objects
├── analyzers/
│   ├── security_analyzer.py       # 20 rules (TF-SEC-*)
│   ├── naming_analyzer.py         # 8 rules (TF-NAM-*)
│   ├── module_analyzer.py         # 12 rules (TF-MOD-*)
│   └── best_practices_analyzer.py # 15 rules (TF-BP-*)
├── reporters/
│   ├── terminal_reporter.py   # Rich terminal output
│   └── export_reporter.py     # JSON, HTML, SARIF
├── cli.py               # Click CLI (scan, demo, rules)
└── demo.py              # Intentionally insecure Terraform
```

## The 7 Rule Categories

### 1. Security (20 rules)

The largest and most critical category. Detects misconfigurations across **AWS, Azure, and GCP**:

| Rule | Severity | What It Catches |
|------|----------|----------------|
| TF-SEC-002 | 🔴 CRITICAL | S3 bucket with public ACL |
| TF-SEC-003 | 🔴 CRITICAL | Security group allows 0.0.0.0/0 |
| TF-SEC-005 | 🔴 CRITICAL | RDS publicly accessible |
| TF-SEC-008 | 🔴 CRITICAL | Azure NSG allows all traffic |
| TF-SEC-010 | 🟠 HIGH | IAM policy with wildcard actions |
| TF-SEC-017 | 🟠 HIGH | tls_private_key stores secrets in state |

### 2. Naming Conventions (8 rules)

Enforces consistent `snake_case` naming across resources, variables, outputs, and modules. Catches generic names like `main`, `this`, `test`.

### 3. Module Quality (12 rules)

| Rule | What It Checks |
|------|---------------|
| TF-MOD-001 | Module source version pinning |
| TF-MOD-003 | Variable descriptions |
| TF-MOD-004 | Variable type constraints |
| TF-MOD-007 | required_providers block |
| TF-MOD-009 | Terraform version constraint |
| TF-MOD-010 | Backend configuration |
| TF-MOD-011 | State locking (DynamoDB for S3) |

### 4. Best Practices (15 rules)

Covers tagging, sensitive flags, `.gitignore`, file organization, and more.

## The HCL2 Parser

Instead of regex-based parsing, tf-audit uses `python-hcl2` for proper AST parsing:

```python
import hcl2, io

with open("main.tf") as f:
    parsed = hcl2.load(io.StringIO(f.read()))

# parsed = {
#   "resource": [{"aws_s3_bucket": [{"data": {"acl": "public-read"}}]}],
#   "variable": [{"region": {"type": "string"}}],
#   ...
# }
```

This gives us structured access to every resource, variable, output, module, and provider block — enabling precise analysis without false positives from string matching.

## Security Analyzer Deep Dive

Here's how the S3 public access check works:

```python
def _check_s3_public_access(res, issues):
    """TF-SEC-002: S3 bucket with public ACL."""
    if res.resource_type != "aws_s3_bucket":
        return
    acl = res.config.get("acl", "")
    if acl in ("public-read", "public-read-write", "authenticated-read"):
        issues.append(Issue(
            rule_id="TF-SEC-002",
            severity=Severity.CRITICAL,
            category=Category.SECURITY,
            message=f"S3 bucket '{res.name}' has public ACL: {acl}",
            suggestion="Set acl to 'private' and use aws_s3_bucket_public_access_block",
        ))
```

Each security check is a focused function that:
1. Filters to the relevant resource type
2. Inspects the specific configuration field
3. Creates an `Issue` with severity, suggestion, and documentation URL

## CI/CD Integration

tf-audit exports to **SARIF** format for native GitHub/GitLab code scanning integration:

```yaml
# GitHub Actions
- name: Terraform Security Audit
  run: |
    pip install tf-audit
    tf-audit scan ./infrastructure --format sarif --output results.sarif --fail-on critical

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

The `--fail-on` flag makes the pipeline exit with code 1 if issues at the specified severity or above are found.

## Quick Start

```bash
# Install
pip install -e .

# Try the demo (intentionally insecure Terraform)
tf-audit demo

# Scan your infrastructure
tf-audit scan ./infrastructure --verbose

# Export JSON report
tf-audit scan . --format json --output report.json

# CI/CD: fail on critical issues
tf-audit scan . --fail-on critical

# List all 55+ rules
tf-audit rules
```

## Try the Demo

The `demo` command creates a realistic multi-cloud infrastructure project with **intentional misconfigurations** spanning AWS, Azure, and GCP:

```bash
$ tf-audit demo

🎪 Creating demo Terraform project with intentional issues...

  Grade: F  (0/100)

  Issue Summary:
    🔴 CRITICAL:  4    # Public S3, open SGs, public RDS, open NSG
    🟠     HIGH: 14    # Unencrypted storage, IAM wildcards, HTTP listeners
    🟡   MEDIUM: 23    # Missing tags, descriptions, Key Vault config
    🔵      LOW: 10    # Naming conventions, generic names
    ⚪     INFO:  4    # VPC flow logs, WAF reminders
```

## Test Suite

64 pytest tests covering all modules:

```
tests/test_models.py      — 10 tests (enums, dataclasses, score calculation)
tests/test_parser.py      — 10 tests (HCL2 parsing, resource extraction)
tests/test_security.py    — 11 tests (all security rule categories)
tests/test_naming.py      —  6 tests (snake_case, generics, hyphens)
tests/test_module.py      —  7 tests (versions, descriptions, backend)
tests/test_best_practices.py — 6 tests (tags, sensitive, gitignore)
tests/test_cli.py         — 14 tests (scan, demo, rules, export formats)
```

## What's Next

- **Custom rule configuration** via `.tf-audit.yaml`
- **Terraform plan JSON** analysis (post-plan validation)
- **Auto-fix** generation for common issues
- **Policy-as-code** compliance frameworks (CIS, SOC2)

## Links

- **GitHub**: [github.com/SanjaySundarMurthy/tf-audit](https://github.com/SanjaySundarMurthy/tf-audit)
- **Stack**: Python, Click, Rich, python-hcl2

---

*tf-audit is part of my DevOps CLI toolkit series. Previously: [helm-doctor](https://github.com/SanjaySundarMurthy/helm-doctor), [kube-netpol](https://github.com/SanjaySundarMurthy/kube-netpol), [policy-guard](https://github.com/SanjaySundarMurthy/policy-guard).*
