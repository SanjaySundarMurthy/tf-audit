# tf-audit

**Terraform Configuration Auditor & Security Scanner** — 55+ rules for security misconfigurations, naming conventions, module quality, and best practices across AWS, Azure, and GCP.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Features

- **20 Security Rules** — S3 encryption, public databases, open security groups, IAM wildcards, Key Vault misconfigs
- **8 Naming Convention Rules** — snake_case enforcement for resources, variables, outputs, modules
- **12 Module Quality Rules** — Version pinning, variable descriptions, type constraints, backend config
- **15+ Best Practice Rules** — Tagging, sensitive flags, .gitignore, file organization
- **Multi-Cloud** — AWS, Azure, and GCP resource support
- **Multiple Export Formats** — Terminal (Rich), JSON, HTML, SARIF
- **CI/CD Integration** — `--fail-on` flag for pipeline quality gates
- **Demo Mode** — Try instantly with intentionally insecure Terraform files

## Installation

```bash
pip install -e .
```

## Quick Start

```bash
# Scan a Terraform directory
tf-audit scan ./infrastructure

# Run the demo
tf-audit demo

# Verbose output with fix suggestions
tf-audit scan . --verbose

# Export as JSON for CI/CD
tf-audit scan . --format json --output report.json

# Fail CI if critical issues found
tf-audit scan . --fail-on critical

# List all rules
tf-audit rules
```

## Commands

| Command | Description |
|---------|-------------|
| `tf-audit scan <path>` | Scan .tf files for issues |
| `tf-audit demo` | Run demo with intentionally insecure Terraform |
| `tf-audit rules` | List all 55+ audit rules |

### Scan Options

| Option | Description |
|--------|-------------|
| `--verbose / -v` | Show fix suggestions for each issue |
| `--format / -f` | Output format: terminal, json, html, sarif |
| `--output / -o` | Output file path |
| `--category / -c` | Run specific analyzers: security, naming, modules, best-practices |
| `--min-severity / -s` | Minimum severity: critical, high, medium, low, info |
| `--fail-on` | Exit code 1 if issues at this severity or above |

## Rule Categories

### Security (TF-SEC-001 to TF-SEC-020)
- S3 bucket encryption and public access
- Security group / NSG / Firewall open to 0.0.0.0/0
- RDS/database public access and encryption
- IAM wildcard policies
- KMS key rotation, EBS encryption
- Load balancer HTTPS enforcement
- Azure Key Vault purge protection
- Secrets in Terraform state (tls_private_key)

### Naming Conventions (TF-NAM-001 to TF-NAM-008)
- Resource, variable, output, module snake_case enforcement
- Generic name detection (main, this, test)

### Module Quality (TF-MOD-001 to TF-MOD-011)
- Module source version pinning
- Variable descriptions and type constraints
- Provider version management
- Backend configuration and state locking

### Best Practices (TF-BP-001 to TF-BP-014)
- Resource tagging compliance
- Sensitive variable/output flags
- File organization and size
- .gitignore completeness

## Example Output

```
╭─────────────── 🔍 tf-audit — Terraform Configuration Auditor ────────────────╮
│ 📂 Path:  ./infrastructure                                                   │
│ 📄 Files: 5 Terraform files                                                  │
│ 📦 Resources: 16 resources scanned                                           │
│ 🔌 Providers: aws, azurerm                                                   │
╰──────────────────────────────────────────────────────────────────────────────╯

  Grade: F  (0/100)

  Issue Summary:
    🔴 CRITICAL:  4
    🟠     HIGH:  14
    🟡   MEDIUM:  23
    🔵      LOW:  10
    ⚪     INFO:  4
```

## License

MIT
