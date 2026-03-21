# tf-audit

[![CI](https://github.com/SanjaySundarMurthy/tf-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/SanjaySundarMurthy/tf-audit/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/tf-audit)](https://pypi.org/project/tf-audit/)
[![PyPI](https://img.shields.io/pypi/v/tf-audit)](https://pypi.org/project/tf-audit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Terraform Configuration Auditor & Security Scanner** — 55 rules for security misconfigurations, naming conventions, module quality, and best practices across AWS, Azure, and GCP.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

---

## Features

- **20 Security Rules** — S3 encryption, public databases, open security groups, IAM wildcards, Key Vault misconfigs, and more
- **8 Naming Convention Rules** — snake_case enforcement for resources, variables, outputs, modules, and data sources
- **12 Module Quality Rules** — Version pinning, variable descriptions, type constraints, backend config, state encryption
- **15 Best Practice Rules** — Tagging, sensitive flags, lifecycle management, file conventions, credential detection
- **Multi-Cloud** — AWS, Azure, and GCP resource support
- **Multiple Export Formats** — Terminal (Rich), JSON, HTML, SARIF
- **CI/CD Integration** — `--fail-on` flag for pipeline quality gates
- **Grading System** — A+ through F scores based on weighted severity findings
- **Demo Mode** — Try instantly with intentionally insecure Terraform files

---

## Installation

```bash
pip install tf-audit
```

### Development

```bash
git clone https://github.com/SanjaySundarMurthy/tf-audit.git
cd tf-audit
pip install -e ".[dev]"
```

---

## Quick Start

```bash
# Scan a Terraform directory
tf-audit scan ./infrastructure

# Run the built-in demo
tf-audit demo

# Verbose output with fix suggestions
tf-audit scan . --verbose

# Export as JSON for CI/CD
tf-audit scan . --format json --output report.json

# Export as HTML report
tf-audit scan . --format html --output report.html

# Export as SARIF (GitHub/GitLab integration)
tf-audit scan . --format sarif --output report.sarif

# Fail CI if critical issues found
tf-audit scan . --fail-on critical

# Scan only security rules
tf-audit scan . --category security

# Filter issues by minimum severity
tf-audit scan . --min-severity high

# List all 55 rules
tf-audit rules
```

---

## Commands

| Command | Description |
|---------|-------------|
| `tf-audit scan <path>` | Scan `.tf` files or directories for issues |
| `tf-audit demo` | Run demo with intentionally insecure Terraform |
| `tf-audit rules` | List all 55 audit rules with severity and category |
| `tf-audit --version` | Show version |
| `tf-audit --help` | Show help |

### Scan Options

| Option | Description |
|--------|-------------|
| `--verbose / -v` | Show fix suggestions for each issue |
| `--format / -f` | Output format: `terminal`, `json`, `html`, `sarif` |
| `--output / -o` | Output file path |
| `--category / -c` | Run specific analyzers: `security`, `naming`, `modules`, `best-practices` |
| `--min-severity / -s` | Minimum severity to report: `critical`, `high`, `medium`, `low`, `info` |
| `--fail-on` | Exit code 1 if issues at this severity or above: `critical`, `high`, `medium`, `low` |

---

## Rule Categories

### Security (TF-SEC-001 to TF-SEC-020) — 20 Rules

| Rule | Severity | Description |
|------|----------|-------------|
| TF-SEC-001 | HIGH | S3 bucket without server-side encryption |
| TF-SEC-002 | CRITICAL | S3 bucket with public ACL |
| TF-SEC-003 | CRITICAL | Security group allows 0.0.0.0/0 ingress |
| TF-SEC-004 | HIGH | Security group allows all ports (0-65535) |
| TF-SEC-005 | CRITICAL | RDS instance publicly accessible |
| TF-SEC-006 | HIGH | RDS instance without storage encryption |
| TF-SEC-007 | HIGH | Azure Storage without HTTPS enforcement |
| TF-SEC-008 | CRITICAL | Azure NSG rule allows 0.0.0.0/0 |
| TF-SEC-009 | CRITICAL | GCP firewall allows 0.0.0.0/0 |
| TF-SEC-010 | HIGH | IAM policy with wildcard (*) actions/resources |
| TF-SEC-011 | MEDIUM | KMS key without automatic rotation |
| TF-SEC-012 | HIGH | EBS volume without encryption |
| TF-SEC-013 | MEDIUM | CloudTrail without multi-region or log validation |
| TF-SEC-014 | INFO | VPC without flow logs configured |
| TF-SEC-015 | HIGH | Load balancer listener using HTTP |
| TF-SEC-016 | MEDIUM | Database without adequate backup retention |
| TF-SEC-017 | HIGH | tls_private_key stores secrets in state |
| TF-SEC-018 | MEDIUM | Container without read-only root filesystem |
| TF-SEC-019 | INFO | Public ALB without WAF association |
| TF-SEC-020 | MEDIUM | Azure Key Vault without purge protection |

### Naming Conventions (TF-NAM-001 to TF-NAM-008) — 8 Rules

| Rule | Severity | Description |
|------|----------|-------------|
| TF-NAM-001 | LOW | Resource name uses uppercase characters |
| TF-NAM-002 | MEDIUM | Resource name contains spaces or hyphens |
| TF-NAM-003 | LOW | Resource name doesn't follow snake_case |
| TF-NAM-004 | LOW | Variable name doesn't follow snake_case |
| TF-NAM-005 | LOW | Output name doesn't follow snake_case |
| TF-NAM-006 | LOW | Module call name doesn't follow snake_case |
| TF-NAM-007 | LOW | Resource name is too generic (main, this, etc.) |
| TF-NAM-008 | LOW | Data source name doesn't follow snake_case |

### Module Quality (TF-MOD-001 to TF-MOD-012) — 12 Rules

| Rule | Severity | Description |
|------|----------|-------------|
| TF-MOD-001 | HIGH | Module source not pinned to version/ref |
| TF-MOD-002 | INFO | Module uses local source path |
| TF-MOD-003 | MEDIUM | Variable without description |
| TF-MOD-004 | MEDIUM | Variable without type constraint |
| TF-MOD-005 | LOW | Variable with overly permissive 'any' type |
| TF-MOD-006 | LOW | Output without description |
| TF-MOD-007 | MEDIUM | No required_providers block |
| TF-MOD-008 | LOW | Provider with inline version (deprecated) |
| TF-MOD-009 | MEDIUM | No required_version constraint |
| TF-MOD-010 | MEDIUM | No backend configuration (local state) |
| TF-MOD-011 | HIGH | S3 backend without DynamoDB state locking |
| TF-MOD-012 | HIGH | S3 backend without encryption enabled |

### Best Practices (TF-BP-001 to TF-BP-015) — 15 Rules

| Rule | Severity | Description |
|------|----------|-------------|
| TF-BP-001 | MEDIUM | Hardcoded IDs instead of variables/data sources |
| TF-BP-002 | HIGH | Sensitive variable without `sensitive = true` |
| TF-BP-003 | MEDIUM | Resource without tags/labels |
| TF-BP-004 | CRITICAL | Hardcoded credentials in resource configuration |
| TF-BP-005 | LOW | `count` used instead of `for_each` |
| TF-BP-006 | LOW | Provider version in provider block (deprecated) |
| TF-BP-007 | MEDIUM | No lifecycle block for stateful resources |
| TF-BP-008 | LOW | File name doesn't follow Terraform conventions |
| TF-BP-009 | LOW | Large file (>500 lines) |
| TF-BP-010 | LOW | Too many resources in one file (>15) |
| TF-BP-011 | MEDIUM | Missing or incomplete `.gitignore` |
| TF-BP-012 | MEDIUM | Provider version without upper bound |
| TF-BP-013 | INFO | Variable without validation block |
| TF-BP-014 | HIGH | Sensitive output without `sensitive = true` |
| TF-BP-015 | MEDIUM | Resource uses provisioner (anti-pattern) |

---

## Grading System

tf-audit assigns a letter grade based on a weighted score (0–100):

| Grade | Score Range | Meaning |
|-------|------------|---------|
| A+ | 95–100 | Excellent — production-ready |
| A | 90–94 | Great — minor improvements possible |
| A- | 85–89 | Good — a few findings to review |
| B+ | 80–84 | Above average |
| B | 75–79 | Average — some issues to address |
| B- | 70–74 | Below average |
| C+ | 65–69 | Needs improvement |
| C | 60–64 | Significant issues |
| C- | 55–59 | Poor |
| D | 50–54 | Very poor |
| D- | 40–49 | Critical issues present |
| F | 0–39 | Failing — immediate action required |

### Severity Weights

| Severity | Points Deducted |
|----------|----------------|
| CRITICAL | 25 |
| HIGH | 15 |
| MEDIUM | 6 |
| LOW | 2 |
| INFO | 0 |

---

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

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Terraform Audit
  run: |
    pip install tf-audit
    tf-audit scan ./infrastructure --fail-on high --format sarif --output results.sarif
```

### GitLab CI

```yaml
terraform-audit:
  script:
    - pip install tf-audit
    - tf-audit scan . --fail-on critical --format json --output report.json
  artifacts:
    reports:
      codequality: report.json
```

---

## 🐳 Docker

Run without installing Python:

```bash
# Build the image
docker build -t tf-audit .

# Run
docker run --rm tf-audit --help

# Scan with volume mount
docker run --rm -v ${PWD}:/workspace tf-audit scan /workspace

# Run demo
docker run --rm tf-audit demo
```

Or pull from the container registry:

```bash
docker pull ghcr.io/SanjaySundarMurthy/tf-audit:latest
docker run --rm ghcr.io/SanjaySundarMurthy/tf-audit:latest --help
```

---

## Project Structure

```
tf-audit/
├── tf_audit/
│   ├── __init__.py              # Package version
│   ├── cli.py                   # Click CLI (scan, demo, rules)
│   ├── models.py                # Data models (Issue, TfFile, AuditReport)
│   ├── parser.py                # HCL2 parser for .tf files
│   ├── demo.py                  # Demo Terraform generator
│   ├── analyzers/
│   │   ├── security_analyzer.py     # 20 security rules
│   │   ├── naming_analyzer.py       # 8 naming convention rules
│   │   ├── module_analyzer.py       # 12 module quality rules
│   │   └── best_practices_analyzer.py # 15 best practice rules
│   └── reporters/
│       ├── terminal_reporter.py     # Rich terminal output
│       └── export_reporter.py       # JSON, HTML, SARIF export
├── tests/
│   ├── conftest.py              # Shared fixtures
│   ├── test_cli.py              # CLI command tests
│   ├── test_security.py         # Security analyzer tests
│   ├── test_naming.py           # Naming analyzer tests
│   ├── test_module.py           # Module quality tests
│   ├── test_best_practices.py   # Best practices tests
│   ├── test_parser.py           # HCL2 parser tests
│   └── test_models.py           # Data model tests
├── .github/workflows/ci.yml     # CI/CD pipeline
├── Dockerfile                   # Multi-stage Docker build
├── pyproject.toml               # Package configuration
└── README.md
```

---

## Test Suite

69 tests covering all analyzers, CLI commands, parser, models, and export formats:

```bash
pytest -v
```

| Test File | Tests | Coverage |
|-----------|-------|----------|
| test_cli.py | 14 | CLI commands, flags, export formats |
| test_security.py | 11 | All 20 security rules |
| test_naming.py | 6 | Naming convention checks |
| test_module.py | 9 | Module quality and state rules |
| test_best_practices.py | 9 | Best practice enforcement |
| test_parser.py | 10 | HCL2 parsing and extraction |
| test_models.py | 10 | Data models and scoring |

---

## 🤝 Contributing

Contributions are welcome! Here's how:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

Please ensure tests pass before submitting:

```bash
pip install -e ".[dev]"
pytest -v
ruff check .
```

---

## License

MIT

---

## Author

**Sanjay S** — [GitHub](https://github.com/SanjaySundarMurthy)

## 🔗 Links

- **PyPI**: [https://pypi.org/project/tf-audit/](https://pypi.org/project/tf-audit/)
- **GitHub**: [https://github.com/SanjaySundarMurthy/tf-audit](https://github.com/SanjaySundarMurthy/tf-audit)
- **Issues**: [https://github.com/SanjaySundarMurthy/tf-audit/issues](https://github.com/SanjaySundarMurthy/tf-audit/issues)