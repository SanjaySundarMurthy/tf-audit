"""tf-audit CLI — Terraform configuration auditor & security scanner."""
import sys
import os
import shutil

import click
from rich.console import Console

# Fix Windows console encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from tf_audit import __version__
from tf_audit.models import AuditReport, Severity, Category
from tf_audit.parser import parse_terraform, get_all_resources, get_providers
from tf_audit.analyzers import security_analyzer, naming_analyzer, module_analyzer, best_practices_analyzer
from tf_audit.reporters.terminal_reporter import print_report
from tf_audit.reporters.export_reporter import export_json, export_html, export_sarif


console = Console()

ANALYZERS = {
    "security": ("Security", security_analyzer),
    "naming": ("Naming Conventions", naming_analyzer),
    "modules": ("Module Quality", module_analyzer),
    "best-practices": ("Best Practices", best_practices_analyzer),
}


def _run_audit(tf_files: list, categories: tuple) -> list:
    """Run selected or all analyzers."""
    analyzers_to_run = {}
    if categories:
        for cat in categories:
            if cat in ANALYZERS:
                analyzers_to_run[cat] = ANALYZERS[cat]
    else:
        analyzers_to_run = ANALYZERS

    all_issues = []
    for name, (display, analyzer) in analyzers_to_run.items():
        with console.status(f"[cyan]Running {display} checks...[/cyan]"):
            issues = analyzer.analyze(tf_files)
            all_issues.extend(issues)

    return all_issues


@click.group()
@click.version_option(version=__version__, prog_name="tf-audit")
def main():
    """🔍 tf-audit — Terraform configuration auditor & security scanner.

    Audit Terraform (.tf) files for security misconfigurations,
    naming conventions, module quality, and best practices.
    55+ rules across 7 categories for AWS, Azure, and GCP.

    \b
    Examples:
      tf-audit scan ./infrastructure
      tf-audit scan ./main.tf --verbose
      tf-audit scan . --format json --output report.json
      tf-audit demo
      tf-audit rules
    """
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--verbose", "-v", is_flag=True, help="Show fix suggestions for each issue")
@click.option("--format", "-f", "output_format", type=click.Choice(["terminal", "json", "html", "sarif"]), default="terminal")
@click.option("--output", "-o", "output_path", type=click.Path(), help="Output file path")
@click.option("--category", "-c", multiple=True, type=click.Choice(list(ANALYZERS.keys())),
              help="Run only specific analyzer categories")
@click.option("--min-severity", "-s", type=click.Choice(["critical", "high", "medium", "low", "info"]),
              default="info", help="Minimum severity to report")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]),
              help="Exit with code 1 if issues of this severity or above exist")
def scan(path, verbose, output_format, output_path, category, min_severity, fail_on):
    """Scan Terraform files for issues.

    PATH is a .tf file or directory containing Terraform configurations.
    """
    abs_path = os.path.abspath(path)

    # Parse Terraform files
    tf_files = parse_terraform(abs_path)
    if not tf_files:
        console.print("[yellow]No .tf files found to scan.[/yellow]")
        return

    # Run audit
    all_issues = _run_audit(tf_files, category)

    # Filter by minimum severity
    sev_order = list(Severity)
    min_sev_idx = sev_order.index(Severity(min_severity))
    all_issues = [i for i in all_issues if sev_order.index(i.severity) <= min_sev_idx]

    # Build report
    all_resources = get_all_resources(tf_files)
    providers_found = get_providers(tf_files)

    report = AuditReport(
        scan_path=abs_path,
        total_files=len(tf_files),
        total_resources=len(all_resources),
        tf_files=tf_files,
        issues=all_issues,
        providers_found=providers_found,
    )
    report.calculate_score()

    # Output
    if output_format == "json":
        dest = output_path or "tf-audit-report.json"
        export_json(report, dest)
        console.print(f"[green]JSON report saved to {dest}[/green]")
    elif output_format == "html":
        dest = output_path or "tf-audit-report.html"
        export_html(report, dest)
        console.print(f"[green]HTML report saved to {dest}[/green]")
    elif output_format == "sarif":
        dest = output_path or "tf-audit-report.sarif"
        export_sarif(report, dest)
        console.print(f"[green]SARIF report saved to {dest}[/green]")
    else:
        print_report(report, console, verbose)

    # CI/CD fail gate
    if fail_on:
        severity_levels = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        threshold_idx = severity_levels.index(Severity(fail_on))
        triggered = severity_levels[:threshold_idx + 1]
        if any(i.severity in triggered for i in all_issues):
            raise SystemExit(1)


@main.command()
@click.option("--verbose", "-v", is_flag=True, help="Show fix suggestions")
def demo(verbose):
    """Run a demo audit on intentionally insecure Terraform files.

    Creates a realistic infrastructure project with security
    misconfigurations to demonstrate tf-audit capabilities.
    """
    from tf_audit.demo import create_demo_terraform

    console.print("[cyan]🎪 Creating demo Terraform project with intentional issues...[/cyan]\n")
    demo_dir = create_demo_terraform()

    try:
        tf_files = parse_terraform(demo_dir)
        all_issues = _run_audit(tf_files, ())

        all_resources = get_all_resources(tf_files)
        providers_found = get_providers(tf_files)

        report = AuditReport(
            scan_path=demo_dir,
            total_files=len(tf_files),
            total_resources=len(all_resources),
            tf_files=tf_files,
            issues=all_issues,
            providers_found=providers_found,
        )
        report.calculate_score()
        print_report(report, console, verbose)
    finally:
        shutil.rmtree(os.path.dirname(demo_dir), ignore_errors=True)


@main.command()
def rules():
    """List all 55+ audit rules organized by category."""
    from rich.table import Table

    rule_defs = [
        # Security (20)
        ("TF-SEC-001", "HIGH", "Security", "S3 bucket without server-side encryption"),
        ("TF-SEC-002", "CRITICAL", "Security", "S3 bucket with public ACL"),
        ("TF-SEC-003", "CRITICAL", "Security", "Security group allows 0.0.0.0/0 ingress"),
        ("TF-SEC-004", "HIGH", "Security", "Security group allows all ports (0-65535)"),
        ("TF-SEC-005", "CRITICAL", "Security", "RDS instance publicly accessible"),
        ("TF-SEC-006", "HIGH", "Security", "RDS instance without storage encryption"),
        ("TF-SEC-007", "HIGH", "Security", "Azure Storage without HTTPS enforcement"),
        ("TF-SEC-008", "CRITICAL", "Security", "Azure NSG rule allows 0.0.0.0/0"),
        ("TF-SEC-009", "CRITICAL", "Security", "GCP firewall allows 0.0.0.0/0"),
        ("TF-SEC-010", "HIGH", "Security", "IAM policy with wildcard (*) actions/resources"),
        ("TF-SEC-011", "MEDIUM", "Security", "KMS key without automatic rotation"),
        ("TF-SEC-012", "HIGH", "Security", "EBS volume without encryption"),
        ("TF-SEC-013", "MEDIUM", "Security", "CloudTrail without multi-region or log validation"),
        ("TF-SEC-014", "INFO", "Security", "VPC without flow logs configured"),
        ("TF-SEC-015", "HIGH", "Security", "Load balancer listener using HTTP"),
        ("TF-SEC-016", "MEDIUM", "Security", "Database without adequate backup retention"),
        ("TF-SEC-017", "HIGH", "Security", "tls_private_key stores secrets in state"),
        ("TF-SEC-018", "MEDIUM", "Security", "Container without read-only root filesystem"),
        ("TF-SEC-019", "INFO", "Security", "Public ALB without WAF association"),
        ("TF-SEC-020", "MEDIUM", "Security", "Azure Key Vault without purge protection"),
        # Naming (8)
        ("TF-NAM-001", "LOW", "Naming", "Resource name uses uppercase characters"),
        ("TF-NAM-002", "MEDIUM", "Naming", "Resource name contains spaces or hyphens"),
        ("TF-NAM-003", "LOW", "Naming", "Resource name doesn't follow snake_case"),
        ("TF-NAM-004", "LOW", "Naming", "Variable name doesn't follow snake_case"),
        ("TF-NAM-005", "LOW", "Naming", "Output name doesn't follow snake_case"),
        ("TF-NAM-006", "LOW", "Naming", "Module call name doesn't follow snake_case"),
        ("TF-NAM-007", "LOW", "Naming", "Resource name is too generic (main, this, etc.)"),
        ("TF-NAM-008", "LOW", "Naming", "Data source name doesn't follow snake_case"),
        # Modules (12)
        ("TF-MOD-001", "HIGH", "Modules", "Module source not pinned to version/ref"),
        ("TF-MOD-002", "INFO", "Modules", "Module uses local source path"),
        ("TF-MOD-003", "MEDIUM", "Modules", "Variable without description"),
        ("TF-MOD-004", "MEDIUM", "Modules", "Variable without type constraint"),
        ("TF-MOD-006", "LOW", "Modules", "Output without description"),
        ("TF-MOD-007", "MEDIUM", "Modules", "No required_providers block"),
        ("TF-MOD-008", "LOW", "Modules", "Provider with inline version (deprecated)"),
        ("TF-MOD-009", "MEDIUM", "Modules", "No required_version constraint"),
        ("TF-MOD-010", "MEDIUM", "State", "No backend configuration (local state)"),
        ("TF-MOD-011", "HIGH", "State", "S3 backend without DynamoDB state locking"),
        # Best Practices (15)
        ("TF-BP-001", "MEDIUM", "Practices", "Hardcoded IDs instead of variables/data sources"),
        ("TF-BP-002", "HIGH", "Practices", "Sensitive variable without sensitive = true"),
        ("TF-BP-003", "MEDIUM", "Tagging", "Resource without tags/labels"),
        ("TF-BP-005", "LOW", "Practices", "count used instead of for_each"),
        ("TF-BP-006", "LOW", "Practices", "Provider version in provider block (deprecated)"),
        ("TF-BP-009", "LOW", "Practices", "Large file (>500 lines)"),
        ("TF-BP-010", "LOW", "Practices", "Too many resources in one file (>15)"),
        ("TF-BP-011", "MEDIUM", "Practices", "Missing or incomplete .gitignore"),
        ("TF-BP-012", "MEDIUM", "Providers", "Provider version without upper bound"),
        ("TF-BP-013", "INFO", "Practices", "Variable without validation block"),
        ("TF-BP-014", "HIGH", "Practices", "Sensitive output without sensitive = true"),
    ]

    table = Table(title="📋 tf-audit Rules (55+)", show_lines=False, padding=(0, 1))
    table.add_column("Rule ID", style="bold cyan", width=12)
    table.add_column("Severity", width=10)
    table.add_column("Category", width=12)
    table.add_column("Description", min_width=45)

    sev_colors = {
        "CRITICAL": "bright_red", "HIGH": "red",
        "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim",
    }

    for rule_id, sev, cat, desc in rule_defs:
        color = sev_colors.get(sev, "white")
        table.add_row(rule_id, f"[{color}]{sev}[/{color}]", cat, desc)

    console.print()
    console.print(table)
    console.print(f"\n[dim]  {len(rule_defs)} rules across 7 categories (Security, Naming, Modules, State, Practices, Tagging, Providers)[/dim]\n")
