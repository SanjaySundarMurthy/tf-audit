"""Terminal reporter — Rich console output for tf-audit."""
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from tf_audit.models import AuditReport, Severity, Category, SEVERITY_COLORS, SEVERITY_ICONS, CATEGORY_ICONS


def print_report(report: AuditReport, console: Console, verbose: bool = False):
    """Print the full audit report to the terminal."""
    _print_header(report, console)
    _print_score(report, console)
    _print_severity_summary(report, console)
    _print_category_summary(report, console)
    _print_issues(report, console, verbose)
    _print_providers(report, console)
    _print_footer(report, console)


def _print_header(report, console):
    """Print scan header with file/resource counts."""
    console.print()
    console.print(Panel(
        f"[bold]📂 Path:[/bold]  {report.scan_path}\n"
        f"[bold]📄 Files:[/bold] {report.total_files} Terraform files\n"
        f"[bold]📦 Resources:[/bold] {report.total_resources} resources scanned\n"
        f"[bold]🔌 Providers:[/bold] {', '.join(report.providers_found) if report.providers_found else 'none detected'}",
        title="[bold cyan]🔍 tf-audit — Terraform Configuration Auditor[/bold cyan]",
        border_style="cyan",
    ))


def _print_score(report, console):
    """Print the grade and score."""
    grade = report.grade
    score = report.score

    if score >= 80:
        color = "green"
    elif score >= 60:
        color = "yellow"
    elif score >= 40:
        color = "red"
    else:
        color = "bright_red"

    console.print()
    console.print(f"  [bold {color}]Grade: {grade}  ({score}/100)[/bold {color}]")


def _print_severity_summary(report, console):
    """Print severity breakdown."""
    console.print()
    console.print("  [bold]Issue Summary:[/bold]")
    items = [
        (Severity.CRITICAL, report.critical_count),
        (Severity.HIGH, report.high_count),
        (Severity.MEDIUM, report.medium_count),
        (Severity.LOW, report.low_count),
        (Severity.INFO, report.info_count),
    ]
    for sev, count in items:
        color = SEVERITY_COLORS[sev]
        icon = SEVERITY_ICONS[sev]
        console.print(f"    {icon} [{color}]{sev.value.upper():>8}[/{color}]:  {count}")


def _print_category_summary(report, console):
    """Print issues grouped by category."""
    category_counts = {}
    for issue in report.issues:
        cat = issue.category
        category_counts[cat] = category_counts.get(cat, 0) + 1

    if not category_counts:
        return

    console.print()
    console.print("  [bold]By Category:[/bold]")
    for cat in Category:
        count = category_counts.get(cat, 0)
        if count > 0:
            icon = CATEGORY_ICONS.get(cat, "📋")
            console.print(f"    {icon} {cat.value:.<25} {count}")


def _print_issues(report, console, verbose):
    """Print issue details table."""
    if not report.issues:
        console.print("\n  [green]✅ No issues found! Excellent Terraform configuration.[/green]")
        return

    console.print()
    table = Table(
        title=f"📋 Issues Found ({len(report.issues)})",
        show_lines=True,
        padding=(0, 1),
    )
    table.add_column("Rule", style="bold cyan", width=12)
    table.add_column("Severity", width=10)
    table.add_column("Category", width=18)
    table.add_column("Message", min_width=40)
    if verbose:
        table.add_column("Suggestion", min_width=30, style="dim")

    for issue in sorted(report.issues, key=lambda i: list(Severity).index(i.severity)):
        sev_color = SEVERITY_COLORS[issue.severity]
        sev_icon = SEVERITY_ICONS[issue.severity]

        resource_info = ""
        if issue.resource_type and issue.resource_name:
            resource_info = f" [{issue.resource_type}.{issue.resource_name}]"

        row = [
            issue.rule_id,
            f"[{sev_color}]{sev_icon} {issue.severity.value.upper()}[/{sev_color}]",
            issue.category.value,
            f"{issue.message}{resource_info}",
        ]
        if verbose:
            row.append(issue.suggestion or "")
        table.add_row(*row)

    console.print(table)


def _print_providers(report, console):
    """Print detected providers."""
    if not report.providers_found:
        return
    console.print()
    console.print(f"  [bold]Cloud Providers:[/bold] {', '.join(report.providers_found)}")


def _print_footer(report, console):
    """Print footer with summary."""
    console.print()
    total = len(report.issues)
    if total == 0:
        console.print("  [green bold]🎯 Perfect score — no issues detected![/green bold]")
    elif report.score >= 80:
        console.print(f"  [green]✨ Good configuration! {total} minor findings to review.[/green]")
    elif report.score >= 60:
        console.print(f"  [yellow]⚠️  {total} issues found. Review and address high/critical findings.[/yellow]")
    else:
        console.print(f"  [red]🚨 {total} issues found. Immediate attention needed for security findings.[/red]")
    console.print(f"  [dim]  Run with --verbose for fix suggestions[/dim]")
    console.print()
