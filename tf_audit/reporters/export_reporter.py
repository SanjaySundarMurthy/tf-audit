"""Export reporter — JSON, HTML, and SARIF export for tf-audit."""
import json
import os
from datetime import datetime, timezone

from tf_audit.models import AuditReport


def export_json(report: AuditReport, output_path: str):
    """Export report as JSON."""
    data = {
        "tool": "tf-audit",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_path": report.scan_path,
        "total_files": report.total_files,
        "total_resources": report.total_resources,
        "providers": report.providers_found,
        "score": report.score,
        "grade": report.grade,
        "summary": {
            "critical": report.critical_count,
            "high": report.high_count,
            "medium": report.medium_count,
            "low": report.low_count,
            "info": report.info_count,
        },
        "issues": [
            {
                "rule_id": i.rule_id,
                "severity": i.severity.value,
                "category": i.category.value,
                "message": i.message,
                "resource_type": i.resource_type,
                "resource_name": i.resource_name,
                "file_path": i.file_path,
                "suggestion": i.suggestion,
                "doc_url": i.doc_url,
            }
            for i in report.issues
        ],
    }
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def export_html(report: AuditReport, output_path: str):
    """Export report as HTML."""
    sev_colors = {
        "critical": "#dc3545", "high": "#fd7e14",
        "medium": "#ffc107", "low": "#17a2b8", "info": "#6c757d",
    }

    rows = ""
    for i in sorted(report.issues, key=lambda x: ["critical", "high", "medium", "low", "info"].index(x.severity.value)):
        color = sev_colors.get(i.severity.value, "#000")
        resource = f"{i.resource_type}.{i.resource_name}" if i.resource_type else ""
        rows += f"""<tr>
            <td><code>{i.rule_id}</code></td>
            <td style="color:{color};font-weight:bold">{i.severity.value.upper()}</td>
            <td>{i.category.value}</td>
            <td>{i.message}</td>
            <td><code>{resource}</code></td>
            <td>{i.suggestion or ''}</td>
        </tr>\n"""

    grade_color = "#28a745" if report.score >= 80 else "#ffc107" if report.score >= 60 else "#dc3545"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>tf-audit Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 2rem; background: #f8f9fa; }}
  .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 2rem; border-radius: 8px; margin-bottom: 2rem; }}
  .header h1 {{ margin: 0; font-size: 1.8rem; }}
  .header .meta {{ opacity: 0.9; margin-top: 0.5rem; }}
  .grade {{ font-size: 3rem; font-weight: bold; color: {grade_color}; text-align: center; padding: 1rem; }}
  .summary {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .card {{ background: white; padding: 1rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.1); flex: 1; min-width: 120px; text-align: center; }}
  .card .num {{ font-size: 2rem; font-weight: bold; }}
  table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
  th {{ background: #343a40; color: white; padding: 0.75rem; text-align: left; }}
  td {{ padding: 0.75rem; border-bottom: 1px solid #dee2e6; }}
  tr:hover {{ background: #f1f3f5; }}
  code {{ background: #e9ecef; padding: 2px 6px; border-radius: 3px; font-size: 0.85rem; }}
</style>
</head>
<body>
<div class="header">
  <h1>🔍 tf-audit — Terraform Configuration Audit Report</h1>
  <div class="meta">Path: {report.scan_path} | {report.total_files} files | {report.total_resources} resources | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</div>
</div>
<div class="grade">{report.grade} ({report.score}/100)</div>
<div class="summary">
  <div class="card"><div class="num" style="color:#dc3545">{report.critical_count}</div>Critical</div>
  <div class="card"><div class="num" style="color:#fd7e14">{report.high_count}</div>High</div>
  <div class="card"><div class="num" style="color:#ffc107">{report.medium_count}</div>Medium</div>
  <div class="card"><div class="num" style="color:#17a2b8">{report.low_count}</div>Low</div>
  <div class="card"><div class="num" style="color:#6c757d">{report.info_count}</div>Info</div>
</div>
<table>
  <thead><tr><th>Rule</th><th>Severity</th><th>Category</th><th>Message</th><th>Resource</th><th>Suggestion</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
</body></html>"""

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)


def export_sarif(report: AuditReport, output_path: str):
    """Export report as SARIF 2.1.0 for GitHub/GitLab integration."""
    rules = {}
    results = []

    for issue in report.issues:
        if issue.rule_id not in rules:
            rules[issue.rule_id] = {
                "id": issue.rule_id,
                "shortDescription": {"text": issue.message[:200]},
                "defaultConfiguration": {"level": _sarif_level(issue.severity.value)},
                "helpUri": issue.doc_url or "",
            }

        result = {
            "ruleId": issue.rule_id,
            "level": _sarif_level(issue.severity.value),
            "message": {"text": issue.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": issue.file_path.replace("\\", "/")},
                }
            }],
        }
        if issue.suggestion:
            result["fixes"] = [{"description": {"text": issue.suggestion}}]
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "tf-audit",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/SanjaySundarMurthy/tf-audit",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, default=str)


def _sarif_level(severity: str) -> str:
    """Convert severity to SARIF level."""
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(severity, "note")
