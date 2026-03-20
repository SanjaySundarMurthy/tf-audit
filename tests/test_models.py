"""Tests for tf-audit data models."""
from tf_audit.models import (
    Severity, Category, Issue, TfResource, TfFile, AuditReport,
)


class TestEnums:
    def test_severity_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.INFO.value == "info"

    def test_category_values(self):
        assert Category.SECURITY.value == "Security"
        assert Category.NAMING.value == "Naming Conventions"
        assert Category.MODULES.value == "Module Quality"
        assert Category.BEST_PRACTICES.value == "Best Practices"


class TestIssue:
    def test_create_issue(self):
        issue = Issue(
            rule_id="TF-SEC-001",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            message="Test issue",
        )
        assert issue.rule_id == "TF-SEC-001"
        assert issue.resource_type == ""

    def test_issue_with_all_fields(self):
        issue = Issue(
            rule_id="TF-SEC-003",
            severity=Severity.CRITICAL,
            category=Category.SECURITY,
            message="Open SG",
            resource_type="aws_security_group",
            resource_name="web",
            file_path="main.tf",
            suggestion="Restrict CIDR",
        )
        assert issue.resource_name == "web"
        assert issue.suggestion == "Restrict CIDR"


class TestTfResource:
    def test_create_resource(self):
        res = TfResource(resource_type="aws_s3_bucket", name="data")
        assert res.provider == ""
        assert res.config == {}

    def test_resource_with_config(self):
        res = TfResource(
            resource_type="aws_instance",
            name="web",
            provider="aws",
            config={"ami": "ami-123", "instance_type": "t3.micro"},
        )
        assert res.provider == "aws"
        assert "ami" in res.config


class TestAuditReport:
    def test_empty_report(self):
        report = AuditReport(scan_path="/tmp")
        assert report.score == 100.0
        assert report.grade == "A+"
        assert report.critical_count == 0

    def test_severity_counts(self):
        issues = [
            Issue("TF-SEC-001", Severity.CRITICAL, Category.SECURITY, "crit"),
            Issue("TF-SEC-002", Severity.HIGH, Category.SECURITY, "high"),
            Issue("TF-SEC-003", Severity.HIGH, Category.SECURITY, "high2"),
            Issue("TF-NAM-001", Severity.LOW, Category.NAMING, "low"),
        ]
        report = AuditReport(scan_path="/tmp", issues=issues)
        assert report.critical_count == 1
        assert report.high_count == 2
        assert report.low_count == 1

    def test_calculate_score_perfect(self):
        report = AuditReport(scan_path="/tmp", total_resources=5)
        report.calculate_score()
        assert report.score == 100.0
        assert report.grade == "A+"

    def test_calculate_score_with_issues(self):
        issues = [
            Issue("TF-SEC-001", Severity.CRITICAL, Category.SECURITY, "crit"),
            Issue("TF-SEC-002", Severity.CRITICAL, Category.SECURITY, "crit2"),
        ]
        report = AuditReport(scan_path="/tmp", total_resources=5, issues=issues)
        report.calculate_score()
        assert report.score < 100
        assert report.grade != "A+"
