"""Tests for tf-audit CLI commands."""
import json
from click.testing import CliRunner
from tf_audit.cli import main


class TestMainGroup:
    def test_version_flag(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "tf-audit" in result.output

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "demo" in result.output
        assert "rules" in result.output


class TestScanCommand:
    def test_scan_good_tf(self, good_tf_dir):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", good_tf_dir])
        assert result.exit_code == 0

    def test_scan_bad_tf(self, bad_tf_dir):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", bad_tf_dir])
        assert result.exit_code == 0

    def test_scan_verbose(self, good_tf_dir):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", good_tf_dir, "--verbose"])
        assert result.exit_code == 0

    def test_scan_export_json(self, good_tf_dir, tmp_path):
        output = str(tmp_path / "report.json")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", good_tf_dir, "--format", "json", "--output", output])
        assert result.exit_code == 0
        with open(output) as f:
            data = json.load(f)
        assert "issues" in data
        assert "score" in data

    def test_scan_export_html(self, good_tf_dir, tmp_path):
        output = str(tmp_path / "report.html")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", good_tf_dir, "--format", "html", "--output", output])
        assert result.exit_code == 0
        assert (tmp_path / "report.html").exists()

    def test_scan_export_sarif(self, good_tf_dir, tmp_path):
        output = str(tmp_path / "report.sarif")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", good_tf_dir, "--format", "sarif", "--output", output])
        assert result.exit_code == 0
        with open(output) as f:
            data = json.load(f)
        assert data["version"] == "2.1.0"

    def test_scan_nonexistent_path(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "/nonexistent/path"])
        assert result.exit_code != 0

    def test_scan_fail_on(self, bad_tf_dir):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", bad_tf_dir, "--fail-on", "critical"])
        assert result.exit_code in (0, 1)

    def test_scan_category_filter(self, good_tf_dir):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", good_tf_dir, "--category", "security"])
        assert result.exit_code == 0

    def test_scan_min_severity(self, bad_tf_dir):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", bad_tf_dir, "--min-severity", "high"])
        assert result.exit_code == 0


class TestDemoCommand:
    def test_demo_runs(self):
        runner = CliRunner()
        result = runner.invoke(main, ["demo"])
        assert result.exit_code == 0


class TestRulesCommand:
    def test_rules_list(self):
        runner = CliRunner()
        result = runner.invoke(main, ["rules"])
        assert result.exit_code == 0
        assert "TF-SEC-" in result.output
        assert "TF-NAM-" in result.output
        assert "TF-MOD-" in result.output
        assert "TF-BP-" in result.output
