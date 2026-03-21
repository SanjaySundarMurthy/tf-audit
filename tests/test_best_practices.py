"""Tests for tf-audit best practices analyzer."""
from tf_audit.parser import parse_terraform
from tf_audit.analyzers.best_practices_analyzer import analyze


class TestBestPracticesAnalyzer:
    def test_secure_config_fewer_issues(self, good_tf_dir):
        tf_files = parse_terraform(good_tf_dir)
        issues = analyze(tf_files)
        # Secure config has tags, sensitive flags, etc.
        # Should not flag sensitive variable (it has sensitive = true)
        assert "TF-BP-002" not in [i.rule_id for i in issues]

    def test_insecure_detects_sensitive_var(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-BP-002" in rule_ids  # db_password without sensitive

    def test_insecure_detects_missing_tags(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-BP-003" in rule_ids  # resources without tags

    def test_insecure_detects_sensitive_output(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-BP-014" in rule_ids  # database_password output

    def test_insecure_detects_missing_gitignore(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-BP-011" in rule_ids  # no .gitignore

    def test_insecure_detects_hardcoded_credentials(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-BP-004" in rule_ids  # hardcoded password in RDS

    def test_insecure_detects_missing_lifecycle(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-BP-007" in rule_ids  # stateful resource without lifecycle

    def test_provisioner_detected(self, tmp_tf):
        path = tmp_tf({"main.tf": '''
resource "aws_instance" "web" {
  ami = "ami-123"
  provisioner "local-exec" {
    command = "echo hello"
  }
}
'''})
        tf_files = parse_terraform(path)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-BP-015" in rule_ids  # provisioner usage

    def test_no_files(self):
        issues = analyze([])
        assert issues == []
