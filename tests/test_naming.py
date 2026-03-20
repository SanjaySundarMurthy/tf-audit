"""Tests for tf-audit naming analyzer."""
from tf_audit.parser import parse_terraform
from tf_audit.analyzers.naming_analyzer import analyze


class TestNamingAnalyzer:
    def test_good_names_no_issues(self, good_tf_dir):
        tf_files = parse_terraform(good_tf_dir)
        issues = analyze(tf_files)
        # Secure config uses snake_case names — should have minimal naming issues
        naming_ids = [i.rule_id for i in issues if i.rule_id.startswith("TF-NAM")]
        assert len(naming_ids) <= 2  # possibly generic name "primary"

    def test_insecure_detects_non_snake_case_var(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-NAM-004" in rule_ids  # instanceCount is not snake_case

    def test_insecure_detects_generic_names(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-NAM-007" in rule_ids  # "main", "this" are generic

    def test_no_files(self):
        issues = analyze([])
        assert issues == []

    def test_hyphenated_name(self, tmp_tf):
        path = tmp_tf({"test.tf": '''
resource "aws_instance" "my-server" {
  ami = "ami-123"
}
'''})
        tf_files = parse_terraform(path)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-NAM-002" in rule_ids  # hyphens

    def test_uppercase_name(self, tmp_tf):
        path = tmp_tf({"test.tf": '''
resource "aws_instance" "MyServer" {
  ami = "ami-123"
}
'''})
        tf_files = parse_terraform(path)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-NAM-001" in rule_ids  # uppercase
