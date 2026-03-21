"""Tests for tf-audit module quality analyzer."""
from tf_audit.parser import parse_terraform
from tf_audit.analyzers.module_analyzer import analyze


class TestModuleAnalyzer:
    def test_secure_config_fewer_issues(self, good_tf_dir):
        tf_files = parse_terraform(good_tf_dir)
        issues = analyze(tf_files)
        # Secure config has required_providers, required_version, backend, descriptions
        # Should not have TF-MOD-007, 009, 010, 003 since they're all present
        assert "TF-MOD-007" not in [i.rule_id for i in issues]
        assert "TF-MOD-009" not in [i.rule_id for i in issues]
        assert "TF-MOD-010" not in [i.rule_id for i in issues]

    def test_insecure_detects_missing_var_description(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-MOD-003" in rule_ids  # variable without description

    def test_insecure_detects_missing_var_type(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-MOD-004" in rule_ids  # variable without type

    def test_insecure_detects_missing_output_desc(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-MOD-006" in rule_ids  # output without description

    def test_insecure_detects_no_required_providers(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-MOD-007" in rule_ids

    def test_insecure_detects_no_backend(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-MOD-010" in rule_ids

    def test_type_any_detected(self, tmp_tf):
        path = tmp_tf({"variables.tf": '''
variable "config" {
  description = "Generic config"
  type        = any
}
'''})
        tf_files = parse_terraform(path)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-MOD-005" in rule_ids  # type = any

    def test_backend_no_encryption(self, tmp_tf):
        path = tmp_tf({"main.tf": '''
terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    bucket         = "my-state"
    key            = "terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "locks"
  }
}
'''})
        tf_files = parse_terraform(path)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-MOD-012" in rule_ids  # no encrypt = true

    def test_no_files(self):
        issues = analyze([])
        assert issues == []
