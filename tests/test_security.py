"""Tests for tf-audit security analyzer."""
from tf_audit.parser import parse_terraform
from tf_audit.analyzers.security_analyzer import analyze


class TestSecurityAnalyzer:
    def test_secure_config_fewer_issues(self, good_tf_dir):
        tf_files = parse_terraform(good_tf_dir)
        issues = analyze(tf_files)
        sec_ids = [i.rule_id for i in issues if i.rule_id.startswith("TF-SEC")]
        # Secure config: encrypted S3, private RDS, encrypted storage
        # May still get INFO-level VPC flow log reminder
        critical = [i for i in issues if i.severity.value == "critical"]
        assert len(critical) == 0

    def test_insecure_detects_public_s3(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-SEC-002" in rule_ids  # public ACL

    def test_insecure_detects_open_sg(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-SEC-003" in rule_ids  # 0.0.0.0/0 ingress

    def test_insecure_detects_all_ports(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-SEC-004" in rule_ids  # all ports

    def test_insecure_detects_public_rds(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-SEC-005" in rule_ids  # publicly accessible

    def test_insecure_detects_unencrypted_rds(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-SEC-006" in rule_ids  # no encryption

    def test_insecure_detects_unencrypted_ebs(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-SEC-012" in rule_ids  # unencrypted EBS

    def test_insecure_detects_tls_key(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-SEC-017" in rule_ids  # tls_private_key

    def test_insecure_detects_iam_wildcard(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-SEC-010" in rule_ids  # wildcard IAM

    def test_insecure_detects_http_listener(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        issues = analyze(tf_files)
        rule_ids = [i.rule_id for i in issues]
        assert "TF-SEC-015" in rule_ids  # HTTP listener

    def test_no_files(self):
        issues = analyze([])
        assert issues == []
