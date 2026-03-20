"""Tests for tf-audit HCL2 parser."""
from tf_audit.parser import parse_terraform, get_all_resources, get_providers


class TestParseTerraform:
    def test_parse_secure_tf(self, good_tf_dir):
        tf_files = parse_terraform(good_tf_dir)
        assert len(tf_files) == 3  # main.tf, variables.tf, outputs.tf

    def test_parse_extracts_resources(self, good_tf_dir):
        tf_files = parse_terraform(good_tf_dir)
        all_resources = get_all_resources(tf_files)
        resource_types = [r.resource_type for r in all_resources]
        assert "aws_s3_bucket" in resource_types
        assert "aws_db_instance" in resource_types

    def test_parse_extracts_variables(self, good_tf_dir):
        tf_files = parse_terraform(good_tf_dir)
        all_vars = []
        for tf in tf_files:
            all_vars.extend(tf.variables)
        var_names = [v["_name"] for v in all_vars]
        assert "region" in var_names
        assert "db_password" in var_names

    def test_parse_extracts_outputs(self, good_tf_dir):
        tf_files = parse_terraform(good_tf_dir)
        all_outputs = []
        for tf in tf_files:
            all_outputs.extend(tf.outputs)
        out_names = [o["_name"] for o in all_outputs]
        assert "bucket_arn" in out_names

    def test_parse_empty_directory(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        tf_files = parse_terraform(str(empty))
        assert tf_files == []

    def test_parse_invalid_hcl(self, tmp_tf):
        path = tmp_tf({"bad.tf": "{{{{invalid hcl content}}}}"})
        tf_files = parse_terraform(path)
        # Should still return a TfFile (with no parsed resources)
        assert len(tf_files) == 1
        assert tf_files[0].resources == []

    def test_parse_single_file(self, tmp_path, secure_main_tf):
        f = tmp_path / "main.tf"
        f.write_text(secure_main_tf, encoding="utf-8")
        tf_files = parse_terraform(str(f))
        assert len(tf_files) == 1

    def test_parse_providers_detected(self, good_tf_dir):
        tf_files = parse_terraform(good_tf_dir)
        providers = get_providers(tf_files)
        assert "aws" in providers

    def test_parse_insecure_resources(self, bad_tf_dir):
        tf_files = parse_terraform(bad_tf_dir)
        all_resources = get_all_resources(tf_files)
        assert len(all_resources) >= 5

    def test_line_count(self, good_tf_dir):
        tf_files = parse_terraform(good_tf_dir)
        for tf in tf_files:
            assert tf.line_count > 0
