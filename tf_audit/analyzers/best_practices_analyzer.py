"""Best practices analyzer — checks for Terraform coding standards and patterns.

15 rules (TF-BP-001 to TF-BP-015)."""
import re
import os
from tf_audit.models import Issue, Severity, Category


# Patterns for detecting hardcoded values that should be variables
HARDCODED_PATTERNS = {
    "ami-": ("AMI ID", "Use a variable or data source for AMI IDs"),
    "subnet-": ("Subnet ID", "Use a variable or data source for subnet IDs"),
    "vpc-": ("VPC ID", "Use a variable or data source for VPC IDs"),
    "sg-": ("Security Group ID", "Use a variable or ref for security group IDs"),
    "arn:aws:": ("AWS ARN", "Use a variable or data source for ARNs"),
}

SENSITIVE_VAR_PATTERNS = re.compile(
    r"(password|secret|token|api_key|access_key|private_key|credentials|connection_string)",
    re.IGNORECASE,
)

CREDENTIAL_PATTERNS = re.compile(
    r"(password|secret|token|api_key|access_key|private_key|credentials|connection_string)\b",
    re.IGNORECASE,
)

# Resource types that are stateful and should have lifecycle blocks
STATEFUL_RESOURCES = {
    "aws_db_instance", "aws_rds_cluster", "aws_s3_bucket", "aws_dynamodb_table",
    "aws_efs_file_system", "aws_elasticache_cluster", "aws_elasticsearch_domain",
    "azurerm_sql_server", "azurerm_cosmosdb_account", "azurerm_storage_account",
    "azurerm_key_vault", "azurerm_postgresql_server", "azurerm_mysql_server",
    "google_sql_database_instance", "google_storage_bucket", "google_bigtable_instance",
}

# Standard Terraform file names
STANDARD_TF_NAMES = {
    "main.tf", "variables.tf", "outputs.tf", "providers.tf", "versions.tf",
    "terraform.tf", "backend.tf", "locals.tf", "data.tf",
}

# Resource types that should have tags
TAGGABLE_AWS = {
    "aws_instance", "aws_s3_bucket", "aws_db_instance", "aws_vpc",
    "aws_subnet", "aws_security_group", "aws_lb", "aws_ecs_cluster",
    "aws_eks_cluster", "aws_lambda_function", "aws_sqs_queue",
    "aws_sns_topic", "aws_dynamodb_table", "aws_kms_key",
    "aws_ebs_volume", "aws_efs_file_system", "aws_rds_cluster",
    "aws_elasticache_cluster", "aws_cloudwatch_log_group",
}
TAGGABLE_AZURE = {
    "azurerm_resource_group", "azurerm_virtual_network", "azurerm_subnet",
    "azurerm_network_security_group", "azurerm_storage_account",
    "azurerm_key_vault", "azurerm_kubernetes_cluster",
    "azurerm_sql_server", "azurerm_app_service", "azurerm_function_app",
    "azurerm_virtual_machine", "azurerm_linux_virtual_machine",
    "azurerm_windows_virtual_machine", "azurerm_cosmosdb_account",
}
TAGGABLE_GCP = {
    "google_compute_instance", "google_storage_bucket",
    "google_container_cluster", "google_sql_database_instance",
    "google_compute_network", "google_compute_firewall",
}
TAGGABLE_RESOURCES = TAGGABLE_AWS | TAGGABLE_AZURE | TAGGABLE_GCP


def analyze(tf_files: list) -> list:
    """Run all best practices checks."""
    issues = []
    for tf in tf_files:
        _check_file_size(tf, issues)
        _check_resource_count(tf, issues)
        _check_file_naming(tf, issues)
        for res in tf.resources:
            _check_hardcoded_ids(res, issues)
            _check_hardcoded_credentials(res, issues)
            _check_resource_tags(res, issues)
            _check_count_vs_for_each(res, issues)
            _check_lifecycle_stateful(res, issues)
            _check_provisioner_usage(res, issues)
        for var in tf.variables:
            _check_sensitive_variable(var, tf.path, issues)
            _check_variable_validation(var, tf.path, issues)
        for out in tf.outputs:
            _check_sensitive_output(out, tf.path, issues)
        for prov in tf.providers:
            _check_inline_provider(prov, tf.path, issues)

    # Cross-file checks
    _check_gitignore(tf_files, issues)
    _check_wildcard_provider_version(tf_files, issues)

    return issues


def _check_hardcoded_ids(res, issues):
    """TF-BP-001: Hardcoded values instead of variables."""
    config_str = str(res.config)
    for pattern, (label, suggestion) in HARDCODED_PATTERNS.items():
        if pattern in config_str:
            issues.append(Issue(
                rule_id="TF-BP-001",
                severity=Severity.MEDIUM,
                category=Category.BEST_PRACTICES,
                message=f"Resource '{res.resource_type}.{res.name}' has hardcoded {label}",
                resource_type=res.resource_type,
                resource_name=res.name,
                file_path=res.file_path,
                suggestion=suggestion,
            ))
            break  # One finding per resource


def _check_hardcoded_credentials(res, issues):
    """TF-BP-004: Hardcoded credentials in resource configuration."""
    config = res.config
    for key, value in config.items():
        if CREDENTIAL_PATTERNS.search(key) and isinstance(value, str) and value and not value.startswith("var."):
            # Skip references to other resources/variables
            if not value.startswith("${") and not value.startswith("data.") and not value.startswith("module."):
                issues.append(Issue(
                    rule_id="TF-BP-004",
                    severity=Severity.CRITICAL,
                    category=Category.BEST_PRACTICES,
                    message=f"Resource '{res.resource_type}.{res.name}' has hardcoded credential in '{key}'",
                    resource_type=res.resource_type,
                    resource_name=res.name,
                    file_path=res.file_path,
                    suggestion="Use a variable with sensitive = true or a secrets manager reference",
                ))
                return  # One finding per resource


def _check_sensitive_variable(var, file_path, issues):
    """TF-BP-002: Sensitive variable without sensitive flag."""
    name = var.get("_name", "")
    if SENSITIVE_VAR_PATTERNS.search(name) and var.get("sensitive") is not True:
        issues.append(Issue(
            rule_id="TF-BP-002",
            severity=Severity.HIGH,
            category=Category.BEST_PRACTICES,
            message=f"Variable '{name}' appears sensitive but lacks sensitive = true",
            file_path=file_path,
            suggestion="Add sensitive = true to prevent the value from appearing in logs/output",
        ))


def _check_resource_tags(res, issues):
    """TF-BP-003: Resource without tags/labels."""
    if res.resource_type not in TAGGABLE_RESOURCES:
        return
    config = res.config
    has_tags = "tags" in config or "labels" in config
    if not has_tags:
        issues.append(Issue(
            rule_id="TF-BP-003",
            severity=Severity.MEDIUM,
            category=Category.TAGGING,
            message=f"Resource '{res.resource_type}.{res.name}' has no tags/labels",
            resource_type=res.resource_type,
            resource_name=res.name,
            file_path=res.file_path,
            suggestion="Add tags for cost allocation, ownership, and environment tracking",
        ))


def _check_count_vs_for_each(res, issues):
    """TF-BP-005: count used instead of for_each (when iterating)."""
    if "count" in res.config and "for_each" not in res.config:
        count_val = res.config.get("count")
        # If count is a number > 1, for_each might be better
        if isinstance(count_val, (int, float)) and count_val > 1:
            issues.append(Issue(
                rule_id="TF-BP-005",
                severity=Severity.LOW,
                category=Category.BEST_PRACTICES,
                message=f"Resource '{res.resource_type}.{res.name}' uses count={count_val}",
                resource_type=res.resource_type,
                resource_name=res.name,
                file_path=res.file_path,
                suggestion="Consider using for_each for safer resource management (avoids index shifts)",
            ))


def _check_inline_provider(prov, file_path, issues):
    """TF-BP-006: Inline provider alias configuration."""
    name = prov.get("_name", "")
    if prov.get("alias"):
        # Alias providers are fine — skip
        return
    # Check for provider blocks with non-standard configs
    # This is informational — just check inline version
    if prov.get("version"):
        issues.append(Issue(
            rule_id="TF-BP-006",
            severity=Severity.LOW,
            category=Category.BEST_PRACTICES,
            message=f"Provider '{name}' has version in provider block (deprecated)",
            file_path=file_path,
            suggestion="Move version constraints to required_providers in terraform block",
        ))


def _check_file_size(tf, issues):
    """TF-BP-009: Large Terraform file (>500 lines)."""
    if tf.line_count > 500:
        issues.append(Issue(
            rule_id="TF-BP-009",
            severity=Severity.LOW,
            category=Category.BEST_PRACTICES,
            message=f"File has {tf.line_count} lines (recommended: <500)",
            file_path=tf.path,
            suggestion="Split large files into logical modules (e.g., networking.tf, compute.tf)",
        ))


def _check_resource_count(tf, issues):
    """TF-BP-010: Too many resources in one file (>15)."""
    total = len(tf.resources)
    if total > 15:
        issues.append(Issue(
            rule_id="TF-BP-010",
            severity=Severity.LOW,
            category=Category.BEST_PRACTICES,
            message=f"File declares {total} resources (recommended: ≤15 per file)",
            file_path=tf.path,
            suggestion="Group related resources into separate files or child modules",
        ))


def _check_gitignore(tf_files, issues):
    """TF-BP-011: Missing .gitignore for Terraform."""
    if not tf_files:
        return
    root_dir = os.path.dirname(tf_files[0].path)
    gitignore = os.path.join(root_dir, ".gitignore")
    if not os.path.isfile(gitignore):
        issues.append(Issue(
            rule_id="TF-BP-011",
            severity=Severity.MEDIUM,
            category=Category.BEST_PRACTICES,
            message="No .gitignore found — .terraform/ and *.tfstate may be committed",
            file_path=root_dir,
            suggestion="Add a .gitignore with: .terraform/, *.tfstate, *.tfstate.backup, *.tfvars",
        ))
    else:
        try:
            with open(gitignore, "r", encoding="utf-8") as f:
                content = f.read()
            if ".terraform" not in content:
                issues.append(Issue(
                    rule_id="TF-BP-011",
                    severity=Severity.MEDIUM,
                    category=Category.BEST_PRACTICES,
                    message=".gitignore does not include .terraform/ directory",
                    file_path=gitignore,
                    suggestion="Add .terraform/ to .gitignore",
                ))
            if "tfstate" not in content:
                issues.append(Issue(
                    rule_id="TF-BP-011",
                    severity=Severity.HIGH,
                    category=Category.BEST_PRACTICES,
                    message=".gitignore does not ignore *.tfstate files",
                    file_path=gitignore,
                    suggestion="Add *.tfstate and *.tfstate.backup to .gitignore",
                ))
        except Exception:
            pass


def _check_wildcard_provider_version(tf_files, issues):
    """TF-BP-012: Wildcard in provider version constraint."""
    for tf in tf_files:
        for tb in tf.terraform_blocks:
            req_providers = tb.get("required_providers", {})
            if isinstance(req_providers, list):
                req_providers = req_providers[0] if req_providers else {}
            if isinstance(req_providers, dict):
                for prov_name, prov_config in req_providers.items():
                    if isinstance(prov_config, dict):
                        version = prov_config.get("version", "")
                        if isinstance(version, str) and ">=" in version and "," not in version and "<" not in version and "~>" not in version:
                            issues.append(Issue(
                                rule_id="TF-BP-012",
                                severity=Severity.MEDIUM,
                                category=Category.PROVIDERS,
                                message=f"Provider '{prov_name}' version '{version}' has no upper bound",
                                file_path=tf.path,
                                suggestion="Use a bounded constraint like \"~> 5.0\" or \">= 5.0, < 6.0\"",
                            ))


def _check_variable_validation(var, file_path, issues):
    """TF-BP-013: Variable without validation block."""
    name = var.get("_name", "")
    # Only flag for variables that look like they need validation
    if var.get("type") in ("string",) and not var.get("validation") and not var.get("default"):
        # Variables without defaults and of string type should have validation
        issues.append(Issue(
            rule_id="TF-BP-013",
            severity=Severity.INFO,
            category=Category.BEST_PRACTICES,
            message=f"Variable '{name}' has no validation block",
            file_path=file_path,
            suggestion="Add validation { condition = ... error_message = ... } for input safety",
        ))


def _check_sensitive_output(out, file_path, issues):
    """TF-BP-014: Sensitive output without sensitive flag."""
    name = out.get("_name", "")
    if SENSITIVE_VAR_PATTERNS.search(name) and out.get("sensitive") is not True:
        issues.append(Issue(
            rule_id="TF-BP-014",
            severity=Severity.HIGH,
            category=Category.BEST_PRACTICES,
            message=f"Output '{name}' appears sensitive but lacks sensitive = true",
            file_path=file_path,
            suggestion="Add sensitive = true to prevent secrets from appearing in terraform output",
        ))


def _check_lifecycle_stateful(res, issues):
    """TF-BP-007: No lifecycle block for stateful resources."""
    if res.resource_type not in STATEFUL_RESOURCES:
        return
    if "lifecycle" not in res.config:
        issues.append(Issue(
            rule_id="TF-BP-007",
            severity=Severity.MEDIUM,
            category=Category.BEST_PRACTICES,
            message=f"Stateful resource '{res.resource_type}.{res.name}' has no lifecycle block",
            resource_type=res.resource_type,
            resource_name=res.name,
            file_path=res.file_path,
            suggestion="Add lifecycle { prevent_destroy = true } for stateful resources in production",
        ))


def _check_file_naming(tf, issues):
    """TF-BP-008: Terraform file name doesn't follow conventions."""
    filename = os.path.basename(tf.path)
    if filename in STANDARD_TF_NAMES:
        return
    # Allow descriptive names like networking.tf, compute.tf — just check format
    if not filename.endswith(".tf"):
        return
    name_part = filename[:-3]
    if not re.match(r"^[a-z][a-z0-9_-]*$", name_part):
        issues.append(Issue(
            rule_id="TF-BP-008",
            severity=Severity.LOW,
            category=Category.BEST_PRACTICES,
            message=f"File '{filename}' doesn't follow naming conventions (lowercase, hyphens/underscores)",
            file_path=tf.path,
            suggestion="Use lowercase names: main.tf, variables.tf, networking.tf",
        ))


def _check_provisioner_usage(res, issues):
    """TF-BP-015: Resource uses provisioner (anti-pattern)."""
    if "provisioner" in res.config:
        issues.append(Issue(
            rule_id="TF-BP-015",
            severity=Severity.MEDIUM,
            category=Category.BEST_PRACTICES,
            message=f"Resource '{res.resource_type}.{res.name}' uses a provisioner (anti-pattern)",
            resource_type=res.resource_type,
            resource_name=res.name,
            file_path=res.file_path,
            suggestion="Replace provisioners with cloud-init, user_data, or configuration management tools",
        ))
