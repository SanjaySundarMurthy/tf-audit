"""Module quality analyzer — checks variables, outputs, providers, state, and module configs.

12 rules (TF-MOD-001 to TF-MOD-012).
"""
import re
from tf_audit.models import Issue, Severity, Category, TfFile


def analyze(tf_files: list) -> list:
    """Run all module quality checks."""
    issues = []

    all_variables = []
    all_outputs = []
    all_modules = []
    all_terraform = []
    all_providers = []

    for tf in tf_files:
        for var in tf.variables:
            all_variables.append((var, tf.path))
        for out in tf.outputs:
            all_outputs.append((out, tf.path))
        for mod in tf.modules:
            all_modules.append((mod, tf.path))
        all_terraform.extend(tf.terraform_blocks)
        for prov in tf.providers:
            all_providers.append((prov, tf.path))

    # Module source checks
    for mod, fpath in all_modules:
        _check_module_source_pin(mod, fpath, issues)
        _check_module_local_source(mod, fpath, issues)

    # Variable checks
    for var, fpath in all_variables:
        _check_variable_description(var, fpath, issues)
        _check_variable_type(var, fpath, issues)

    # Output checks
    for out, fpath in all_outputs:
        _check_output_description(out, fpath, issues)

    # Terraform block checks
    _check_required_providers(all_terraform, tf_files, issues)
    _check_provider_version_constraint(all_providers, issues)
    _check_terraform_version(all_terraform, tf_files, issues)
    _check_backend_config(all_terraform, tf_files, issues)
    _check_backend_locking(all_terraform, tf_files, issues)

    return issues


def _check_module_source_pin(mod, file_path, issues):
    """TF-MOD-001: Module source not pinned to version."""
    source = mod.get("source", "")
    if not isinstance(source, str):
        return
    # Registry modules should have version pinned
    if source.startswith("registry.terraform.io") or (not source.startswith("./") and not source.startswith("../") and not source.startswith("git:") and "/" in source and "::" not in source):
        version = mod.get("version", "")
        if not version:
            issues.append(Issue(
                rule_id="TF-MOD-001",
                severity=Severity.HIGH,
                category=Category.MODULES,
                message=f"Module '{mod.get('_name', '?')}' source is not version-pinned",
                file_path=file_path,
                suggestion="Add version constraint: version = \"~> 1.0\"",
            ))
    # Git sources should have ref
    elif source.startswith("git::") or source.startswith("github.com"):
        if "?ref=" not in source and "//?" not in source:
            issues.append(Issue(
                rule_id="TF-MOD-001",
                severity=Severity.HIGH,
                category=Category.MODULES,
                message=f"Module '{mod.get('_name', '?')}' git source has no version ref",
                file_path=file_path,
                suggestion="Pin to a specific tag or commit: ?ref=v1.0.0",
            ))


def _check_module_local_source(mod, file_path, issues):
    """TF-MOD-002: Module sourced from local path."""
    source = mod.get("source", "")
    if isinstance(source, str) and (source.startswith("./") or source.startswith("../")):
        issues.append(Issue(
            rule_id="TF-MOD-002",
            severity=Severity.INFO,
            category=Category.MODULES,
            message=f"Module '{mod.get('_name', '?')}' uses local source path: {source}",
            file_path=file_path,
            suggestion="Consider publishing to a private registry for reuse across teams",
        ))


def _check_variable_description(var, file_path, issues):
    """TF-MOD-003: Variable without description."""
    name = var.get("_name", "")
    if not var.get("description"):
        issues.append(Issue(
            rule_id="TF-MOD-003",
            severity=Severity.MEDIUM,
            category=Category.MODULES,
            message=f"Variable '{name}' has no description",
            file_path=file_path,
            suggestion="Add description = \"...\" to document the variable's purpose",
        ))


def _check_variable_type(var, file_path, issues):
    """TF-MOD-004: Variable without type constraint."""
    name = var.get("_name", "")
    if "type" not in var:
        issues.append(Issue(
            rule_id="TF-MOD-004",
            severity=Severity.MEDIUM,
            category=Category.MODULES,
            message=f"Variable '{name}' has no type constraint",
            file_path=file_path,
            suggestion="Add type = string|number|bool|list|map|object to enforce input types",
        ))


def _check_output_description(out, file_path, issues):
    """TF-MOD-006: Output without description."""
    name = out.get("_name", "")
    if not out.get("description"):
        issues.append(Issue(
            rule_id="TF-MOD-006",
            severity=Severity.LOW,
            category=Category.MODULES,
            message=f"Output '{name}' has no description",
            file_path=file_path,
            suggestion="Add description = \"...\" to document the output",
        ))


def _check_required_providers(terraform_blocks, tf_files, issues):
    """TF-MOD-007: No required_providers block."""
    has_required = False
    for tb in terraform_blocks:
        if "required_providers" in tb:
            has_required = True
            break
    if not has_required and tf_files:
        issues.append(Issue(
            rule_id="TF-MOD-007",
            severity=Severity.MEDIUM,
            category=Category.MODULES,
            message="No required_providers block found",
            file_path=tf_files[0].path if tf_files else "",
            suggestion="Add terraform { required_providers { ... } } to pin provider versions",
        ))


def _check_provider_version_constraint(providers, issues):
    """TF-MOD-008: Provider without version constraint (inline provider block)."""
    for prov, fpath in providers:
        name = prov.get("_name", "")
        version = prov.get("version", "")
        if version:
            # Inline version in provider block is deprecated
            issues.append(Issue(
                rule_id="TF-MOD-008",
                severity=Severity.LOW,
                category=Category.MODULES,
                message=f"Provider '{name}' has inline version constraint (deprecated)",
                file_path=fpath,
                suggestion="Move version constraints to terraform { required_providers { } }",
            ))


def _check_terraform_version(terraform_blocks, tf_files, issues):
    """TF-MOD-009: Terraform version not constrained."""
    has_version = False
    for tb in terraform_blocks:
        if "required_version" in tb:
            has_version = True
            break
    if not has_version and tf_files:
        issues.append(Issue(
            rule_id="TF-MOD-009",
            severity=Severity.MEDIUM,
            category=Category.MODULES,
            message="No required_version constraint found",
            file_path=tf_files[0].path if tf_files else "",
            suggestion="Add terraform { required_version = \">= 1.5\" } to pin Terraform version",
        ))


def _check_backend_config(terraform_blocks, tf_files, issues):
    """TF-MOD-010: Missing backend configuration."""
    has_backend = False
    for tb in terraform_blocks:
        if "backend" in tb:
            has_backend = True
            break
    if not has_backend and tf_files:
        issues.append(Issue(
            rule_id="TF-MOD-010",
            severity=Severity.MEDIUM,
            category=Category.STATE,
            message="No backend configuration found — state stored locally",
            file_path=tf_files[0].path if tf_files else "",
            suggestion="Configure a remote backend (S3, Azure Blob, GCS) for team collaboration",
        ))


def _check_backend_locking(terraform_blocks, tf_files, issues):
    """TF-MOD-011: Backend without state locking."""
    for tb in terraform_blocks:
        backend = tb.get("backend", {})
        if isinstance(backend, dict):
            for backend_type, config in backend.items():
                if isinstance(config, dict):
                    # S3 backend should have dynamodb_table
                    if backend_type == "s3" and not config.get("dynamodb_table"):
                        issues.append(Issue(
                            rule_id="TF-MOD-011",
                            severity=Severity.HIGH,
                            category=Category.STATE,
                            message="S3 backend does not have DynamoDB state locking configured",
                            file_path=tf_files[0].path if tf_files else "",
                            suggestion="Add dynamodb_table for state locking to prevent concurrent modifications",
                        ))
