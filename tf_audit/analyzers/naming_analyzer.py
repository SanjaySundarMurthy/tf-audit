"""Naming convention analyzer — checks resource, variable, output, and module naming.

8 rules (TF-NAM-001 to TF-NAM-008).
"""
import re
from tf_audit.models import Issue, Severity, Category, TfFile


SNAKE_CASE_RE = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$")
GENERIC_NAMES = {"main", "this", "that", "default", "example", "test", "tmp", "temp", "my", "foo", "bar"}


def analyze(tf_files: list) -> list:
    """Run all naming convention checks."""
    issues = []
    for tf in tf_files:
        for res in tf.resources:
            _check_resource_uppercase(res, issues)
            _check_resource_spaces(res, issues)
            _check_resource_snake_case(res, issues)
            _check_resource_generic(res, issues)
        for var in tf.variables:
            _check_variable_naming(var, tf.path, issues)
        for out in tf.outputs:
            _check_output_naming(out, tf.path, issues)
        for mod in tf.modules:
            _check_module_naming(mod, tf.path, issues)
        for ds in tf.data_sources:
            _check_data_source_naming(ds, issues)
    return issues


def _check_resource_uppercase(res, issues):
    """TF-NAM-001: Resource name uses uppercase."""
    if res.name != res.name.lower():
        issues.append(Issue(
            rule_id="TF-NAM-001",
            severity=Severity.LOW,
            category=Category.NAMING,
            message=f"Resource '{res.resource_type}.{res.name}' uses uppercase characters",
            resource_type=res.resource_type,
            resource_name=res.name,
            file_path=res.file_path,
            suggestion="Use lowercase snake_case for resource names",
        ))


def _check_resource_spaces(res, issues):
    """TF-NAM-002: Resource name contains spaces or hyphens."""
    if " " in res.name or "-" in res.name:
        issues.append(Issue(
            rule_id="TF-NAM-002",
            severity=Severity.MEDIUM,
            category=Category.NAMING,
            message=f"Resource '{res.resource_type}.{res.name}' contains spaces or hyphens",
            resource_type=res.resource_type,
            resource_name=res.name,
            file_path=res.file_path,
            suggestion="Use underscores instead of spaces/hyphens in resource names",
        ))


def _check_resource_snake_case(res, issues):
    """TF-NAM-003: Resource name doesn't follow snake_case convention."""
    # Skip if already caught by other rules
    if res.name != res.name.lower() or " " in res.name or "-" in res.name:
        return
    if not SNAKE_CASE_RE.match(res.name):
        issues.append(Issue(
            rule_id="TF-NAM-003",
            severity=Severity.LOW,
            category=Category.NAMING,
            message=f"Resource '{res.resource_type}.{res.name}' doesn't follow snake_case convention",
            resource_type=res.resource_type,
            resource_name=res.name,
            file_path=res.file_path,
            suggestion="Use snake_case: lowercase letters, numbers, and underscores only",
        ))


def _check_resource_generic(res, issues):
    """TF-NAM-007: Resource name is too generic."""
    if res.name.lower() in GENERIC_NAMES:
        issues.append(Issue(
            rule_id="TF-NAM-007",
            severity=Severity.LOW,
            category=Category.NAMING,
            message=f"Resource '{res.resource_type}.{res.name}' has a generic name",
            resource_type=res.resource_type,
            resource_name=res.name,
            file_path=res.file_path,
            suggestion="Use descriptive names that indicate the resource's purpose",
        ))


def _check_variable_naming(var, file_path, issues):
    """TF-NAM-004: Variable name doesn't follow snake_case convention."""
    name = var.get("_name", "")
    if not name:
        return
    if not SNAKE_CASE_RE.match(name):
        issues.append(Issue(
            rule_id="TF-NAM-004",
            severity=Severity.LOW,
            category=Category.NAMING,
            message=f"Variable '{name}' doesn't follow snake_case convention",
            file_path=file_path,
            suggestion="Use snake_case for variable names",
        ))


def _check_output_naming(out, file_path, issues):
    """TF-NAM-005: Output name doesn't follow snake_case convention."""
    name = out.get("_name", "")
    if not name:
        return
    if not SNAKE_CASE_RE.match(name):
        issues.append(Issue(
            rule_id="TF-NAM-005",
            severity=Severity.LOW,
            category=Category.NAMING,
            message=f"Output '{name}' doesn't follow snake_case convention",
            file_path=file_path,
            suggestion="Use snake_case for output names",
        ))


def _check_module_naming(mod, file_path, issues):
    """TF-NAM-006: Module call name doesn't follow snake_case convention."""
    name = mod.get("_name", "")
    if not name:
        return
    if not SNAKE_CASE_RE.match(name):
        issues.append(Issue(
            rule_id="TF-NAM-006",
            severity=Severity.LOW,
            category=Category.NAMING,
            message=f"Module call '{name}' doesn't follow snake_case convention",
            file_path=file_path,
            suggestion="Use snake_case for module call names",
        ))


def _check_data_source_naming(ds, issues):
    """TF-NAM-008: Data source name doesn't follow snake_case convention."""
    if not SNAKE_CASE_RE.match(ds.name):
        issues.append(Issue(
            rule_id="TF-NAM-008",
            severity=Severity.LOW,
            category=Category.NAMING,
            message=f"Data source '{ds.resource_type}.{ds.name}' doesn't follow snake_case convention",
            resource_type=ds.resource_type,
            resource_name=ds.name,
            file_path=ds.file_path,
            suggestion="Use snake_case for data source names",
        ))
