"""Security analyzer — scans Terraform resources for security misconfigurations.

20 rules (TF-SEC-001 to TF-SEC-020) covering AWS, Azure, and GCP resources.
"""
from tf_audit.models import Issue, Severity, Category, TfFile


def analyze(tf_files: list) -> list:
    """Run all security checks across parsed Terraform files."""
    issues = []
    for tf in tf_files:
        for res in tf.resources:
            _check_s3_encryption(res, issues)
            _check_s3_public_access(res, issues)
            _check_sg_open_ingress(res, issues)
            _check_sg_all_ports(res, issues)
            _check_rds_public(res, issues)
            _check_rds_encryption(res, issues)
            _check_azure_storage_https(res, issues)
            _check_azure_nsg_open(res, issues)
            _check_gcp_firewall_open(res, issues)
            _check_iam_wildcard(res, issues)
            _check_kms_rotation(res, issues)
            _check_ebs_encryption(res, issues)
            _check_cloudtrail(res, issues)
            _check_vpc_flow_logs(res, issues)
            _check_lb_https(res, issues)
            _check_db_backup(res, issues)
            _check_ssh_key_encryption(res, issues)
            _check_container_readonly(res, issues)
            _check_waf_alb(res, issues)
            _check_azure_keyvault_purge(res, issues)
    return issues


# ─── AWS Rules ──────────────────────────────────────────────────────────────

def _check_s3_encryption(res, issues):
    """TF-SEC-001: S3 bucket without server-side encryption."""
    if res.resource_type != "aws_s3_bucket":
        return
    config = res.config
    # Check for server_side_encryption_configuration
    has_sse = "server_side_encryption_configuration" in config
    if not has_sse:
        issues.append(Issue(
            rule_id="TF-SEC-001",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            message=f"S3 bucket '{res.name}' has no server-side encryption configured",
            resource_type=res.resource_type,
            resource_name=res.name,
            file_path=res.file_path,
            suggestion="Add server_side_encryption_configuration with AES256 or aws:kms",
            doc_url="https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#server_side_encryption_configuration",
        ))


def _check_s3_public_access(res, issues):
    """TF-SEC-002: S3 bucket with public ACL."""
    if res.resource_type != "aws_s3_bucket":
        return
    acl = res.config.get("acl", "")
    if isinstance(acl, str) and acl in ("public-read", "public-read-write", "authenticated-read"):
        issues.append(Issue(
            rule_id="TF-SEC-002",
            severity=Severity.CRITICAL,
            category=Category.SECURITY,
            message=f"S3 bucket '{res.name}' has public ACL: {acl}",
            resource_type=res.resource_type,
            resource_name=res.name,
            file_path=res.file_path,
            suggestion="Set acl to 'private' and use aws_s3_bucket_public_access_block",
        ))


def _check_sg_open_ingress(res, issues):
    """TF-SEC-003: Security group allows 0.0.0.0/0 ingress."""
    if res.resource_type != "aws_security_group":
        return
    for ingress in _get_list(res.config, "ingress"):
        cidrs = _get_list(ingress, "cidr_blocks")
        for cidr in cidrs:
            if cidr == "0.0.0.0/0":
                issues.append(Issue(
                    rule_id="TF-SEC-003",
                    severity=Severity.CRITICAL,
                    category=Category.SECURITY,
                    message=f"Security group '{res.name}' allows ingress from 0.0.0.0/0",
                    resource_type=res.resource_type,
                    resource_name=res.name,
                    file_path=res.file_path,
                    suggestion="Restrict cidr_blocks to specific IP ranges",
                ))
                return


def _check_sg_all_ports(res, issues):
    """TF-SEC-004: Security group allows all ports."""
    if res.resource_type != "aws_security_group":
        return
    for ingress in _get_list(res.config, "ingress"):
        from_port = ingress.get("from_port", -1)
        to_port = ingress.get("to_port", -1)
        if from_port == 0 and to_port == 65535:
            issues.append(Issue(
                rule_id="TF-SEC-004",
                severity=Severity.HIGH,
                category=Category.SECURITY,
                message=f"Security group '{res.name}' allows all ports (0-65535)",
                resource_type=res.resource_type,
                resource_name=res.name,
                file_path=res.file_path,
                suggestion="Restrict port range to only required ports",
            ))
            return


def _check_rds_public(res, issues):
    """TF-SEC-005: RDS instance publicly accessible."""
    if res.resource_type != "aws_db_instance":
        return
    if res.config.get("publicly_accessible") is True:
        issues.append(Issue(
            rule_id="TF-SEC-005",
            severity=Severity.CRITICAL,
            category=Category.SECURITY,
            message=f"RDS instance '{res.name}' is publicly accessible",
            resource_type=res.resource_type,
            resource_name=res.name,
            file_path=res.file_path,
            suggestion="Set publicly_accessible = false",
        ))


def _check_rds_encryption(res, issues):
    """TF-SEC-006: RDS instance without encryption."""
    if res.resource_type != "aws_db_instance":
        return
    if res.config.get("storage_encrypted") is not True:
        issues.append(Issue(
            rule_id="TF-SEC-006",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            message=f"RDS instance '{res.name}' does not have storage encryption enabled",
            resource_type=res.resource_type,
            resource_name=res.name,
            file_path=res.file_path,
            suggestion="Set storage_encrypted = true and specify kms_key_id",
        ))


# ─── Azure Rules ────────────────────────────────────────────────────────────

def _check_azure_storage_https(res, issues):
    """TF-SEC-007: Azure Storage account without HTTPS enforcement."""
    if res.resource_type != "azurerm_storage_account":
        return
    if res.config.get("enable_https_traffic_only") is False:
        issues.append(Issue(
            rule_id="TF-SEC-007",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            message=f"Azure Storage '{res.name}' does not enforce HTTPS-only traffic",
            resource_type=res.resource_type,
            resource_name=res.name,
            file_path=res.file_path,
            suggestion="Set enable_https_traffic_only = true (default in recent provider versions)",
        ))


def _check_azure_nsg_open(res, issues):
    """TF-SEC-008: Azure NSG rule allows 0.0.0.0/0."""
    if res.resource_type != "azurerm_network_security_rule":
        return
    src = res.config.get("source_address_prefix", "")
    if isinstance(src, str) and src in ("*", "0.0.0.0/0", "Internet"):
        access = res.config.get("access", "")
        if isinstance(access, str) and access.lower() == "allow":
            issues.append(Issue(
                rule_id="TF-SEC-008",
                severity=Severity.CRITICAL,
                category=Category.SECURITY,
                message=f"Azure NSG rule '{res.name}' allows inbound from {src}",
                resource_type=res.resource_type,
                resource_name=res.name,
                file_path=res.file_path,
                suggestion="Restrict source_address_prefix to specific CIDR ranges",
            ))


# ─── GCP Rules ──────────────────────────────────────────────────────────────

def _check_gcp_firewall_open(res, issues):
    """TF-SEC-009: GCP firewall rule allows 0.0.0.0/0."""
    if res.resource_type != "google_compute_firewall":
        return
    sources = _get_list(res.config, "source_ranges")
    if "0.0.0.0/0" in sources:
        issues.append(Issue(
            rule_id="TF-SEC-009",
            severity=Severity.CRITICAL,
            category=Category.SECURITY,
            message=f"GCP firewall '{res.name}' allows traffic from 0.0.0.0/0",
            resource_type=res.resource_type,
            resource_name=res.name,
            file_path=res.file_path,
            suggestion="Restrict source_ranges to specific CIDR blocks",
        ))


# ─── Cross-Cloud Rules ─────────────────────────────────────────────────────

def _check_iam_wildcard(res, issues):
    """TF-SEC-010: IAM policy with wildcard actions or resources."""
    iam_types = ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy",
                 "aws_iam_group_policy", "google_project_iam_binding")
    if res.resource_type not in iam_types:
        return
    policy = res.config.get("policy", "")
    if isinstance(policy, str) and '"*"' in policy:
        issues.append(Issue(
            rule_id="TF-SEC-010",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            message=f"IAM policy '{res.name}' contains wildcard (*) actions or resources",
            resource_type=res.resource_type,
            resource_name=res.name,
            file_path=res.file_path,
            suggestion="Follow least-privilege principle — specify exact actions and resources",
        ))


def _check_kms_rotation(res, issues):
    """TF-SEC-011: KMS key without automatic rotation."""
    if res.resource_type != "aws_kms_key":
        return
    if res.config.get("enable_key_rotation") is not True:
        issues.append(Issue(
            rule_id="TF-SEC-011",
            severity=Severity.MEDIUM,
            category=Category.SECURITY,
            message=f"KMS key '{res.name}' does not have automatic key rotation enabled",
            resource_type=res.resource_type,
            resource_name=res.name,
            file_path=res.file_path,
            suggestion="Set enable_key_rotation = true",
        ))


def _check_ebs_encryption(res, issues):
    """TF-SEC-012: EBS volume without encryption."""
    if res.resource_type != "aws_ebs_volume":
        return
    if res.config.get("encrypted") is not True:
        issues.append(Issue(
            rule_id="TF-SEC-012",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            message=f"EBS volume '{res.name}' is not encrypted",
            resource_type=res.resource_type,
            resource_name=res.name,
            file_path=res.file_path,
            suggestion="Set encrypted = true and specify kms_key_id",
        ))


def _check_cloudtrail(res, issues):
    """TF-SEC-013: CloudTrail without multi-region or log validation."""
    if res.resource_type != "aws_cloudtrail":
        return
    if res.config.get("is_multi_region_trail") is not True:
        issues.append(Issue(
            rule_id="TF-SEC-013",
            severity=Severity.MEDIUM,
            category=Category.SECURITY,
            message=f"CloudTrail '{res.name}' is not configured for multi-region",
            resource_type=res.resource_type,
            resource_name=res.name,
            file_path=res.file_path,
            suggestion="Set is_multi_region_trail = true for complete audit coverage",
        ))
    if res.config.get("enable_log_file_validation") is not True:
        issues.append(Issue(
            rule_id="TF-SEC-013",
            severity=Severity.MEDIUM,
            category=Category.SECURITY,
            message=f"CloudTrail '{res.name}' does not enable log file validation",
            resource_type=res.resource_type,
            resource_name=res.name,
            file_path=res.file_path,
            suggestion="Set enable_log_file_validation = true",
        ))


def _check_vpc_flow_logs(res, issues):
    """TF-SEC-014: VPC without flow logs (heuristic — checks VPC existence)."""
    # We check if there's a VPC but we flag it for awareness
    if res.resource_type == "aws_vpc":
        # This is a heuristic — we can't easily check if flow logs exist in another resource
        # We flag as INFO to remind users
        issues.append(Issue(
            rule_id="TF-SEC-014",
            severity=Severity.INFO,
            category=Category.SECURITY,
            message=f"VPC '{res.name}' found — ensure aws_flow_log is configured for this VPC",
            resource_type=res.resource_type,
            resource_name=res.name,
            file_path=res.file_path,
            suggestion="Add aws_flow_log resource pointing to this VPC",
        ))


def _check_lb_https(res, issues):
    """TF-SEC-015: Load balancer listener without HTTPS."""
    if res.resource_type == "aws_lb_listener":
        protocol = res.config.get("protocol", "")
        if isinstance(protocol, str) and protocol.upper() == "HTTP":
            issues.append(Issue(
                rule_id="TF-SEC-015",
                severity=Severity.HIGH,
                category=Category.SECURITY,
                message=f"Load balancer listener '{res.name}' uses HTTP instead of HTTPS",
                resource_type=res.resource_type,
                resource_name=res.name,
                file_path=res.file_path,
                suggestion="Use protocol = 'HTTPS' with a valid SSL certificate",
            ))
    elif res.resource_type == "azurerm_lb_rule":
        protocol = res.config.get("protocol", "")
        if isinstance(protocol, str) and protocol.lower() == "tcp":
            port = res.config.get("frontend_port", 0)
            if port == 80:
                issues.append(Issue(
                    rule_id="TF-SEC-015",
                    severity=Severity.MEDIUM,
                    category=Category.SECURITY,
                    message=f"Azure LB rule '{res.name}' serves on port 80 (HTTP)",
                    resource_type=res.resource_type,
                    resource_name=res.name,
                    file_path=res.file_path,
                    suggestion="Redirect HTTP to HTTPS or serve on port 443",
                ))


def _check_db_backup(res, issues):
    """TF-SEC-016: Database without backup retention."""
    db_types = ("aws_db_instance", "azurerm_mssql_database", "azurerm_postgresql_server",
                "google_sql_database_instance")
    if res.resource_type not in db_types:
        return

    if res.resource_type == "aws_db_instance":
        retention = res.config.get("backup_retention_period", 0)
        if isinstance(retention, (int, float)) and retention < 7:
            issues.append(Issue(
                rule_id="TF-SEC-016",
                severity=Severity.MEDIUM,
                category=Category.SECURITY,
                message=f"RDS '{res.name}' backup retention is less than 7 days ({retention})",
                resource_type=res.resource_type,
                resource_name=res.name,
                file_path=res.file_path,
                suggestion="Set backup_retention_period >= 7",
            ))

    elif res.resource_type == "google_sql_database_instance":
        settings = res.config.get("settings", {}) or {}
        if isinstance(settings, list):
            settings = settings[0] if settings else {}
        backup = settings.get("backup_configuration", {})
        if isinstance(backup, list):
            backup = backup[0] if backup else {}
        if not backup or backup.get("enabled") is not True:
            issues.append(Issue(
                rule_id="TF-SEC-016",
                severity=Severity.MEDIUM,
                category=Category.SECURITY,
                message=f"Cloud SQL '{res.name}' does not have backups enabled",
                resource_type=res.resource_type,
                resource_name=res.name,
                file_path=res.file_path,
                suggestion="Enable backup_configuration with enabled = true",
            ))


def _check_ssh_key_encryption(res, issues):
    """TF-SEC-017: TLS private key resource (secrets in state)."""
    if res.resource_type == "tls_private_key":
        issues.append(Issue(
            rule_id="TF-SEC-017",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            message=f"tls_private_key '{res.name}' stores private key in Terraform state",
            resource_type=res.resource_type,
            resource_name=res.name,
            file_path=res.file_path,
            suggestion="Use an external secrets manager or generate keys outside Terraform",
        ))


def _check_container_readonly(res, issues):
    """TF-SEC-018: ECS/AKS container missing read-only root filesystem."""
    if res.resource_type == "aws_ecs_task_definition":
        container_defs = res.config.get("container_definitions", "")
        if isinstance(container_defs, str) and '"readonlyRootFilesystem":false' in container_defs.replace(" ", "").lower():
            issues.append(Issue(
                rule_id="TF-SEC-018",
                severity=Severity.MEDIUM,
                category=Category.SECURITY,
                message=f"ECS task '{res.name}' has container without read-only root filesystem",
                resource_type=res.resource_type,
                resource_name=res.name,
                file_path=res.file_path,
                suggestion="Set readonlyRootFilesystem: true in container definitions",
            ))


def _check_waf_alb(res, issues):
    """TF-SEC-019: ALB without WAF association (heuristic)."""
    if res.resource_type == "aws_lb":
        lb_type = res.config.get("internal", False)
        load_balancer_type = res.config.get("load_balancer_type", "application")
        if not lb_type and load_balancer_type == "application":
            issues.append(Issue(
                rule_id="TF-SEC-019",
                severity=Severity.INFO,
                category=Category.SECURITY,
                message=f"Public ALB '{res.name}' — ensure WAF is associated via aws_wafv2_web_acl_association",
                resource_type=res.resource_type,
                resource_name=res.name,
                file_path=res.file_path,
                suggestion="Add aws_wafv2_web_acl_association for this ALB",
            ))


def _check_azure_keyvault_purge(res, issues):
    """TF-SEC-020: Azure Key Vault without purge protection."""
    if res.resource_type != "azurerm_key_vault":
        return
    if res.config.get("purge_protection_enabled") is not True:
        issues.append(Issue(
            rule_id="TF-SEC-020",
            severity=Severity.MEDIUM,
            category=Category.SECURITY,
            message=f"Key Vault '{res.name}' does not have purge protection enabled",
            resource_type=res.resource_type,
            resource_name=res.name,
            file_path=res.file_path,
            suggestion="Set purge_protection_enabled = true",
        ))


# ─── Helpers ────────────────────────────────────────────────────────────────

def _get_list(d, key):
    """Safely get a list from a dict, handling various HCL2 parsing formats."""
    val = d.get(key, [])
    if isinstance(val, list):
        return val
    if isinstance(val, dict):
        return [val]
    return []
