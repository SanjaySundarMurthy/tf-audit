"""Demo module — creates realistic Terraform files with intentional issues."""
import os
import tempfile


def create_demo_terraform() -> str:
    """Create a demo Terraform project with intentional misconfigurations.

    Returns:
        Path to the demo directory containing .tf files.
    """
    demo_dir = os.path.join(tempfile.mkdtemp(prefix="tf-audit-demo-"), "insecure-infra")
    os.makedirs(demo_dir, exist_ok=True)

    # ─── main.tf — Core infrastructure with security issues ─────────────
    (open(os.path.join(demo_dir, "main.tf"), "w", encoding="utf-8")).write('''# Demo infrastructure — intentionally insecure for tf-audit demo
# DO NOT deploy this to any environment!

terraform {
  required_version = ">= 1.5"
}

provider "aws" {
  region  = "us-east-1"
  version = "~> 5.0"
}

# ─── VPC ────────────────────────────────────────────────────────────────
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "public" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}

# ─── Security Group — WIDE OPEN ────────────────────────────────────────
resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Web security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ─── S3 Bucket — No encryption, public ACL ─────────────────────────────
resource "aws_s3_bucket" "data" {
  bucket = "my-insecure-data-bucket"
  acl    = "public-read"
}

# ─── RDS — Public, unencrypted, weak backup ─────────────────────────────
resource "aws_db_instance" "database" {
  engine               = "mysql"
  instance_class       = "db.t3.medium"
  allocated_storage    = 20
  publicly_accessible  = true
  storage_encrypted    = false
  backup_retention_period = 1
  username             = "admin"
  password             = "SuperSecret123!"
  skip_final_snapshot  = true
}

# ─── EBS Volume — Unencrypted ───────────────────────────────────────────
resource "aws_ebs_volume" "data_vol" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

# ─── KMS Key — No rotation ─────────────────────────────────────────────
resource "aws_kms_key" "app_key" {
  description         = "Application encryption key"
  enable_key_rotation = false
}

# ─── Load Balancer — HTTP only ──────────────────────────────────────────
resource "aws_lb" "web_alb" {
  name               = "web-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = [aws_subnet.public.id]
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.web_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789:targetgroup/web/abc123"
  }
}

# ─── CloudTrail — Single region, no log validation ──────────────────────
resource "aws_cloudtrail" "audit" {
  name                          = "audit-trail"
  s3_bucket_name                = aws_s3_bucket.data.id
  is_multi_region_trail         = false
  enable_log_file_validation    = false
}

# ─── TLS Private Key in State ──────────────────────────────────────────
resource "tls_private_key" "ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# ─── IAM Policy with Wildcards ─────────────────────────────────────────
resource "aws_iam_role_policy" "admin" {
  name = "admin-policy"
  role = "admin-role"
  policy = <<-EOF
    {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
      }]
    }
  EOF
}
''')

    # ─── variables.tf — Missing descriptions and types ──────────────────
    (open(os.path.join(demo_dir, "variables.tf"), "w", encoding="utf-8")).write('''# Variables with intentional issues

variable "region" {
}

variable "Environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
}

variable "db_password" {
  type = string
}

variable "api_token" {
  description = "API authentication token"
  type        = string
  default     = "tok-abc123"
}

variable "instanceCount" {
  description = "Number of instances"
  type        = number
  default     = 3
}
''')

    # ─── outputs.tf — Missing descriptions, sensitive leaks ─────────────
    (open(os.path.join(demo_dir, "outputs.tf"), "w", encoding="utf-8")).write('''# Outputs with intentional issues

output "vpc_id" {
  value = aws_vpc.main.id
}

output "database_password" {
  value = aws_db_instance.database.password
}

output "private_key_pem" {
  value = tls_private_key.ssh_key.private_key_pem
}

output "bucket_arn" {
  description = "S3 bucket ARN"
  value       = aws_s3_bucket.data.arn
}
''')

    # ─── modules.tf — Unpinned module sources ───────────────────────────
    (open(os.path.join(demo_dir, "modules.tf"), "w", encoding="utf-8")).write('''# Module calls with issues

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  # Missing version pin!

  name = "production-vpc"
  cidr = "10.0.0.0/16"
}

module "Custom-Module" {
  source = "git::https://github.com/example/terraform-module.git"
  # Git source without ref!
}

module "local_utils" {
  source = "../shared/utils"
}
''')

    # ─── azure.tf — Azure resources with issues ─────────────────────────
    (open(os.path.join(demo_dir, "azure.tf"), "w", encoding="utf-8")).write('''# Azure resources with security issues

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "main" {
  name     = "rg-production"
  location = "East US"
}

resource "azurerm_storage_account" "data" {
  name                     = "insecurestorageacct"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  enable_https_traffic_only = false
}

resource "azurerm_network_security_rule" "allow_all" {
  name                        = "allow-all-inbound"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.main.name
  network_security_group_name = "main-nsg"
}

resource "azurerm_key_vault" "secrets" {
  name                = "insecure-keyvault"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"

  purge_protection_enabled = false
}
''')

    return demo_dir
