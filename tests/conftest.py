"""Shared test fixtures for tf-audit."""
import pytest


@pytest.fixture
def tmp_tf(tmp_path):
    """Factory fixture: creates temp directory with .tf files."""
    def _make(tf_files: dict):
        tf_dir = tmp_path / "terraform"
        tf_dir.mkdir(exist_ok=True)
        for name, content in tf_files.items():
            (tf_dir / name).write_text(content, encoding="utf-8")
        return str(tf_dir)
    return _make


@pytest.fixture
def secure_main_tf():
    return '''
terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    bucket         = "my-state-bucket"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-locks"
  }
}

provider "aws" {
  region = var.region
}

resource "aws_s3_bucket" "app_data" {
  bucket = "my-secure-bucket"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = {
    Environment = "production"
    Team        = "platform"
  }
}

resource "aws_db_instance" "primary" {
  engine               = "postgres"
  instance_class       = "db.t3.medium"
  storage_encrypted    = true
  publicly_accessible  = false
  backup_retention_period = 14

  tags = {
    Environment = "production"
  }
}
'''


@pytest.fixture
def secure_variables_tf():
    return '''
variable "region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "db_password" {
  description = "Database master password"
  type        = string
  sensitive   = true
}
'''


@pytest.fixture
def secure_outputs_tf():
    return '''
output "bucket_arn" {
  description = "ARN of the S3 bucket"
  value       = aws_s3_bucket.app_data.arn
}

output "db_password" {
  description = "Database password"
  value       = aws_db_instance.primary.password
  sensitive   = true
}
'''


@pytest.fixture
def insecure_main_tf():
    return '''
provider "aws" {
  region  = "us-east-1"
  version = "~> 5.0"
}

resource "aws_s3_bucket" "data" {
  bucket = "public-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name = "web-sg"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "main" {
  engine              = "mysql"
  instance_class      = "db.t3.medium"
  publicly_accessible = true
  storage_encrypted   = false
  backup_retention_period = 1
}

resource "aws_ebs_volume" "this" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

resource "aws_kms_key" "main" {
  enable_key_rotation = false
}

resource "tls_private_key" "ssh" {
  algorithm = "RSA"
}

resource "aws_iam_role_policy" "admin" {
  name   = "admin"
  role   = "admin-role"
  policy = <<-EOF
    {"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
  EOF
}

resource "aws_lb_listener" "http" {
  port     = 80
  protocol = "HTTP"
  default_action {
    type = "forward"
  }
}
'''


@pytest.fixture
def insecure_variables_tf():
    return '''
variable "region" {
}

variable "db_password" {
  type = string
}

variable "api_token" {
  type    = string
  default = "tok-abc123"
}

variable "instanceCount" {
  description = "Count"
  type        = number
}
'''


@pytest.fixture
def insecure_outputs_tf():
    return '''
output "vpc_id" {
  value = "vpc-12345"
}

output "database_password" {
  value = "secret"
}
'''


@pytest.fixture
def good_tf_dir(tmp_tf, secure_main_tf, secure_variables_tf, secure_outputs_tf):
    return tmp_tf({
        "main.tf": secure_main_tf,
        "variables.tf": secure_variables_tf,
        "outputs.tf": secure_outputs_tf,
    })


@pytest.fixture
def bad_tf_dir(tmp_tf, insecure_main_tf, insecure_variables_tf, insecure_outputs_tf):
    return tmp_tf({
        "main.tf": insecure_main_tf,
        "variables.tf": insecure_variables_tf,
        "outputs.tf": insecure_outputs_tf,
    })
