########################################################################
# SecAudit lab environment - DELIBERATELY VULNERABLE. DO NOT reuse any
# of these patterns in production. Purpose: give SecAudit a realistic,
# disposable network target with textbook misconfigurations so its
# findings can be demonstrated end-to-end.
#
# Misconfigurations baked in on purpose:
#   - Security group open to 0.0.0.0/0 on SSH(22), FTP(21), Telnet(23),
#     RDP(3389), and SMB(445)
#   - An EC2 instance running vsftpd (anonymous upload allowed) and
#     an old OpenSSH build
#   - An S3 bucket with public-read ACL and no encryption
#   - IAM user with an overly broad inline policy (AdministratorAccess)
#
# Cost note: t3.micro is Free Tier eligible in most accounts, but
# ALWAYS run `terraform destroy` when you're done testing.
########################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region to deploy the lab into"
  type        = string
  default     = "us-east-1"
}

variable "allow_my_ip_only" {
  description = "If true, restricts inbound access to var.my_ip instead of 0.0.0.0/0. Set this true unless you specifically want the fully-open version for a demo."
  type        = bool
  default     = true
}

variable "my_ip" {
  description = "Your public IP in CIDR form, e.g. 203.0.113.4/32"
  type        = string
  default     = "0.0.0.0/0"
}

locals {
  ingress_cidr = var.allow_my_ip_only ? var.my_ip : "0.0.0.0/0"
}

data "aws_vpc" "default" {
  default = true
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

# --- Intentionally over-permissive security group -------------------
resource "aws_security_group" "vuln_sg" {
  name        = "secaudit-lab-vuln-sg"
  description = "Deliberately over-exposed SG for SecAudit lab target"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH - deliberately exposed"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [local.ingress_cidr]
  }
  ingress {
    description = "FTP - deliberately exposed"
    from_port   = 21
    to_port     = 21
    protocol    = "tcp"
    cidr_blocks = [local.ingress_cidr]
  }
  ingress {
    description = "Telnet - deliberately exposed"
    from_port   = 23
    to_port     = 23
    protocol    = "tcp"
    cidr_blocks = [local.ingress_cidr]
  }
  ingress {
    description = "RDP - deliberately exposed (unused on Linux target, left for realism)"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [local.ingress_cidr]
  }
  ingress {
    description = "SMB - deliberately exposed"
    from_port   = 445
    to_port     = 445
    protocol    = "tcp"
    cidr_blocks = [local.ingress_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Project = "SecAudit-Lab", Purpose = "intentionally-vulnerable" }
}

# --- Target EC2 instance ---------------------------------------------
resource "aws_instance" "vuln_target" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.vuln_sg.id]
  user_data              = file("${path.module}/user_data.sh")

  tags = { Name = "secaudit-lab-target", Project = "SecAudit-Lab" }
}

# --- Intentionally public, unencrypted S3 bucket ----------------------
resource "aws_s3_bucket" "vuln_bucket" {
  bucket = "secaudit-lab-vuln-bucket-${random_id.suffix.hex}"
  tags   = { Project = "SecAudit-Lab" }
}

resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket_public_access_block" "vuln_bucket" {
  bucket                  = aws_s3_bucket.vuln_bucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "vuln_bucket_acl" {
  bucket     = aws_s3_bucket.vuln_bucket.id
  acl        = "public-read"
  depends_on = [aws_s3_bucket_public_access_block.vuln_bucket]
}

output "target_public_ip" {
  value = aws_instance.vuln_target.public_ip
}

output "vuln_bucket_name" {
  value = aws_s3_bucket.vuln_bucket.bucket
}
