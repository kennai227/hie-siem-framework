# =============================================================================
# HIE SIEM Framework — AWS Canada Central Foundation
# Region: ca-central-1 | Compliance: HIPAA, PHIPA, PIPEDA
# =============================================================================

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    bucket         = "hie-siem-tfstate-ca"
    key            = "aws/foundation/terraform.tfstate"
    region         = "ca-central-1"
    encrypt        = true
    kms_key_id     = "alias/hie-terraform-state"
    dynamodb_table = "hie-siem-tfstate-lock"
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "HIE-SIEM"
      Environment = var.environment
      Compliance  = "HIPAA-PHIPA-PIPEDA"
      ManagedBy   = "Terraform"
      DataClass   = "PHI-Restricted"
    }
  }
}

# =============================================================================
# KMS — Encryption at rest for all PHI-adjacent resources
# =============================================================================
resource "aws_kms_key" "hie_master" {
  description             = "HIE SIEM master encryption key — PHI data at rest"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = false # Stay in ca-central-1 for PIPEDA residency

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow SIEM services"
        Effect = "Allow"
        Principal = {
          Service = ["s3.amazonaws.com", "logs.ca-central-1.amazonaws.com", "guardduty.amazonaws.com"]
        }
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "hie_master" {
  name          = "alias/hie-siem-master"
  target_key_id = aws_kms_key.hie_master.key_id
}

# =============================================================================
# VPC — Isolated network for SIEM workloads
# =============================================================================
resource "aws_vpc" "hie_siem" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "hie-siem-vpc" }
}

# Private subnets — Wazuh manager, OpenSearch, log processors
resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.hie_siem.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = { Name = "hie-siem-private-${count.index + 1}", Tier = "Private" }
}

# Public subnets — NAT Gateway, VPN endpoints only
resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.hie_siem.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false # Never auto-assign public IPs

  tags = { Name = "hie-siem-public-${count.index + 1}", Tier = "Public" }
}

resource "aws_internet_gateway" "hie" {
  vpc_id = aws_vpc.hie_siem.id
  tags   = { Name = "hie-siem-igw" }
}

resource "aws_eip" "nat" {
  count  = length(var.public_subnet_cidrs)
  domain = "vpc"
  tags   = { Name = "hie-siem-nat-eip-${count.index + 1}" }
}

resource "aws_nat_gateway" "hie" {
  count         = length(var.public_subnet_cidrs)
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  tags          = { Name = "hie-siem-nat-${count.index + 1}" }
}

# =============================================================================
# VPC Flow Logs — Network-level log aggregation (HIPAA 164.312(b))
# =============================================================================
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/hie-siem-flow-logs"
  retention_in_days = 365 # 1 year minimum for HIPAA
  kms_key_id        = aws_kms_key.hie_master.arn
}

resource "aws_flow_log" "hie_siem" {
  vpc_id          = aws_vpc.hie_siem.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.vpc_flow_logs.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn

  log_format = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${windowstart} $${windowend} $${action} $${flow-direction} $${log-status} $${vpc-id} $${subnet-id} $${instance-id} $${tcp-flags} $${type} $${pkt-srcaddr} $${pkt-dstaddr}"
}

# =============================================================================
# S3 — Immutable log archive (HIPAA 164.312(c)(1) — Integrity Controls)
# =============================================================================
resource "aws_s3_bucket" "log_archive" {
  bucket        = "hie-siem-log-archive-${data.aws_caller_identity.current.account_id}"
  force_destroy = false # Never allow accidental deletion of audit logs
}

resource "aws_s3_bucket_versioning" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_object_lock_configuration" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id
  rule {
    default_retention {
      mode = "COMPLIANCE" # WORM — cannot be overridden even by root
      days = 2557         # 7 years per HIPAA retention requirement
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.hie_master.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "log_archive" {
  bucket                  = aws_s3_bucket.log_archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# =============================================================================
# GuardDuty — AWS-native ML threat detection
# =============================================================================
resource "aws_guardduty_detector" "hie" {
  enable = true
  datasources {
    s3_logs { enable = true }
    kubernetes { audit_logs { enable = true } }
    malware_protection {
      scan_ec2_instance_with_findings { ebs_volumes { enable = true } }
    }
  }
}

# =============================================================================
# CloudTrail — API audit logging (HIPAA 164.312(b))
# =============================================================================
resource "aws_cloudtrail" "hie_audit" {
  name                          = "hie-siem-audit-trail"
  s3_bucket_name                = aws_s3_bucket.log_archive.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = false # Stay in ca-central-1
  enable_log_file_validation    = true  # Integrity hash validation
  kms_key_id                    = aws_kms_key.hie_master.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.log_archive.arn}/"]
    }
  }

  insight_selector {
    insight_type = "ApiCallRateInsight"
  }
  insight_selector {
    insight_type = "ApiErrorRateInsight"
  }
}

# =============================================================================
# Security Hub — Centralized findings aggregation
# =============================================================================
resource "aws_securityhub_account" "hie" {}

resource "aws_securityhub_standards_subscription" "hipaa" {
  depends_on    = [aws_securityhub_account.hie]
  standards_arn = "arn:aws:securityhub:ca-central-1::standards/aws-foundational-security-best-practices/v/1.0.0"
}

resource "aws_securityhub_standards_subscription" "cis" {
  depends_on    = [aws_securityhub_account.hie]
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
}

# =============================================================================
# Data Sources
# =============================================================================
data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" { state = "available" }
