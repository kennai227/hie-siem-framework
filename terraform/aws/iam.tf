# =============================================================================
# IAM — Least-privilege roles for HIE SIEM components
# =============================================================================

# VPC Flow Logs role
resource "aws_iam_role" "vpc_flow_logs" {
  name = "hie-siem-vpc-flow-logs-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "vpc_flow_logs" {
  name = "hie-siem-vpc-flow-logs-policy"
  role = aws_iam_role.vpc_flow_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*"
    }]
  })
}

# Wazuh Manager role — read logs from S3, write findings to Security Hub
resource "aws_iam_role" "wazuh_manager" {
  name = "hie-siem-wazuh-manager-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "wazuh_manager" {
  name = "hie-siem-wazuh-manager-policy"
  role = aws_iam_role.wazuh_manager.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadLogArchive"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.log_archive.arn,
          "${aws_s3_bucket.log_archive.arn}/*"
        ]
      },
      {
        Sid    = "WriteFindings"
        Effect = "Allow"
        Action = ["securityhub:BatchImportFindings"]
        Resource = "arn:aws:securityhub:${var.aws_region}:${data.aws_caller_identity.current.account_id}:hub/default"
      },
      {
        Sid    = "UseKMS"
        Effect = "Allow"
        Action = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.hie_master.arn
      },
      {
        Sid    = "ReadGuardDutyFindings"
        Effect = "Allow"
        Action = ["guardduty:ListFindings", "guardduty:GetFindings"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "wazuh_manager" {
  name = "hie-siem-wazuh-manager-profile"
  role = aws_iam_role.wazuh_manager.name
}

# Break-glass emergency access role (HIPAA 164.312(a)(2)(ii))
resource "aws_iam_role" "break_glass" {
  name                 = "hie-siem-break-glass-role"
  max_session_duration = 3600 # 1 hour max
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
      Action    = "sts:AssumeRole"
      Condition = {
        Bool              = { "aws:MultiFactorAuthPresent" = "true" }
        NumericLessThan   = { "aws:MultiFactorAuthAge" = "300" }
      }
    }]
  })
  tags = { Sensitivity = "BREAK-GLASS", AlertOnUse = "true" }
}

# CloudWatch alarm to alert when break-glass role is used
resource "aws_cloudwatch_metric_alarm" "break_glass_used" {
  alarm_name          = "hie-siem-break-glass-role-used"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "AssumeRoleEventCount"
  namespace           = "CloudTrailMetrics"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "CRITICAL: Break-glass IAM role assumed — immediate review required (HIPAA 164.312(a)(2)(ii))"
  treat_missing_data  = "notBreaching"
}
