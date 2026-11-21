# ==============================================================================
# Compliance, Security & Audit Controls: NIST 800-53 Rev 5, CIS, SOC 2, HIPAA/ePHI
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. AWS GuardDuty: Continuous Threat Detection (NIST SI-4, SOC 2 CC7.2)
# ------------------------------------------------------------------------------

resource "aws_guardduty_detector" "primary" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = {
    Name       = "${var.project_name}-${var.environment}-guardduty"
    Compliance = "NIST80053-SI4-SOC2-HIPAA"
  }
}

# ------------------------------------------------------------------------------
# 2. VPC Flow Logs: Network Traffic Auditing (CIS 4.1, NIST AU-12, HIPAA §164.312)
# ------------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/${var.project_name}-${var.environment}-flow-logs"
  retention_in_days = var.log_retention_in_days
  kms_key_id        = aws_kms_key.bedrock_platform.arn

  tags = {
    Name       = "${var.project_name}-${var.environment}-flow-logs"
    Compliance = "CIS-4.1-NIST-AU12-HIPAA"
  }
}

resource "aws_iam_role" "vpc_flow_logs" {
  name = "${var.project_name}-${var.environment}-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "vpc_flow_logs" {
  name = "${var.project_name}-${var.environment}-vpc-flow-logs-policy"
  role = aws_iam_role.vpc_flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_flow_log" "vpc" {
  iam_role_arn    = aws_iam_role.vpc_flow_logs.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id

  tags = {
    Name       = "${var.project_name}-${var.environment}-vpc-flow-log"
    Compliance = "CIS-4.1-NIST-AU12"
  }
}

# ------------------------------------------------------------------------------
# 3. AWS CloudTrail: Multi-Region Auditing (CIS 3.1 - 3.7, NIST AU-2/AU-3/AU-6)
# ------------------------------------------------------------------------------

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket              = "${var.project_name}-${var.environment}-cloudtrail-${data.aws_caller_identity.current.account_id}"
  force_destroy       = false
  object_lock_enabled = true

  tags = {
    Name       = "${var.project_name}-${var.environment}-cloudtrail"
    DataClass  = "AuditLogs"
    Compliance = "CIS-3.1-NIST-AU2-HIPAA-FDA21CFR11"
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Audit Log Immutability: 1-Year WORM Compliance Retention
resource "aws_s3_bucket_object_lock_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    default_retention {
      mode  = "COMPLIANCE"
      years = 1
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.bedrock_platform.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "cloudtrail-logs/"
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLSRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail_logs.arn,
          "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
          NumericLessThan = {
            "s3:TlsVersion" = 1.2
          }
        }
      },
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"      = "bucket-owner-full-control"
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.project_name}-${var.environment}-audit-trail"
  retention_in_days = var.log_retention_in_days
  kms_key_id        = aws_kms_key.bedrock_platform.arn

  tags = {
    Name       = "${var.project_name}-${var.environment}-cloudtrail-cw-logs"
    Compliance = "CIS-3.4-NIST-AU2"
  }
}

resource "aws_iam_role" "cloudtrail_to_cloudwatch" {
  name = "${var.project_name}-${var.environment}-cloudtrail-cw-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudtrail_to_cloudwatch" {
  name = "${var.project_name}-${var.environment}-cloudtrail-cw-policy"
  role = aws_iam_role.cloudtrail_to_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
      }
    ]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = "${var.project_name}-${var.environment}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  enable_logging                = true
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true # CIS 3.2: Integrity validation (NIST AU-9)
  kms_key_id                    = aws_kms_key.bedrock_platform.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_to_cloudwatch.arn

  tags = {
    Name       = "${var.project_name}-${var.environment}-trail"
    Compliance = "CIS-3.1-NIST-AU2-SOC2"
  }

  depends_on = [
    aws_s3_bucket_policy.cloudtrail_logs,
    aws_iam_role_policy.cloudtrail_to_cloudwatch
  ]
}

# ------------------------------------------------------------------------------
# 4. CloudWatch Metric Filters & Alarms for CIS Benchmarks (Sections 3.x)
# ------------------------------------------------------------------------------

# CIS 3.1: Unauthorized API Calls
resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
  name           = "UnauthorizedAPICalls"
  pattern        = "{($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\")}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "UnauthorizedAPICalls"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  alarm_name          = "${var.project_name}-${var.environment}-unauthorized-api-calls"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.unauthorized_api_calls.metric_transformation[0].name
  namespace           = "CISBenchmark"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "CIS 3.1: Triggered when unauthorized API calls occur"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

# CIS 3.3: Root Account Usage
resource "aws_cloudwatch_log_metric_filter" "root_account_usage" {
  name           = "RootAccountUsage"
  pattern        = "{$.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\"}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "RootAccountUsage"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_account_usage" {
  alarm_name          = "${var.project_name}-${var.environment}-root-account-usage"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.root_account_usage.metric_transformation[0].name
  namespace           = "CISBenchmark"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "CIS 3.3: Triggered when root account is used"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

# CIS 3.4: IAM Policy Changes
resource "aws_cloudwatch_log_metric_filter" "iam_policy_changes" {
  name           = "IAMPolicyChanges"
  pattern        = "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "IAMPolicyChanges"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_policy_changes" {
  alarm_name          = "${var.project_name}-${var.environment}-iam-policy-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.iam_policy_changes.metric_transformation[0].name
  namespace           = "CISBenchmark"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "CIS 3.4: Triggered when IAM policies are altered"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

# CIS 3.10: Security Group Changes
resource "aws_cloudwatch_log_metric_filter" "security_group_changes" {
  name           = "SecurityGroupChanges"
  pattern        = "{($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup)}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "SecurityGroupChanges"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "security_group_changes" {
  alarm_name          = "${var.project_name}-${var.environment}-security-group-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.security_group_changes.metric_transformation[0].name
  namespace           = "CISBenchmark"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "CIS 3.10: Triggered when Security Groups are modified"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

# ------------------------------------------------------------------------------
# 5. AWS Config: Continuous Asset Compliance Auditing (NIST CM-2, CM-8, SOC 2)
# ------------------------------------------------------------------------------

resource "aws_s3_bucket" "config_logs" {
  bucket        = "${var.project_name}-${var.environment}-config-${data.aws_caller_identity.current.account_id}"
  force_destroy = false

  tags = {
    Name       = "${var.project_name}-${var.environment}-config"
    DataClass  = "AuditLogs"
    Compliance = "NIST-CM2-SOC2"
  }
}

resource "aws_s3_bucket_versioning" "config_logs" {
  bucket = aws_s3_bucket.config_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config_logs" {
  bucket = aws_s3_bucket.config_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.bedrock_platform.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "config_logs" {
  bucket = aws_s3_bucket.config_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "config_logs" {
  bucket = aws_s3_bucket.config_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLSRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.config_logs.arn,
          "${aws_s3_bucket.config_logs.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
          NumericLessThan = {
            "s3:TlsVersion" = 1.2
          }
        }
      },
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.config_logs.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AWSConfigBucketDelivery"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.config_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"      = "bucket-owner-full-control"
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

resource "aws_iam_role" "config_role" {
  name = "${var.project_name}-${var.environment}-config-service-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "config_role_standard" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "main" {
  name     = "${var.project_name}-${var.environment}-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "${var.project_name}-${var.environment}-channel"
  s3_bucket_name = aws_s3_bucket.config_logs.id

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [
    aws_config_configuration_recorder.main,
    aws_s3_bucket_policy.config_logs
  ]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

# AWS Config Managed Rule: S3 Bucket SSL Requests Only (HIPAA / NIST SC-8)
resource "aws_config_config_rule" "s3_ssl" {
  name        = "s3-bucket-ssl-requests-only"
  description = "Checks that S3 bucket policies require SSL/TLS requests"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# AWS Config Managed Rule: S3 Server-Side Encryption (NIST SC-13, HIPAA ePHI)
resource "aws_config_config_rule" "s3_encryption" {
  name        = "s3-bucket-server-side-encryption-enabled"
  description = "Checks that S3 buckets have server-side encryption enabled"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# ------------------------------------------------------------------------------
# 6. AWS Security Hub: Centralized CSPM & Compliance Standards (CIS, NIST, FSBP)
# ------------------------------------------------------------------------------

resource "aws_securityhub_account" "main" {
  enable_default_standards = false
  auto_enable_controls     = true
}

# CIS AWS Foundations Benchmark v3.0.0
resource "aws_securityhub_standards_subscription" "cis_aws_foundations" {
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/3.0.0"
  depends_on    = [aws_securityhub_account.main]
}

# AWS Foundational Security Best Practices (FSBP)
resource "aws_securityhub_standards_subscription" "aws_foundational_security" {
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}

# ------------------------------------------------------------------------------
# 7. IAM Access Analyzer: Continuous Resource Policy & Exposure Auditing
# ------------------------------------------------------------------------------

resource "aws_accessanalyzer_analyzer" "main" {
  analyzer_name = "${var.project_name}-${var.environment}-access-analyzer"
  type          = "ACCOUNT"

  tags = {
    Name       = "${var.project_name}-${var.environment}-access-analyzer"
    Compliance = "NIST-AC3-CIS-SOC2"
  }
}

# ------------------------------------------------------------------------------
# 8. EventBridge Automated Incident Detection & Remediation Routing
# ------------------------------------------------------------------------------

# EventBridge Rule: GuardDuty High-Severity Finding (Severity >= 7.0)
resource "aws_cloudwatch_event_rule" "guardduty_high_severity" {
  name        = "${var.project_name}-${var.environment}-guardduty-high-findings"
  description = "Captures high severity GuardDuty findings (severity >= 7.0) for immediate alerting and remediation"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [
        7, 7.0, 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8, 7.9,
        8, 8.0, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8, 8.9
      ]
    }
  })

  tags = {
    Name       = "${var.project_name}-${var.environment}-guardduty-event-rule"
    Compliance = "NIST-SI4-SOC2"
  }
}

# EventBridge Target: Alert SecOps immediately via KMS-encrypted SNS
resource "aws_cloudwatch_event_target" "guardduty_high_to_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_high_severity.name
  target_id = "SendToSecurityAlertsSNS"
  arn       = aws_sns_topic.security_alerts.arn
}

# EventBridge Rule: AWS Config Compliance Drift
resource "aws_cloudwatch_event_rule" "config_compliance_drift" {
  name        = "${var.project_name}-${var.environment}-config-compliance-drift"
  description = "Captures non-compliant evaluation results across AWS resources"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })

  tags = {
    Name       = "${var.project_name}-${var.environment}-config-event-rule"
    Compliance = "NIST-CM2-SOC2"
  }
}

# EventBridge Target: Send Config non-compliance to Security Alerts SNS
resource "aws_cloudwatch_event_target" "config_drift_to_sns" {
  rule      = aws_cloudwatch_event_rule.config_compliance_drift.name
  target_id = "SendConfigDriftToSNS"
  arn       = aws_sns_topic.security_alerts.arn
}

# ------------------------------------------------------------------------------
# 9. Amazon Macie: Automated Sensitive ePHI Discovery (HITRUST Domain 18 - 18.c)
# ------------------------------------------------------------------------------

resource "aws_macie2_account" "primary" {
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  status                       = "ENABLED"
}

# EventBridge Rule: Macie Sensitive Data / ePHI Discovery Finding
resource "aws_cloudwatch_event_rule" "macie_findings" {
  name        = "${var.project_name}-${var.environment}-macie-sensitive-data"
  description = "Captures Amazon Macie sensitive ePHI discovery findings for SecOps alerting"

  event_pattern = jsonencode({
    source      = ["aws.macie"]
    detail-type = ["Macie Finding"]
    detail = {
      severity = {
        description = ["High", "Medium"]
      }
    }
  })

  tags = {
    Name       = "${var.project_name}-${var.environment}-macie-event-rule"
    Compliance = "HITRUST-18c-HIPAA"
  }
}

# EventBridge Target: Route Macie Findings to Security Alerts SNS
resource "aws_cloudwatch_event_target" "macie_findings_to_sns" {
  rule      = aws_cloudwatch_event_rule.macie_findings.name
  target_id = "SendMacieFindingsToSNS"
  arn       = aws_sns_topic.security_alerts.arn
}
