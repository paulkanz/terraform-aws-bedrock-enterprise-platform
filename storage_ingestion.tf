# ==============================================================================
# Storage & Ingestion Pipeline (NIST 800-53, CIS Benchmark, HIPAA/ePHI & SOC 2)
# ==============================================================================

# ------------------------------------------------------------------------------
# S3: Centralized Server Access Logs Bucket (CIS 2.1.4, NIST AU-2/AU-9)
# ------------------------------------------------------------------------------

resource "aws_s3_bucket" "access_logs" {
  bucket        = "${var.project_name}-${var.environment}-s3-access-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = false

  tags = {
    Name       = "${var.project_name}-${var.environment}-s3-access-logs"
    DataClass  = "AuditAccessLogs"
    Compliance = "HIPAA-SOC2-NIST80053"
  }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.bedrock_platform.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "access_logs_policy" {
  bucket = aws_s3_bucket.access_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLSRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.access_logs.arn,
          "${aws_s3_bucket.access_logs.arn}/*"
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
        Sid    = "AllowS3ServerAccessLogging"
        Effect = "Allow"
        Principal = {
          Service = "logging.s3.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.access_logs.arn}/*"
        Condition = {
          ArnLike = {
            "aws:SourceArn" = "arn:aws:s3:::${var.project_name}-${var.environment}-*"
          }
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AllowALBAccessLogging"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::127311923021:root" # AWS ELB Account for us-east-1
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.access_logs.arn}/alb-access-logs/*"
      },
      {
        Sid    = "AllowALBLogDeliveryService"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.access_logs.arn}/alb-access-logs/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# S3: Raw Clinical Documents & Protocols (HIPAA ePHI, HITRUST, SOC 2)
# ------------------------------------------------------------------------------

resource "aws_s3_bucket" "clinical_docs" {
  bucket              = "${var.project_name}-${var.environment}-clinical-docs-${data.aws_caller_identity.current.account_id}"
  force_destroy       = false
  object_lock_enabled = true

  tags = {
    Name               = "${var.project_name}-${var.environment}-clinical-docs"
    DataClass          = "ClinicalPHI"
    Compliance         = "HIPAA-SOC2-NIST80053-FDA-21CFR11"
    DataClassification = "ePHI-Restricted"
  }
}

resource "aws_s3_bucket_versioning" "clinical_docs" {
  bucket = aws_s3_bucket.clinical_docs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# FDA 21 CFR Part 11 & Legal Hold: 7-Year WORM Storage (Non-overwritable)
resource "aws_s3_bucket_object_lock_configuration" "clinical_docs" {
  bucket = aws_s3_bucket.clinical_docs.id

  rule {
    default_retention {
      mode  = "COMPLIANCE"
      years = 7
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "clinical_docs" {
  bucket = aws_s3_bucket.clinical_docs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.bedrock_platform.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "clinical_docs" {
  bucket = aws_s3_bucket.clinical_docs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "clinical_docs" {
  bucket = aws_s3_bucket.clinical_docs.id

  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "clinical-docs/"
}

resource "aws_s3_bucket_policy" "clinical_docs_enforce_tls" {
  bucket = aws_s3_bucket.clinical_docs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLSRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.clinical_docs.arn,
          "${aws_s3_bucket.clinical_docs.arn}/*"
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
        Sid       = "DenyUnencryptedObjectUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.clinical_docs.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# S3: Bedrock Model Invocation Logs (Audit Retention - NIST AU-9 / SOC 2 CC6.8)
# ------------------------------------------------------------------------------

resource "aws_s3_bucket" "bedrock_invocation_logs" {
  bucket        = "${var.project_name}-${var.environment}-bedrock-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = false

  tags = {
    Name       = "${var.project_name}-${var.environment}-bedrock-logs"
    DataClass  = "AuditLogs"
    Compliance = "HIPAA-SOC2-NIST80053"
  }
}

resource "aws_s3_bucket_versioning" "bedrock_invocation_logs" {
  bucket = aws_s3_bucket.bedrock_invocation_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bedrock_invocation_logs" {
  bucket = aws_s3_bucket.bedrock_invocation_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.bedrock_platform.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "bedrock_invocation_logs" {
  bucket = aws_s3_bucket.bedrock_invocation_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "bedrock_invocation_logs" {
  bucket = aws_s3_bucket.bedrock_invocation_logs.id

  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "bedrock-invocation-logs/"
}

resource "aws_s3_bucket_lifecycle_configuration" "bedrock_invocation_logs" {
  bucket = aws_s3_bucket.bedrock_invocation_logs.id

  rule {
    id     = "archive-audit-logs"
    status = "Enabled"

    filter {}

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 180
      storage_class = "GLACIER"
    }

    expiration {
      days = var.log_retention_in_days
    }
  }
}

# ------------------------------------------------------------------------------
# Amazon SQS: Dead-Letter Queue & AI Processing Queue (KMS CMK Encrypted)
# ------------------------------------------------------------------------------

resource "aws_sqs_queue" "ai_jobs_dlq" {
  name                      = "${var.project_name}-${var.environment}-ai-jobs-dlq"
  kms_master_key_id         = aws_kms_key.bedrock_platform.id
  message_retention_seconds = 1209600 # 14 days

  tags = {
    Name       = "${var.project_name}-${var.environment}-ai-jobs-dlq"
    Compliance = "HIPAA-SOC2-NIST80053"
  }
}

resource "aws_sqs_queue" "ai_jobs" {
  name                       = "${var.project_name}-${var.environment}-ai-jobs-queue"
  kms_master_key_id          = aws_kms_key.bedrock_platform.id
  visibility_timeout_seconds = 300
  message_retention_seconds  = 345600 # 4 days

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.ai_jobs_dlq.arn
    maxReceiveCount     = 3
  })

  tags = {
    Name       = "${var.project_name}-${var.environment}-ai-jobs-queue"
    Compliance = "HIPAA-SOC2-NIST80053"
  }
}
