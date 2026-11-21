# ==============================================================================
# AWS Backup & Disaster Recovery: HITRUST Domain 15 (15.c / 15.d) & FDA 21 CFR 11
# ==============================================================================
# Automates daily backups of stateful clinical trial datasets, enforces immutable
# WORM protection via AWS Backup Vault Lock, and guarantees long-term retention.
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. AWS Backup Vault (KMS CMK Encrypted)
# ------------------------------------------------------------------------------

resource "aws_backup_vault" "clinical_vault" {
  name        = "${var.project_name}-${var.environment}-clinical-backup-vault"
  kms_key_arn = aws_kms_key.bedrock_platform.arn

  tags = {
    Name       = "${var.project_name}-${var.environment}-backup-vault"
    Compliance = "HITRUST-15c-15d-FDA21CFR11-NIST-CP9"
  }
}

# ------------------------------------------------------------------------------
# 2. AWS Backup Vault Lock: Immutable WORM Compliance Lock
# ------------------------------------------------------------------------------
# Enforces that once recovery points are created, they cannot be deleted,
# truncated, or expired early by any user, account root, or compromised credential.

resource "aws_backup_vault_lock_configuration" "clinical_vault_lock" {
  backup_vault_name   = aws_backup_vault.clinical_vault.name
  min_retention_days  = 35
  max_retention_days  = 2555 # 7 Years (FDA 21 CFR Part 11 / eTMF Retention)
  changeable_for_days = 3    # 3-day grace period before lock becomes completely immutable
}

# ------------------------------------------------------------------------------
# 3. AWS Backup Plan: Daily Snapshots, Cold Storage Transition & 7-Year Retention
# ------------------------------------------------------------------------------

resource "aws_backup_plan" "clinical_backup_plan" {
  name = "${var.project_name}-${var.environment}-clinical-backup-plan"

  rule {
    rule_name         = "DailyClinicalBackupRule"
    target_vault_name = aws_backup_vault.clinical_vault.name
    schedule          = "cron(0 5 ? * * *)" # Every day at 05:00 UTC
    start_window      = 60                  # 1 hour start window
    completion_window = 120                 # 2 hours completion window

    lifecycle {
      cold_storage_after = 90   # Move to Glacier/Cold storage after 90 days
      delete_after       = 2555 # Retain for 7 years (FDA 21 CFR Part 11 compliance)
    }

    recovery_point_tags = {
      Environment = var.environment
      DataClass   = "ClinicalPHI-Backup"
      Compliance  = "HITRUST-15c"
    }
  }

  tags = {
    Name       = "${var.project_name}-${var.environment}-backup-plan"
    Compliance = "HITRUST-Domain15"
  }
}

# ------------------------------------------------------------------------------
# 4. IAM Service Role for AWS Backup
# ------------------------------------------------------------------------------

resource "aws_iam_role" "aws_backup_role" {
  name = "${var.project_name}-${var.environment}-backup-service-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "backup.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "backup_standard" {
  role       = aws_iam_role.aws_backup_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_iam_role_policy_attachment" "backup_restores" {
  role       = aws_iam_role.aws_backup_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
}

resource "aws_iam_role_policy" "backup_kms_access" {
  name = "${var.project_name}-${var.environment}-backup-kms-policy"
  role = aws_iam_role.aws_backup_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = aws_kms_key.bedrock_platform.arn
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# 5. AWS Backup Selection: Automatic Inclusion of Clinical Data
# ------------------------------------------------------------------------------

resource "aws_backup_selection" "clinical_data" {
  iam_role_arn = aws_iam_role.aws_backup_role.arn
  name         = "${var.project_name}-${var.environment}-clinical-backup-selection"
  plan_id      = aws_backup_plan.clinical_backup_plan.id

  resources = [
    aws_s3_bucket.clinical_docs.arn
  ]

  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Compliance"
    value = "HIPAA-SOC2-NIST80053-FDA-21CFR11"
  }
}
