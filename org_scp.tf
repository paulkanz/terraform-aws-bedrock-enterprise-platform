# ==============================================================================
# AWS Organizations: Service Control Policies (SCPs)
# ==============================================================================
# In a compliant multi-account landing zone (AWS Control Tower / AWS Organizations),
# these SCPs are attached to the Root or Clinical Workloads OU from the Management
# Account. They enforce non-bypassable guardrails that even account root cannot violate.
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. SCP: Enforce Region Lock (Deny Non-US Regions - HIPAA ePHI & NIST SC-8)
# ------------------------------------------------------------------------------

resource "aws_organizations_policy" "deny_non_us_regions" {
  name        = "${var.project_name}-scp-deny-non-us-regions"
  description = "Denies all API calls outside authorized US Commercial regions (us-east-1 and us-west-2) for data sovereignty"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyNonUSRegions"
        Effect = "Deny"
        NotAction = [
          "iam:*",
          "organizations:*",
          "route53:*",
          "budgets:*",
          "wafv2:*",
          "cloudfront:*",
          "globalaccelerator:*",
          "support:*",
          "shield:*"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:RequestedRegion" = [
              "us-east-1",
              "us-west-2"
            ]
          }
        }
      }
    ]
  })

  tags = {
    Name       = "${var.project_name}-scp-deny-non-us-regions"
    Compliance = "HIPAA-ePHI-NIST-SC8"
  }
}

# ------------------------------------------------------------------------------
# 2. SCP: Protect Core Security & Audit Services (CIS 3.x, NIST AU-9, SOC 2 CC6.8)
# ------------------------------------------------------------------------------

resource "aws_organizations_policy" "protect_audit_and_security" {
  name        = "${var.project_name}-scp-protect-audit-and-security"
  description = "Prevents disabling, stopping, or tampering with CloudTrail, GuardDuty, AWS Config, and Bedrock logging"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyDisablingCloudTrail"
        Effect = "Deny"
        Action = [
          "cloudtrail:DeleteTrail",
          "cloudtrail:StopLogging",
          "cloudtrail:UpdateTrail"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyDisablingGuardDuty"
        Effect = "Deny"
        Action = [
          "guardduty:DeleteDetector",
          "guardduty:DisassociateFromMasterAccount",
          "guardduty:UpdateDetector"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyDisablingAWSConfig"
        Effect = "Deny"
        Action = [
          "config:DeleteConfigurationRecorder",
          "config:DeleteDeliveryChannel",
          "config:StopConfigurationRecorder"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyDisablingBedrockInvocationLogging"
        Effect = "Deny"
        Action = [
          "bedrock:DeleteModelInvocationLoggingConfiguration",
          "bedrock:PutModelInvocationLoggingConfiguration"
        ]
        Resource = "*"
        Condition = {
          StringNotLike = {
            "aws:PrincipalArn" = [
              "arn:aws:iam::*:role/aws-service-role/*",
              "arn:aws:iam::*:role/*TerraformDeploymentRole*"
            ]
          }
        }
      }
    ]
  })

  tags = {
    Name       = "${var.project_name}-scp-protect-audit-security"
    Compliance = "CIS-3.1-NIST-AU9-SOC2"
  }
}

# ------------------------------------------------------------------------------
# 3. SCP: Enforce S3 Public Access Block & Deny Public Buckets (CIS 2.1.2)
# ------------------------------------------------------------------------------

resource "aws_organizations_policy" "deny_s3_public_access" {
  name        = "${var.project_name}-scp-deny-s3-public-access"
  description = "Prohibits disabling S3 Block Public Access or publishing public S3 buckets"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyModifyingS3PublicAccessBlock"
        Effect = "Deny"
        Action = [
          "s3:PutAccountPublicAccessBlock",
          "s3:DeleteAccountPublicAccessBlock",
          "s3:PutBucketPublicAccessBlock"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyPublicBucketPoliciesAndACLs"
        Effect = "Deny"
        Action = [
          "s3:PutBucketPolicy",
          "s3:PutBucketAcl",
          "s3:PutObjectAcl"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = [
              "public-read",
              "public-read-write",
              "authenticated-read"
            ]
          }
        }
      }
    ]
  })

  tags = {
    Name       = "${var.project_name}-scp-deny-s3-public-access"
    Compliance = "CIS-2.1.2-HIPAA-ePHI"
  }
}

# ------------------------------------------------------------------------------
# 4. SCP: Enforce KMS CMK Encryption at Rest (NIST SC-13, HIPAA ePHI)
# ------------------------------------------------------------------------------

resource "aws_organizations_policy" "enforce_encryption_at_rest" {
  name        = "${var.project_name}-scp-enforce-encryption-at-rest"
  description = "Enforces that all EBS volumes, RDS databases, and S3 uploads use KMS encryption"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnencryptedEBSVolumes"
        Effect = "Deny"
        Action = [
          "ec2:CreateVolume",
          "ec2:RunInstances"
        ]
        Resource = "arn:aws:ec2:*:*:volume/*"
        Condition = {
          Bool = {
            "ec2:Encrypted" = "false"
          }
        }
      },
      {
        Sid      = "DenyUnencryptedS3Uploads"
        Effect   = "Deny"
        Action   = "s3:PutObject"
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })

  tags = {
    Name       = "${var.project_name}-scp-enforce-encryption"
    Compliance = "NIST-SC13-HIPAA"
  }
}

# ------------------------------------------------------------------------------
# 5. SCP: Bedrock Foundation Model & Guardrails Governance (OWASP LLM Top 10)
# ------------------------------------------------------------------------------

resource "aws_organizations_policy" "govern_bedrock_ai" {
  name        = "${var.project_name}-scp-govern-bedrock-ai"
  description = "Restricts Bedrock inference strictly to approved BAA models (Claude 3.5 & Titan Embeddings) and protects Guardrails"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnapprovedBedrockModels"
        Effect = "Deny"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ]
        NotResource = [
          "arn:aws:bedrock:*::foundation-model/anthropic.claude-3-5-sonnet*",
          "arn:aws:bedrock:*::foundation-model/anthropic.claude-3-5-haiku*",
          "arn:aws:bedrock:*::foundation-model/amazon.titan-embed-text-*"
        ]
      },
      {
        Sid    = "DenyDeletingBedrockGuardrails"
        Effect = "Deny"
        Action = [
          "bedrock:DeleteGuardrail",
          "bedrock:DeleteGuardrailVersion"
        ]
        Resource = "*"
        Condition = {
          StringNotLike = {
            "aws:PrincipalArn" = [
              "arn:aws:iam::*:role/*TerraformDeploymentRole*"
            ]
          }
        }
      }
    ]
  })

  tags = {
    Name       = "${var.project_name}-scp-govern-bedrock"
    Compliance = "OWASP-LLM-HIPAA-BAA"
  }
}

# ------------------------------------------------------------------------------
# 6. SCP: Enforce Multi-Factor Authentication (MFA) for Destructive Actions
# ------------------------------------------------------------------------------
# HITRUST Domain 10 / 11 (Access Control & Identification - Control 10.b / 11.a)
# Denies destructive actions against KMS keys, S3 buckets, and audit trails
# unless the calling principal authenticated with MFA.

resource "aws_organizations_policy" "enforce_mfa_for_destructive_actions" {
  name        = "${var.project_name}-scp-enforce-mfa-destructive-actions"
  description = "Denies destructive actions against KMS, S3, and CloudTrail unless authenticated with MFA"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyDestructiveActionsWithoutMFA"
        Effect = "Deny"
        Action = [
          "kms:ScheduleKeyDeletion",
          "kms:DisableKey",
          "s3:DeleteBucket",
          "cloudtrail:DeleteTrail",
          "cloudtrail:StopLogging"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })

  tags = {
    Name       = "${var.project_name}-scp-enforce-mfa"
    Compliance = "HITRUST-10b-11a-CIS-1.5"
  }
}
