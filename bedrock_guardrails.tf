# ==============================================================================
# AWS Bedrock Guardrails & Model Invocation Logging Configuration
# ==============================================================================

# ------------------------------------------------------------------------------
# Bedrock Guardrail (HIPAA / PII Redaction & Prompt Injection Defense)
# ------------------------------------------------------------------------------

resource "aws_bedrock_guardrail" "clinical_hipaa_guardrail" {
  name                      = "${var.project_name}-${var.environment}-guardrail"
  description               = "Enforces HIPAA PII/PHI redaction, OWASP LLM prompt injection defense, and output grounding"
  blocked_input_messaging   = "Request rejected: prompt violates enterprise HIPAA or security policy guardrails."
  blocked_outputs_messaging = "Response redacted: generated output contained unverified PHI or violated safety thresholds."

  # Content policy filters
  content_policy_config {
    filters_config {
      type            = "HATE"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }
    filters_config {
      type            = "INSULTS"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }
    filters_config {
      type            = "SEXUAL"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }
    filters_config {
      type            = "VIOLENCE"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }
    filters_config {
      type            = "MISCONDUCT"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }
    filters_config {
      type            = "PROMPT_ATTACK"
      input_strength  = "HIGH"
      output_strength = "NONE"
    }
  }

  # Sensitive information policy (PII/PHI masking & blocking)
  sensitive_information_policy_config {
    pii_entities_config {
      type   = "NAME"
      action = "ANONYMIZE"
    }
    pii_entities_config {
      type   = "US_SOCIAL_SECURITY_NUMBER"
      action = "BLOCK"
    }
    pii_entities_config {
      type   = "EMAIL"
      action = "ANONYMIZE"
    }
    pii_entities_config {
      type   = "PHONE"
      action = "ANONYMIZE"
    }
    pii_entities_config {
      type   = "US_PASSPORT_NUMBER"
      action = "BLOCK"
    }
    pii_entities_config {
      type   = "US_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER"
      action = "BLOCK"
    }

    # Custom Regex for Medical Record Number (MRN)
    regexes_config {
      name        = "MedicalRecordNumber"
      description = "Detects and blocks 7 to 10 digit hospital Medical Record Numbers"
      pattern     = "\\bMRN[ -]?[0-9]{7,10}\\b"
      action      = "BLOCK"
    }
  }

  # Word policy for prompt injection keywords
  word_policy_config {
    managed_word_lists_config {
      type = "PROFANITY"
    }
    words_config {
      text = "ignore all previous instructions"
    }
    words_config {
      text = "reveal system prompt"
    }
    words_config {
      text = "bypass guardrails"
    }
  }

  # Contextual Grounding Policy: Detects & blocks ungrounded hallucinations in clinical trial data
  contextual_grounding_policy_config {
    filters_config {
      type      = "GROUNDING"
      threshold = 0.75
    }
    filters_config {
      type      = "RELEVANCE"
      threshold = 0.75
    }
  }

  kms_key_arn = aws_kms_key.bedrock_platform.arn

  tags = {
    Name       = "${var.project_name}-${var.environment}-guardrail"
    Compliance = "HIPAA-SOC2"
  }
}

resource "aws_bedrock_guardrail_version" "clinical_hipaa_guardrail_v1" {
  guardrail_arn = aws_bedrock_guardrail.clinical_hipaa_guardrail.guardrail_arn
  description   = "Version 1.0 of HIPAA and OWASP LLM guardrail"

  depends_on = [aws_bedrock_guardrail.clinical_hipaa_guardrail]
}

# ------------------------------------------------------------------------------
# Bedrock Model Invocation Logging Configuration (Audit Trail)
# ------------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "bedrock_invocations" {
  name              = "/aws/bedrock/${var.project_name}-${var.environment}-model-invocations"
  retention_in_days = var.log_retention_in_days
  kms_key_id        = aws_kms_key.bedrock_platform.arn

  tags = {
    Name       = "${var.project_name}-${var.environment}-bedrock-invocation-logs"
    Compliance = "HIPAA-SOC2"
  }
}

# IAM Role for Bedrock Invocation Logging
resource "aws_iam_role" "bedrock_logging" {
  name = "${var.project_name}-${var.environment}-bedrock-logging-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "bedrock.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "bedrock_logging" {
  name = "${var.project_name}-${var.environment}-bedrock-logging-policy"
  role = aws_iam_role.bedrock_logging.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.bedrock_invocations.arn}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.bedrock_invocation_logs.arn}/*"
      }
    ]
  })
}

resource "aws_bedrock_model_invocation_logging_configuration" "platform" {
  logging_config {
    embedding_data_delivery_enabled = true
    image_data_delivery_enabled     = false
    text_data_delivery_enabled      = true

    cloudwatch_config {
      log_group_name = aws_cloudwatch_log_group.bedrock_invocations.name
      role_arn       = aws_iam_role.bedrock_logging.arn
    }

    s3_config {
      bucket_name = aws_s3_bucket.bedrock_invocation_logs.id
      key_prefix  = "invocations/"
    }
  }

  depends_on = [
    aws_iam_role_policy.bedrock_logging,
    aws_s3_bucket_policy.bedrock_logging_bucket_policy
  ]
}

resource "aws_s3_bucket_policy" "bedrock_logging_bucket_policy" {
  bucket = aws_s3_bucket.bedrock_invocation_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowBedrockInvocationLogging"
        Effect = "Allow"
        Principal = {
          Service = "bedrock.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.bedrock_invocation_logs.arn}/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}
