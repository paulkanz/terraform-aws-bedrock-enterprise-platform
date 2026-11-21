# ==============================================================================
# Outputs: Enterprise Bedrock GenAI & MCP Platform
# ==============================================================================

output "vpc_id" {
  description = "The ID of the multi-tenant VPC"
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "List of public subnet IDs (ALB tier)"
  value       = aws_subnet.public[*].id
}

output "private_app_subnet_ids" {
  description = "List of private application subnet IDs (ECS App & MCP Gateway)"
  value       = aws_subnet.private_app[*].id
}

output "private_data_subnet_ids" {
  description = "List of private isolated subnet IDs (VPC Endpoints & Data)"
  value       = aws_subnet.private_data[*].id
}

output "alb_dns_name" {
  description = "Public DNS name of the Application Load Balancer"
  value       = aws_lb.external.dns_name
}

output "kms_key_arn" {
  description = "ARN of the KMS Customer Managed Key (CMK)"
  value       = aws_kms_key.bedrock_platform.arn
}

output "kms_key_alias" {
  description = "Alias of the KMS Customer Managed Key"
  value       = aws_kms_alias.bedrock_platform.name
}

output "clinical_docs_bucket_name" {
  description = "Name of the S3 bucket storing raw clinical protocols and documents"
  value       = aws_s3_bucket.clinical_docs.id
}

output "bedrock_logs_bucket_name" {
  description = "Name of the S3 bucket storing Bedrock invocation audit logs"
  value       = aws_s3_bucket.bedrock_invocation_logs.id
}

output "ai_jobs_queue_url" {
  description = "URL of the primary SQS AI processing queue"
  value       = aws_sqs_queue.ai_jobs.id
}

output "ai_jobs_queue_arn" {
  description = "ARN of the primary SQS AI processing queue"
  value       = aws_sqs_queue.ai_jobs.arn
}

output "ai_jobs_dlq_url" {
  description = "URL of the SQS Dead-Letter Queue"
  value       = aws_sqs_queue.ai_jobs_dlq.id
}

output "bedrock_guardrail_arn" {
  description = "ARN of the HIPAA & OWASP LLM Bedrock Guardrail"
  value       = aws_bedrock_guardrail.clinical_hipaa_guardrail.guardrail_arn
}

output "bedrock_guardrail_id" {
  description = "ID of the HIPAA & OWASP LLM Bedrock Guardrail"
  value       = aws_bedrock_guardrail.clinical_hipaa_guardrail.guardrail_id
}

output "bedrock_guardrail_version" {
  description = "Version of the HIPAA Bedrock Guardrail"
  value       = aws_bedrock_guardrail_version.clinical_hipaa_guardrail_v1.version
}

output "ecs_cluster_name" {
  description = "Name of the ECS Fargate cluster"
  value       = aws_ecs_cluster.main.name
}

output "mcp_service_name" {
  description = "Name of the Internal MCP Service / AI Gateway ECS service"
  value       = aws_ecs_service.mcp_gateway.name
}

output "app_service_name" {
  description = "Name of the Clinical Web/API ECS service"
  value       = aws_ecs_service.app.name
}

output "guardduty_detector_id" {
  description = "ID of the AWS GuardDuty detector (NIST SI-4 threat detection)"
  value       = aws_guardduty_detector.primary.id
}

output "cloudtrail_arn" {
  description = "ARN of the Multi-Region CloudTrail audit trail (CIS 3.1, NIST AU-2)"
  value       = aws_cloudtrail.main.arn
}

output "waf_web_acl_arn" {
  description = "ARN of the AWS WAFv2 Web ACL protecting the ALB (NIST SC-7, OWASP Top 10)"
  value       = aws_wafv2_web_acl.alb.arn
}

output "config_recorder_name" {
  description = "Name of the AWS Config configuration recorder (NIST CM-2, SOC 2 change tracking)"
  value       = aws_config_configuration_recorder.main.name
}

output "access_logs_bucket_name" {
  description = "Name of the S3 bucket storing S3 and ALB access logs (CIS 2.1.4, NIST AU-9)"
  value       = aws_s3_bucket.access_logs.id
}

output "vpc_flow_logs_group_name" {
  description = "Name of the CloudWatch log group storing VPC Flow Logs (CIS 4.1, NIST AU-12)"
  value       = aws_cloudwatch_log_group.vpc_flow_logs.name
}

# ------------------------------------------------------------------------------
# Enhanced Security Outputs
# ------------------------------------------------------------------------------

output "security_hub_id" {
  description = "ID of the AWS Security Hub account (Centralized CSPM)"
  value       = aws_securityhub_account.main.id
}

output "access_analyzer_arn" {
  description = "ARN of the IAM Access Analyzer continuously vetting external exposure"
  value       = aws_accessanalyzer_analyzer.main.arn
}

output "secrets_manager_arn" {
  description = "ARN of the KMS CMK-encrypted AWS Secrets Manager platform secret"
  value       = aws_secretsmanager_secret.clinical_secrets.arn
}

output "ecr_clinical_app_url" {
  description = "URL of the Amazon ECR repository for Clinical App (Immutable tags, KMS encrypted)"
  value       = aws_ecr_repository.clinical_app.repository_url
}

output "ecr_mcp_service_url" {
  description = "URL of the Amazon ECR repository for Internal MCP Service (Immutable tags, KMS encrypted)"
  value       = aws_ecr_repository.mcp_service.repository_url
}

output "service_connect_namespace_arn" {
  description = "ARN of the Cloud Map HTTP namespace for Zero-Trust ECS Service Connect"
  value       = aws_service_discovery_http_namespace.ecs_services.arn
}

output "guardduty_event_rule_arn" {
  description = "ARN of the EventBridge rule capturing GuardDuty high-severity findings for auto-remediation"
  value       = aws_cloudwatch_event_rule.guardduty_high_severity.arn
}

output "config_drift_event_rule_arn" {
  description = "ARN of the EventBridge rule capturing AWS Config compliance drift for auto-remediation"
  value       = aws_cloudwatch_event_rule.config_compliance_drift.arn
}

# ------------------------------------------------------------------------------
# HITRUST CSF Controls Outputs
# ------------------------------------------------------------------------------

output "backup_vault_arn" {
  description = "ARN of the AWS Backup Vault (HITRUST Domain 15 Business Continuity)"
  value       = aws_backup_vault.clinical_vault.arn
}

output "backup_vault_name" {
  description = "Name of the AWS Backup Vault protected by WORM Vault Lock"
  value       = aws_backup_vault.clinical_vault.name
}

output "backup_plan_id" {
  description = "ID of the AWS Backup Plan enforcing daily backups and 7-year retention"
  value       = aws_backup_plan.clinical_backup_plan.id
}

output "macie_account_id" {
  description = "ID of the Amazon Macie account performing continuous sensitive ePHI discovery (HITRUST Domain 18)"
  value       = aws_macie2_account.primary.id
}

output "macie_event_rule_arn" {
  description = "ARN of the EventBridge rule routing Amazon Macie sensitive data findings to SecOps"
  value       = aws_cloudwatch_event_rule.macie_findings.arn
}
