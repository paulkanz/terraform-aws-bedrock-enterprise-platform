# ==============================================================================
# Observability, Monitoring & Alerting (CloudWatch, OpenTelemetry & SNS)
# ==============================================================================

# ------------------------------------------------------------------------------
# SNS Topics for Real-Time Alerting (KMS CMK Encrypted)
# ------------------------------------------------------------------------------

resource "aws_sns_topic" "sre_alerts" {
  name              = "${var.project_name}-${var.environment}-sre-alerts"
  kms_master_key_id = aws_kms_key.bedrock_platform.id

  tags = {
    Name       = "${var.project_name}-${var.environment}-sre-alerts"
    Compliance = "HIPAA-SOC2"
  }
}

resource "aws_sns_topic" "security_alerts" {
  name              = "${var.project_name}-${var.environment}-security-alerts"
  kms_master_key_id = aws_kms_key.bedrock_platform.id

  tags = {
    Name       = "${var.project_name}-${var.environment}-security-alerts"
    Compliance = "CIS-3.1-NIST-SI4"
  }
}

# ------------------------------------------------------------------------------
# CloudWatch Log Groups for Application & MCP Services
# ------------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "app_service" {
  name              = "/aws/ecs/${var.project_name}-${var.environment}-clinical-app"
  retention_in_days = var.log_retention_in_days
  kms_key_id        = aws_kms_key.bedrock_platform.arn

  tags = {
    Name       = "${var.project_name}-${var.environment}-app-logs"
    Compliance = "HIPAA-SOC2"
  }
}

resource "aws_cloudwatch_log_group" "mcp_service" {
  name              = "/aws/ecs/${var.project_name}-${var.environment}-mcp-service"
  retention_in_days = var.log_retention_in_days
  kms_key_id        = aws_kms_key.bedrock_platform.arn

  tags = {
    Name       = "${var.project_name}-${var.environment}-mcp-logs"
    Compliance = "HIPAA-SOC2"
  }
}

# ------------------------------------------------------------------------------
# CloudWatch Metric Alarms (SRE / Platform Reliability)
# ------------------------------------------------------------------------------

# SQS DLQ Messages Alarm (Alerts when AI processing jobs fail 3 times)
resource "aws_cloudwatch_metric_alarm" "dlq_messages" {
  alarm_name          = "${var.project_name}-${var.environment}-ai-jobs-dlq-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "Triggered when failed clinical AI jobs enter the Dead Letter Queue"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.sre_alerts.arn]

  dimensions = {
    QueueName = aws_sqs_queue.ai_jobs_dlq.name
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-dlq-alarm"
  }
}

# MCP Service High Latency Alarm
resource "aws_cloudwatch_metric_alarm" "mcp_latency" {
  alarm_name          = "${var.project_name}-${var.environment}-mcp-high-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Average"
  threshold           = 5.0 # 5 seconds
  alarm_description   = "Triggers when average AI inference response time exceeds 5 seconds"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.sre_alerts.arn]

  dimensions = {
    LoadBalancer = aws_lb.external.arn_suffix
    TargetGroup  = aws_lb_target_group.app.arn_suffix
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-latency-alarm"
  }
}
