# ==============================================================================
# AWS WAFv2: Application Security Firewall (NIST SC-7, SI-4, HIPAA, HITRUST)
# ==============================================================================

resource "aws_wafv2_web_acl" "alb" {
  name        = "${var.project_name}-${var.environment}-web-acl"
  description = "WAF rules protecting Clinical API from OWASP Top 10, SQL injection, and DDoS"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # 0. HITRUST Domain 08/18: Ingress Geographic Perimeter Enclave (US-Only Restriction)
  rule {
    name     = "EnforceUSGeoRestriction"
    priority = 0

    action {
      block {}
    }

    statement {
      not_statement {
        statement {
          geo_match_statement {
            country_codes = ["US", "PR", "VI", "GU"]
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "EnforceUSGeoRestrictionMetric"
      sampled_requests_enabled   = true
    }
  }

  # 1. AWS Managed Rules: Core Rule Set (OWASP Top 10)
  rule {
    name     = "AWS-AWSManagedRulesCommonRuleSet"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # 2. AWS Managed Rules: Known Bad Inputs (SQLi, Path Traversal, Command Injection)
  rule {
    name     = "AWS-AWSManagedRulesKnownBadInputsRuleSet"
    priority = 20

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesKnownBadInputsRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # 3. AWS Managed Rules: Amazon IP Reputation List (Known malicious bots & scanners)
  rule {
    name     = "AWS-AWSManagedRulesAmazonIpReputationList"
    priority = 30

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesAmazonIpReputationListMetric"
      sampled_requests_enabled   = true
    }
  }

  # 4. Rate-Based Rule: Defend against API flooding / DDoS (Max 2,000 requests per 5 mins per IP)
  rule {
    name     = "RateLimit2000Requests"
    priority = 40

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimit2000RequestsMetric"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project_name}-${var.environment}-web-acl"
    sampled_requests_enabled   = true
  }

  tags = {
    Name       = "${var.project_name}-${var.environment}-web-acl"
    Compliance = "HIPAA-SOC2-NIST80053"
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.external.arn
  web_acl_arn  = aws_wafv2_web_acl.alb.arn
}
