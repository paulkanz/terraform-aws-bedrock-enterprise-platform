# Enterprise AWS Bedrock Generative AI & MCP Platform (Terraform)

Production-grade Infrastructure as Code (Terraform) deploying a **Multi-Tenant Enterprise AWS Bedrock Generative AI & Model Context Protocol (MCP) Platform** hardened for regulated industries (Healthcare, FinTech, Life Sciences).

This architecture is hardened to strictly comply with:
* **NIST SP 800-53 Rev 5** (FedRAMP High/Moderate baseline controls)
* **CIS AWS Foundations Benchmark v3.0** (Level 1 & Level 2 profiles)
* **SOC 2 Type II** (Trust Services Criteria: Security, Availability, Confidentiality)
* **HITRUST CSF v9.x / v11.x** (Healthcare security and data protection controls)
* **HIPAA Security Rule & ePHI Safeguards** (45 CFR § 164.312 Technical Safeguards)
* **FDA 21 CFR Part 11** (Time-stamped audit trails, immutable WORM records retention)
* **OWASP Top 10 for Large Language Model Applications**

> **Detailed Architecture & Security Posture Specification:** See [`docs/SECURITY_SPECIFICATION.md`](docs/SECURITY_SPECIFICATION.md) for the formal 7-layer defense-in-depth security model and regulatory controls breakdown.

---

## 1. Directory Structure

```text
terraform-aws-bedrock-enterprise-platform/
├── docs/
│   └── SECURITY_SPECIFICATION.md # Formal 7-Layer Zero-Trust & Regulatory Specification
├── versions.tf                   # Terraform CLI (>= 1.5.0), AWS (~> 5.50) & TLS providers, default compliance tags
├── variables.tf                  # Parameterized variables (VPC, CIDRs, Fargate sizing, 365-day audit log retention)
├── org_scp.tf                    # AWS Organizations SCPs (Region lock, service protection, KMS enforce, MFA delete lock)
├── security_kms.tf               # KMS Customer Managed Key (CMK) with rotation & least-privilege key policies
├── network.tf                    # Multi-AZ VPC, subnets, NAT, isolated default SG (CIS 5.1), PrivateLink VPCEs
├── storage_ingestion.tf          # S3 buckets (Docs WORM Object Lock, Invocations, Access Logs) & SQS (Main + DLQ)
├── backup_disaster_recovery.tf   # AWS Backup, Backup Plan (7-Year), Vault Lock WORM, and automated selection (HITRUST 15)
├── bedrock_guardrails.tf         # Bedrock Guardrail (HIPAA PII/PHI redaction, Prompt Attack, Contextual Grounding) & Logging
├── ecs_mcp_platform.tf           # ECS Fargate, ECR repos, Secrets Manager, Service Connect mTLS, ALB (Idle Timeout 300s)
├── waf.tf                        # AWS WAFv2 Web ACL (US Geo-Match Rule, OWASP Top 10, SQLi, IP Reputation, Rate Limiting)
├── compliance_security_audit.tf  # Security Hub, Macie ePHI discovery, Access Analyzer, EventBridge auto-remediation, Config
├── observability.tf              # CloudWatch Log Groups & Platform SRE Alarms (DLQ depth, high latency > 5s)
├── outputs.tf                    # VPC, ALB DNS, Guardrail ARN, SQS URLs, Backup Vault, Security Hub, Macie IDs
├── terraform.tfvars.example      # Production-ready configuration example
└── README.md                     # Architectural guide, regulatory matrix and runbook
```

---

## 2. Regulatory & Compliance Control Matrix

| Compliance Framework | Mandatory Control Requirement | Terraform Implementation & Resource |
| :--- | :--- | :--- |
| **HITRUST CSF v9.x / v11.x** | **Domain 15 (15.c / 15.d):** Business Continuity, Automated Backups & Disaster Recovery | `aws_backup_vault.clinical_vault` with `aws_backup_vault_lock_configuration` (immutable WORM lock, 7-year retention); automated daily backups via `aws_backup_plan`. |
| **HITRUST CSF v9.x / v11.x** | **Domain 08 & 18 (08.b / 18.b):** Network Protection & Data Sovereignty Enclave | `aws_wafv2_web_acl.alb` enforcing US Geo-Match rule (priority 0) blocking non-US IP addresses before reaching ALB. |
| **HITRUST CSF v9.x / v11.x** | **Domain 10 & 11 (10.b / 11.a):** Multi-Factor Authentication for Privileged Actions | `aws_organizations_policy.enforce_mfa_for_destructive_actions` denying `kms:ScheduleKeyDeletion`, `s3:DeleteBucket`, and CloudTrail deletion without MFA. |
| **HITRUST CSF v9.x / v11.x** | **Domain 18 (18.c / 18.d):** Automated Sensitive Data Discovery & Classification | `aws_macie2_account.primary` with automated ePHI discovery and EventBridge high/medium finding routing to SecOps. |
| **HITRUST CSF v9.x / v11.x** | **Domain 11 (11.e):** Inactivity Session Termination & Connection Teardown | `aws_lb.external` enforcing `idle_timeout = 300` (5 mins); Target Group stickiness expiring sessions after 900s (15 mins max). |
| **NIST SP 800-53 Rev 5** | **AC-3 / AC-4:** Access Enforcement & Information Flow Enforcement | Multi-AZ Private VPC, PrivateLink VPCEs, Security Groups with default drop, IAM Task Roles with least privilege. |
| **NIST SP 800-53 Rev 5** | **SC-8 / SC-13:** Cryptographic Protection & Transmission Confidentiality | `aws_kms_key.bedrock_platform` (CMK with annual rotation); `aws_secretsmanager_secret` for credentials; `aws_s3_bucket_policy` enforcing TLS >= 1.2; ALB listener enforcing `ELBSecurityPolicy-TLS13-1-2-2021-06`. |
| **NIST SP 800-53 Rev 5** | **AU-2 / AU-3 / AU-6 / AU-9 / AU-12:** Audit Logging, Content, Analysis & WORM Protection | `aws_cloudtrail.main` (multi-region with KMS encryption, SHA-256 validation & Object Lock); `aws_flow_log.vpc` (traffic type ALL); S3 invocation audit logging; 365-day CloudWatch retention; SCP denying trail deletion. |
| **NIST SP 800-53 Rev 5** | **SI-4:** Information System Monitoring & Threat Detection | `aws_guardduty_detector.primary` (S3 logs, K8s audit, EBS malware scanning); `aws_wafv2_web_acl.alb` protecting public endpoints; `aws_cloudwatch_event_rule.guardduty_high_severity` auto-remediation routing. |
| **NIST SP 800-53 Rev 5** | **CM-2 / SI-2:** Configuration Management & Flaw Remediation | `aws_config_configuration_recorder.main` with managed rules; `aws_ecr_repository` with immutable tags and scan-on-push CVE detection. |
| **CIS Benchmark v3.0** | **Section 2.1:** S3 Bucket Security Standards | All S3 buckets enforce `aws_s3_bucket_public_access_block` (2.1.2), KMS CMK encryption (2.1.1), SSL-only policies (2.1.3), versioning (2.1.5), and access logging (2.1.4). |
| **CIS Benchmark v3.0** | **Section 3.1 – 3.14:** Monitoring & Real-Time Security Alarms | CloudWatch metric filters and alarms for Unauthorized API Calls (3.1), Root Account Usage (3.3), IAM Policy Changes (3.4), S3 Policy Changes (3.8), and Security Group Changes (3.10). |
| **CIS Benchmark v3.0** | **Section 5.1 & 5.4:** Networking & Load Balancer Hardening | `aws_default_security_group.default` drops all default traffic (5.1); `aws_lb.external` drops invalid header fields (5.4) and records access logs. |
| **FDA 21 CFR Part 11** | **§11.10(a) & (e):** Validation, Time-stamped Audit Trails & Records Retention | `aws_s3_bucket_object_lock_configuration` in `COMPLIANCE` mode (7-year WORM storage for clinical records, 1-year for audit digests); immutable ECR images; AWS Backup Vault Lock. |
| **HIPAA Security Rule** | **45 CFR § 164.312(a):** Access Control & Emergency Procedures | Zero public IP addresses on application or MCP containers; traffic routed exclusively through private subnets and PrivateLink VPC Endpoints. |
| **HIPAA Security Rule** | **45 CFR § 164.312(b):** Audit Controls (ePHI Activity Tracking) | S3 access logs, Bedrock model invocation logs (hash, token count, tenant ID), CloudTrail, and VPC Flow Logs. |
| **HIPAA Security Rule** | **45 CFR § 164.312(c):** Integrity Controls (Corroborate ePHI) | S3 Object Versioning & Object Lock enabled; CloudTrail log file validation enabled with SHA-256 digital signatures. |
| **HIPAA Security Rule** | **45 CFR § 164.312(e):** Transmission Security | End-to-end TLS encryption; ECS Service Connect private service discovery; Port 80 HTTP listener redirects 301 to Port 443 HTTPS. |
| **SOC 2 Type II** | **CC6.1 – CC6.8 / CC7.2:** Logical Access, Perimeter Defense & CSPM | AWS Security Hub centralized compliance; IAM Access Analyzer continuous exposure audits; AWS WAFv2 blocking OWASP Top 10. |
| **OWASP LLM Top 10** | **LLM01 / LLM02 / LLM09:** Prompt Injection, Sensitive Info Disclosure & Hallucination | Bedrock Guardrails with PII/PHI redaction, MRN custom regex, prompt attack filters, and Contextual Grounding / Relevance filters. |

---

## 3. Key Architectural Controls

### HIPAA BAA & PrivateLink Verification
* All calls to `bedrock-runtime.us-east-1.amazonaws.com` resolve to the private IP addresses of the Interface VPC Endpoints inside `private_data` subnets.
* No clinical document text or model inference ever traverses the public internet.

### Token Cost Attribution (FinOps)
* The MCP Service container exposes a REST/gRPC endpoint (`:8000`) where application calls must supply a `tenant_id`.
* The MCP service tracks input/output tokens and writes cost attribution metrics to CloudWatch / DynamoDB for per-tenant billing.

---

## 4. Deployment Guide

### Prerequisites
1. **Terraform:** v1.5.0 or higher (`terraform version`).
2. **AWS CLI:** Configured with administrative access to target AWS Commercial Account (Region: `us-east-1`).
3. **Bedrock Model Access:** Ensure model access for **Anthropic Claude 3.5 Sonnet** and **Claude 3.5 Haiku** is requested in the AWS Bedrock Console.

### Execution

```bash
# 1. Clone the repository and navigate to the terraform directory
git clone https://github.com/paulkanz/terraform-aws-bedrock-enterprise-platform.git
cd terraform-aws-bedrock-enterprise-platform

# 2. Copy the example variables file and adjust parameters if needed
cp terraform.tfvars.example terraform.tfvars

# 3. Initialize Terraform (downloads AWS and TLS provider plugins)
terraform init

# 4. Review execution plan
terraform plan

# 5. Apply the infrastructure
terraform apply
```
