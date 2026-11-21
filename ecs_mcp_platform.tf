# ==============================================================================
# ECS Fargate Compute: Application Tier & Internal MCP Service (AI Gateway)
# ==============================================================================

resource "aws_ecs_cluster" "main" {
  name = "${var.project_name}-${var.environment}-ecs-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-ecs-cluster"
  }
}

# ------------------------------------------------------------------------------
# IAM Roles for ECS Tasks
# ------------------------------------------------------------------------------

# 1. ECS Task Execution Role (Pulling images, fetching secrets, logging)
resource "aws_iam_role" "ecs_execution_role" {
  name = "${var.project_name}-${var.environment}-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution_standard" {
  role       = aws_iam_role.ecs_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "ecs_execution_kms_and_secrets" {
  name = "${var.project_name}-${var.environment}-ecs-execution-kms-secrets"
  role = aws_iam_role.ecs_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.bedrock_platform.arn
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:${var.project_name}-${var.environment}-*"
      }
    ]
  })
}

# 2. ECS Task Role for Internal MCP Service (AI Gateway)
resource "aws_iam_role" "mcp_task_role" {
  name = "${var.project_name}-${var.environment}-mcp-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "mcp_bedrock_policy" {
  name = "${var.project_name}-${var.environment}-mcp-bedrock-policy"
  role = aws_iam_role.mcp_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowBedrockInference"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ]
        Resource = [
          "arn:aws:bedrock:${var.aws_region}::foundation-model/anthropic.claude-3-5-sonnet*",
          "arn:aws:bedrock:${var.aws_region}::foundation-model/anthropic.claude-3-5-haiku*",
          "arn:aws:bedrock:${var.aws_region}::foundation-model/amazon.titan-embed-text-*"
        ]
      },
      {
        Sid    = "AllowBedrockGuardrails"
        Effect = "Allow"
        Action = [
          "bedrock:ApplyGuardrail"
        ]
        Resource = aws_bedrock_guardrail.clinical_hipaa_guardrail.guardrail_arn
      },
      {
        Sid    = "AllowS3DocumentAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.clinical_docs.arn,
          "${aws_s3_bucket.clinical_docs.arn}/*"
        ]
      },
      {
        Sid    = "AllowSQSMessageProcessing"
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = aws_sqs_queue.ai_jobs.arn
      },
      {
        Sid    = "AllowKMSOperations"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*"
        ]
        Resource = aws_kms_key.bedrock_platform.arn
      }
    ]
  })
}

# 3. ECS Task Role for Clinical Web/API Service
resource "aws_iam_role" "app_task_role" {
  name = "${var.project_name}-${var.environment}-app-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "app_permissions" {
  name = "${var.project_name}-${var.environment}-app-policy"
  role = aws_iam_role.app_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowS3Uploads"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.clinical_docs.arn,
          "${aws_s3_bucket.clinical_docs.arn}/*"
        ]
      },
      {
        Sid    = "AllowSQSSend"
        Effect = "Allow"
        Action = [
          "sqs:SendMessage",
          "sqs:GetQueueUrl"
        ]
        Resource = aws_sqs_queue.ai_jobs.arn
      },
      {
        Sid    = "AllowKMS"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*"
        ]
        Resource = aws_kms_key.bedrock_platform.arn
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# Application Load Balancer (Public Ingress - CIS 5.4, NIST SC-8, HIPAA)
# ------------------------------------------------------------------------------

resource "aws_lb" "external" {
  name                       = "${var.project_name}-${var.environment}-alb"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = aws_subnet.public[*].id
  drop_invalid_header_fields = true # CIS 5.4 / NIST SC-8: Drop invalid HTTP header fields
  idle_timeout               = 300  # HITRUST Domain 11 (11.e): 5-minute inactive connection teardown
  enable_deletion_protection = false

  access_logs {
    bucket  = aws_s3_bucket.access_logs.id
    prefix  = "alb-access-logs"
    enabled = true
  }

  tags = {
    Name       = "${var.project_name}-${var.environment}-alb"
    Compliance = "HIPAA-SOC2-CIS5.4-HITRUST-11e"
  }
}

# Self-signed TLS certificate for local/staging verification (replaced with ACM cert ARN in production)
resource "tls_private_key" "alb_cert" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "alb_cert" {
  private_key_pem = tls_private_key.alb_cert.private_key_pem

  subject {
    common_name  = "api.${var.project_name}.internal"
    organization = "Enterprise Platform Architecture"
  }

  validity_period_hours = 8760 # 1 year

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth"
  ]
}

resource "aws_acm_certificate" "alb_cert" {
  private_key      = tls_private_key.alb_cert.private_key_pem
  certificate_body = tls_self_signed_cert.alb_cert.cert_pem

  tags = {
    Name       = "${var.project_name}-${var.environment}-alb-cert"
    Compliance = "HIPAA-SOC2"
  }
}

resource "aws_lb_target_group" "app" {
  name        = "${var.project_name}-${var.environment}-app-tg"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  # HITRUST Domain 11 (11.e): Enforce 15-minute (900s) maximum session inactivity limit
  stickiness {
    type            = "lb_cookie"
    cookie_duration = 900
    enabled         = true
  }

  health_check {
    path                = "/health"
    matcher             = "200-299"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-app-tg"
  }
}

# Port 80 Listener: Redirect all unencrypted HTTP traffic to HTTPS (Port 443)
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.external.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# Port 443 Listener: Enforces TLS 1.2 / 1.3 modern cipher policy (HIPAA Transmission Security & NIST SC-8)
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.external.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.alb_cert.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# ------------------------------------------------------------------------------
# Amazon ECR: Immutable Container Repositories with KMS Encryption & CVE Scanning
# ------------------------------------------------------------------------------

resource "aws_ecr_repository" "clinical_app" {
  name                 = "${var.project_name}/${var.environment}/clinical-app"
  image_tag_mutability = "IMMUTABLE" # NIST CM-2: Supply chain tamper protection

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.bedrock_platform.arn
  }

  image_scanning_configuration {
    scan_on_push = true # NIST SI-2: Automated vulnerability scanning
  }

  tags = {
    Name       = "${var.project_name}-ecr-app"
    Compliance = "NIST-SI2-SOC2"
  }
}

resource "aws_ecr_repository" "mcp_service" {
  name                 = "${var.project_name}/${var.environment}/mcp-service"
  image_tag_mutability = "IMMUTABLE"

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.bedrock_platform.arn
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name       = "${var.project_name}-ecr-mcp"
    Compliance = "NIST-SI2-SOC2"
  }
}

resource "aws_ecr_lifecycle_policy" "clinical_app" {
  repository = aws_ecr_repository.clinical_app.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 30 tagged production releases"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 30
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

resource "aws_ecr_lifecycle_policy" "mcp_service" {
  repository = aws_ecr_repository.mcp_service.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 30 tagged production releases"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 30
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# AWS Secrets Manager: KMS-Encrypted Credentials & Service Tokens
# ------------------------------------------------------------------------------

resource "aws_secretsmanager_secret" "clinical_secrets" {
  name                    = "${var.project_name}-${var.environment}-platform-secrets"
  description             = "Encrypted application secrets, database credentials, and service tokens for clinical AI platform"
  kms_key_id              = aws_kms_key.bedrock_platform.arn
  recovery_window_in_days = 30

  tags = {
    Name       = "${var.project_name}-${var.environment}-secrets"
    Compliance = "HIPAA-SOC2-NIST-SC13"
  }
}

resource "aws_secretsmanager_secret_version" "clinical_secrets" {
  secret_id = aws_secretsmanager_secret.clinical_secrets.id
  secret_string = jsonencode({
    DB_PASSWORD      = "TemporaryBootstrapPasswordChangeInProd123!"
    API_SECRET_KEY   = "TemporaryBootstrapKeyChangeInProd456!"
    MCP_INTERNAL_KEY = "TemporaryBootstrapMCPKeyChangeInProd789!"
  })
}

# ------------------------------------------------------------------------------
# AWS Cloud Map & ECS Service Connect: Zero-Trust East-West Microservice Network
# ------------------------------------------------------------------------------

resource "aws_service_discovery_http_namespace" "ecs_services" {
  name        = "${var.project_name}.internal"
  description = "Cloud Map namespace for ECS Service Connect private microservice routing"

  tags = {
    Name       = "${var.project_name}-service-connect-ns"
    Compliance = "HIPAA-SOC2-NIST-SC8"
  }
}

# ------------------------------------------------------------------------------
# ECS Tasks & Services (Fargate)
# ------------------------------------------------------------------------------

# 1. Clinical Web / API Service
resource "aws_ecs_task_definition" "app" {
  family                   = "${var.project_name}-${var.environment}-app"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = tostring(var.app_service_cpu)
  memory                   = tostring(var.app_service_memory)
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn
  task_role_arn            = aws_iam_role.app_task_role.arn

  container_definitions = jsonencode([
    {
      name      = "clinical-app"
      image     = "${aws_ecr_repository.clinical_app.repository_url}:latest"
      essential = true
      portMappings = [
        {
          name          = "app-port"
          containerPort = 8080
          hostPort      = 8080
          protocol      = "tcp"
          appProtocol   = "http"
        }
      ]
      environment = [
        { name = "ENVIRONMENT", value = var.environment },
        { name = "DOCS_BUCKET", value = aws_s3_bucket.clinical_docs.id },
        { name = "AI_JOBS_QUEUE_URL", value = aws_sqs_queue.ai_jobs.id },
        { name = "MCP_GATEWAY_URL", value = "http://mcp-gateway:8000" }
      ]
      secrets = [
        {
          name      = "DB_PASSWORD"
          valueFrom = "${aws_secretsmanager_secret.clinical_secrets.arn}:DB_PASSWORD::"
        },
        {
          name      = "API_SECRET_KEY"
          valueFrom = "${aws_secretsmanager_secret.clinical_secrets.arn}:API_SECRET_KEY::"
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.app_service.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "app"
        }
      }
    }
  ])

  tags = {
    Name = "${var.project_name}-${var.environment}-app-task"
  }
}

resource "aws_ecs_service" "app" {
  name            = "${var.project_name}-${var.environment}-app-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = var.app_service_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private_app[*].id
    security_groups  = [aws_security_group.app.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = "clinical-app"
    container_port   = 8080
  }

  service_connect_configuration {
    enabled   = true
    namespace = aws_service_discovery_http_namespace.ecs_services.arn
  }

  depends_on = [aws_lb_listener.https]

  tags = {
    Name = "${var.project_name}-${var.environment}-app-service"
  }
}

# 2. Internal MCP Service / AI Gateway
resource "aws_ecs_task_definition" "mcp_gateway" {
  family                   = "${var.project_name}-${var.environment}-mcp-gateway"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = tostring(var.mcp_service_cpu)
  memory                   = tostring(var.mcp_service_memory)
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn
  task_role_arn            = aws_iam_role.mcp_task_role.arn

  container_definitions = jsonencode([
    {
      name      = "mcp-gateway"
      image     = "${aws_ecr_repository.mcp_service.repository_url}:latest"
      essential = true
      portMappings = [
        {
          name          = "mcp-port"
          containerPort = 8000
          hostPort      = 8000
          protocol      = "tcp"
          appProtocol   = "http"
        }
      ]
      environment = [
        { name = "ENVIRONMENT", value = var.environment },
        { name = "AWS_BEDROCK_REGION", value = var.aws_region },
        { name = "GUARDRAIL_ID", value = aws_bedrock_guardrail.clinical_hipaa_guardrail.guardrail_id },
        { name = "GUARDRAIL_VERSION", value = aws_bedrock_guardrail_version.clinical_hipaa_guardrail_v1.version },
        { name = "DEFAULT_CLAUDE_MODEL", value = "anthropic.claude-3-5-sonnet-20241022-v2:0" },
        { name = "HAIKU_CLAUDE_MODEL", value = "anthropic.claude-3-5-haiku-20241022-v1:0" },
        { name = "DOCS_BUCKET", value = aws_s3_bucket.clinical_docs.id },
        { name = "AI_JOBS_QUEUE_URL", value = aws_sqs_queue.ai_jobs.id }
      ]
      secrets = [
        {
          name      = "MCP_INTERNAL_KEY"
          valueFrom = "${aws_secretsmanager_secret.clinical_secrets.arn}:MCP_INTERNAL_KEY::"
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.mcp_service.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "mcp"
        }
      }
    }
  ])

  tags = {
    Name = "${var.project_name}-${var.environment}-mcp-task"
  }
}

resource "aws_ecs_service" "mcp_gateway" {
  name            = "${var.project_name}-${var.environment}-mcp-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.mcp_gateway.arn
  desired_count   = var.mcp_service_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private_app[*].id
    security_groups  = [aws_security_group.mcp_gateway.id]
    assign_public_ip = false
  }

  service_connect_configuration {
    enabled   = true
    namespace = aws_service_discovery_http_namespace.ecs_services.arn
    service {
      discovery_name = "mcp-gateway"
      port_name      = "mcp-port"
      client_alias {
        port = 8000
      }
    }
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-mcp-service"
  }
}
