variable "aws_region" {
  type        = string
  description = "AWS Commercial region for deployment (Bedrock Claude 3.5 Sonnet is natively available in us-east-1)"
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "Deployment environment name (e.g. prod, staging, dev)"
  default     = "prod"
}

variable "project_name" {
  type        = string
  description = "Project and workload prefix for resource naming"
  default     = "enterprise-genai"
}

variable "vpc_cidr" {
  type        = string
  description = "CIDR block for the multi-tenant VPC"
  default     = "10.100.0.0/16"
}

variable "availability_zones" {
  type        = list(string)
  description = "List of Availability Zones for high-availability multi-AZ deployment"
  default     = ["us-east-1a", "us-east-1b"]
}

variable "public_subnet_cidrs" {
  type        = list(string)
  description = "CIDR blocks for public subnets (ALB / Ingress)"
  default     = ["10.100.1.0/24", "10.100.2.0/24"]
}

variable "private_app_subnet_cidrs" {
  type        = list(string)
  description = "CIDR blocks for private application subnets (ECS Fargate workloads & MCP Gateway)"
  default     = ["10.100.10.0/24", "10.100.11.0/24"]
}

variable "private_data_subnet_cidrs" {
  type        = list(string)
  description = "CIDR blocks for private isolated data subnets (VPC Endpoints & internal storage)"
  default     = ["10.100.20.0/24", "10.100.21.0/24"]
}

variable "enable_nat_gateway" {
  type        = bool
  description = "Enable NAT Gateways for outbound internet access from private subnets"
  default     = true
}

variable "single_nat_gateway" {
  type        = bool
  description = "Set to true to share a single NAT Gateway across AZs (cost-saving for non-prod); set false for full multi-AZ prod redundancy"
  default     = false
}

variable "app_service_cpu" {
  type        = number
  description = "CPU units for the Clinical Web/API Fargate task (1024 = 1 vCPU)"
  default     = 1024
}

variable "app_service_memory" {
  type        = number
  description = "Memory (MB) for the Clinical Web/API Fargate task"
  default     = 2048
}

variable "app_service_desired_count" {
  type        = number
  description = "Desired number of ECS task replicas for the Clinical Web/API service"
  default     = 2
}

variable "mcp_service_cpu" {
  type        = number
  description = "CPU units for the Internal MCP Service / AI Gateway Fargate task (1024 = 1 vCPU)"
  default     = 1024
}

variable "mcp_service_memory" {
  type        = number
  description = "Memory (MB) for the Internal MCP Service / AI Gateway Fargate task"
  default     = 2048
}

variable "mcp_service_desired_count" {
  type        = number
  description = "Desired number of ECS task replicas for the Internal MCP Service / AI Gateway"
  default     = 2
}

variable "log_retention_in_days" {
  type        = number
  description = "CloudWatch log retention period in days (365 days for HIPAA/SOC 2 audit compliance)"
  default     = 365
}
