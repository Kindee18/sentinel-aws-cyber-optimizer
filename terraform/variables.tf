# =============================================================================
# Sentinel-AWS Cyber-Optimizer — Root Variables
# =============================================================================

# -----------------------------------------------------------------------------
# General
# -----------------------------------------------------------------------------
variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "sentinel-cyber-optimizer"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "aws_region" {
  description = "AWS region for resource deployment"
  type        = string
  default     = "us-east-1"
}

# -----------------------------------------------------------------------------
# Networking
# -----------------------------------------------------------------------------
variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24"]
}

# -----------------------------------------------------------------------------
# EKS
# -----------------------------------------------------------------------------
variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  default     = "sentinel-eks"
}

variable "cluster_version" {
  description = "Kubernetes version for the EKS cluster"
  type        = string
  default     = "1.29"
}

variable "node_instance_types" {
  description = "EC2 instance types for EKS managed node group"
  type        = list(string)
  default     = ["t3.medium"]
}

variable "node_desired_size" {
  description = "Desired number of worker nodes"
  type        = number
  default     = 2
}

variable "node_min_size" {
  description = "Minimum number of worker nodes"
  type        = number
  default     = 1
}

variable "node_max_size" {
  description = "Maximum number of worker nodes"
  type        = number
  default     = 4
}

# -----------------------------------------------------------------------------
# Log Ingestion
# -----------------------------------------------------------------------------
variable "log_retention_days" {
  description = "Number of days to retain logs in S3 before transitioning to Glacier"
  type        = number
  default     = 90
}

variable "sqs_message_retention" {
  description = "SQS message retention period in seconds (default: 14 days)"
  type        = number
  default     = 1209600
}

# -----------------------------------------------------------------------------
# Multi-Tenancy
# -----------------------------------------------------------------------------
variable "tenants" {
  description = "List of tenant identifiers for multi-tenant log separation"
  type        = list(string)
  default     = ["tenant-alpha", "tenant-beta"]
}

# -----------------------------------------------------------------------------
# SIEM Integration
# -----------------------------------------------------------------------------
variable "siem_type" {
  description = "Target SIEM platform for log forwarding"
  type        = string
  default     = "microsoft-sentinel"
}
