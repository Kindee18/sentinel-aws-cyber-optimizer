# =============================================================================
# Security Module — Variables
# =============================================================================

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
}

variable "environment" {
  description = "Deployment environment"
  type        = string
}

variable "oidc_provider_arn" {
  description = "ARN of the EKS OIDC provider for IRSA trust"
  type        = string
}

variable "oidc_provider_url" {
  description = "URL of the EKS OIDC provider (without https://)"
  type        = string
}

variable "external_id" {
  description = "External ID for cross-account assume role (prevents confused deputy)"
  type        = string
  default     = "sentinel-security-audit-2024"
}

variable "firehose_arn" {
  description = "ARN of the Kinesis Firehose delivery stream (optional, uses wildcard if empty)"
  type        = string
  default     = ""
}
