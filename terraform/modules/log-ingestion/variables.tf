# =============================================================================
# Log Ingestion Module — Variables
# =============================================================================

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
}

variable "environment" {
  description = "Deployment environment"
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of the KMS key for encryption"
  type        = string
}

variable "kms_key_id" {
  description = "ID of the KMS key for SQS encryption"
  type        = string
}

variable "log_retention_days" {
  description = "Days before transitioning logs to Glacier"
  type        = number
  default     = 90
}

variable "sqs_message_retention" {
  description = "SQS message retention in seconds"
  type        = number
  default     = 1209600
}

variable "tenants" {
  description = "List of tenant identifiers for log prefix organization"
  type        = list(string)
  default     = []
}
