# =============================================================================
# Sentinel-AWS Cyber-Optimizer — Root Outputs
# =============================================================================

# -----------------------------------------------------------------------------
# Networking
# -----------------------------------------------------------------------------
output "vpc_id" {
  description = "ID of the VPC"
  value       = module.networking.vpc_id
}

output "private_subnet_ids" {
  description = "IDs of private subnets"
  value       = module.networking.private_subnet_ids
}

# -----------------------------------------------------------------------------
# EKS
# -----------------------------------------------------------------------------
output "eks_cluster_name" {
  description = "Name of the EKS cluster"
  value       = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  description = "EKS cluster API server endpoint"
  value       = module.eks.cluster_endpoint
}

output "eks_oidc_provider_arn" {
  description = "ARN of the OIDC provider for IRSA"
  value       = module.eks.oidc_provider_arn
}

# -----------------------------------------------------------------------------
# Security
# -----------------------------------------------------------------------------
output "kms_key_arn" {
  description = "ARN of the master KMS encryption key"
  value       = module.security.kms_key_arn
}

output "security_audit_role_arn" {
  description = "ARN of the cross-account security audit role"
  value       = module.security.security_audit_role_arn
}

output "fluent_bit_irsa_role_arn" {
  description = "ARN of the IRSA role for Fluent Bit logging agent"
  value       = module.security.fluent_bit_role_arn
}

# -----------------------------------------------------------------------------
# Log Ingestion
# -----------------------------------------------------------------------------
output "log_bucket_arn" {
  description = "ARN of the S3 log storage bucket"
  value       = module.log_ingestion.log_bucket_arn
}

output "siem_queue_url" {
  description = "URL of the SQS queue for SIEM notifications"
  value       = module.log_ingestion.sqs_queue_url
}

# -----------------------------------------------------------------------------
# Firehose Pipeline
# -----------------------------------------------------------------------------
output "firehose_stream_name" {
  description = "Name of the Kinesis Firehose delivery stream"
  value       = module.firehose.firehose_name
}

output "lambda_transformer_arn" {
  description = "ARN of the Lambda log transformer function"
  value       = module.firehose.lambda_function_arn
}

# -----------------------------------------------------------------------------
# Deployment Info
# -----------------------------------------------------------------------------
output "kubeconfig_command" {
  description = "Command to configure kubectl"
  value       = "aws eks update-kubeconfig --name ${module.eks.cluster_name} --region ${var.aws_region}"
}
