# =============================================================================
# Security Module — Outputs
# =============================================================================

output "kms_key_arn" {
  description = "ARN of the master KMS encryption key"
  value       = aws_kms_key.master.arn
}

output "kms_key_id" {
  description = "ID of the master KMS encryption key"
  value       = aws_kms_key.master.key_id
}

output "security_audit_role_arn" {
  description = "ARN of the cross-account security audit role"
  value       = aws_iam_role.security_audit.arn
}

output "fluent_bit_role_arn" {
  description = "ARN of the IRSA role for Fluent Bit"
  value       = aws_iam_role.fluent_bit.arn
}

output "lambda_transformer_role_arn" {
  description = "ARN of the Lambda log transformer execution role"
  value       = aws_iam_role.lambda_transformer.arn
}
