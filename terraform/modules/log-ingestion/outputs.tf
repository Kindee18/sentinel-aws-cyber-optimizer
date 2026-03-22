# =============================================================================
# Log Ingestion Module — Outputs
# =============================================================================

output "log_bucket_arn" {
  description = "ARN of the S3 log bucket"
  value       = aws_s3_bucket.logs.arn
}

output "log_bucket_id" {
  description = "ID of the S3 log bucket"
  value       = aws_s3_bucket.logs.id
}

output "sqs_queue_arn" {
  description = "ARN of the SQS SIEM notification queue"
  value       = aws_sqs_queue.siem_notifications.arn
}

output "sqs_queue_url" {
  description = "URL of the SQS SIEM notification queue"
  value       = aws_sqs_queue.siem_notifications.id
}

output "sqs_dlq_arn" {
  description = "ARN of the SQS Dead Letter Queue"
  value       = aws_sqs_queue.siem_dlq.arn
}
