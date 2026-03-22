# =============================================================================
# Firehose Module — Outputs
# =============================================================================

output "firehose_arn" {
  description = "ARN of the Kinesis Firehose delivery stream"
  value       = aws_kinesis_firehose_delivery_stream.logs.arn
}

output "firehose_name" {
  description = "Name of the Kinesis Firehose delivery stream"
  value       = aws_kinesis_firehose_delivery_stream.logs.name
}

output "lambda_function_arn" {
  description = "ARN of the Lambda log transformer function"
  value       = aws_lambda_function.log_transformer.arn
}

output "lambda_function_name" {
  description = "Name of the Lambda log transformer function"
  value       = aws_lambda_function.log_transformer.function_name
}
