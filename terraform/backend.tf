# =============================================================================
# Sentinel-AWS Cyber-Optimizer — Remote Backend Configuration
# =============================================================================
# Uncomment the block below for production deployments.
# Ensure the S3 bucket and DynamoDB table exist before enabling.
#
# terraform {
#   backend "s3" {
#     bucket         = "sentinel-cyber-optimizer-tfstate"
#     key            = "infrastructure/terraform.tfstate"
#     region         = "us-east-1"
#     encrypt        = true
#     dynamodb_table = "sentinel-terraform-lock"
#
#     # Enable versioning on the state bucket for rollback capability
#     # Enable server-side encryption with KMS for security compliance
#   }
# }
