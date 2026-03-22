# =============================================================================
# COMPLIANT Terraform Configuration
# This file demonstrates security best practices that pass Checkov scans
# =============================================================================
# PURPOSE: Used for compliance testing — this MUST PASS Checkov scans
# =============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ✅ COMPLIANT: KMS key with rotation enabled
# Checkov: CKV_AWS_7
resource "aws_kms_key" "secure_key" {
  description             = "Secure KMS key with rotation enabled"
  deletion_window_in_days = 30
  enable_key_rotation     = true  # ✅ Key rotation enabled

  tags = {
    Name    = "secure-encryption-key"
    Purpose = "log-encryption"
  }
}

# ✅ COMPLIANT: S3 bucket with full security configuration
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "secure-encrypted-logs-example"

  tags = {
    Name       = "secure-logs"
    Compliance = "required"
  }
}

# ✅ COMPLIANT: Server-side encryption with KMS
# Checkov: CKV_AWS_19, CKV_AWS_145
resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.secure_key.arn
    }
    bucket_key_enabled = true
  }
}

# ✅ COMPLIANT: Versioning enabled
# Checkov: CKV_AWS_21
resource "aws_s3_bucket_versioning" "secure" {
  bucket = aws_s3_bucket.secure_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

# ✅ COMPLIANT: Public access fully blocked
# Checkov: CKV_AWS_53, CKV_AWS_54, CKV_AWS_55, CKV_AWS_56
resource "aws_s3_bucket_public_access_block" "secure" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ✅ COMPLIANT: Access logging enabled
# Checkov: CKV_AWS_18
resource "aws_s3_bucket_logging" "secure" {
  bucket = aws_s3_bucket.secure_bucket.id

  target_bucket = aws_s3_bucket.secure_bucket.id
  target_prefix = "access-logs/"
}

# ✅ COMPLIANT: Security group with restricted SSH access
# Checkov: CKV_AWS_24
resource "aws_security_group" "restricted_ssh" {
  name        = "restricted-ssh-access"
  description = "SECURE: SSH restricted to corporate VPN CIDR only"
  vpc_id      = "vpc-12345678"

  ingress {
    description = "SSH from corporate VPN only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # ✅ Restricted to private CIDR
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "restricted-ssh-sg"
  }
}

# ✅ COMPLIANT: IAM role with least-privilege policy
# Checkov: CKV_AWS_40
resource "aws_iam_role" "least_privilege" {
  name = "secure-least-privilege-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "secure-role"
  }
}

resource "aws_iam_role_policy" "least_privilege" {
  name = "secure-least-privilege-policy"
  role = aws_iam_role.least_privilege.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSpecificS3Access"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.secure_bucket.arn}/*"  # ✅ Specific resource
      },
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:log-group:/aws/lambda/*"  # ✅ Scoped logs
      }
    ]
  })
}
