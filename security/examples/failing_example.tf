# =============================================================================
# INTENTIONALLY NON-COMPLIANT Terraform Configuration
# This file demonstrates security violations that Checkov should catch
# =============================================================================
# PURPOSE: Used for compliance testing — this MUST FAIL Checkov scans
# =============================================================================

# ❌ VIOLATION: S3 bucket without encryption
# Checkov: CKV_AWS_19, CKV_AWS_145
resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "insecure-unencrypted-logs"
}

# ❌ VIOLATION: No public access block
# Checkov: CKV_AWS_53, CKV_AWS_54, CKV_AWS_55, CKV_AWS_56
# (Missing aws_s3_bucket_public_access_block resource)

# ❌ VIOLATION: No versioning
# Checkov: CKV_AWS_21
# (Missing aws_s3_bucket_versioning resource)

# ❌ VIOLATION: No access logging
# Checkov: CKV_AWS_18
# (Missing aws_s3_bucket_logging resource)

# ❌ VIOLATION: Security group allows unrestricted SSH access
# Checkov: CKV_AWS_24
resource "aws_security_group" "allow_all_ssh" {
  name        = "allow-all-ssh"
  description = "INSECURE: Allows SSH from anywhere"
  vpc_id      = "vpc-12345678"

  ingress {
    description = "SSH from anywhere - INSECURE"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # ❌ Unrestricted SSH access
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ❌ VIOLATION: Security group allows unrestricted RDP access
# Checkov: CKV_AWS_25
resource "aws_security_group" "allow_all_rdp" {
  name        = "allow-all-rdp"
  description = "INSECURE: Allows RDP from anywhere"
  vpc_id      = "vpc-12345678"

  ingress {
    description = "RDP from anywhere - INSECURE"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # ❌ Unrestricted RDP access
  }
}

# ❌ VIOLATION: IAM role with overly permissive policy
# Checkov: CKV_AWS_40
resource "aws_iam_role_policy" "overly_permissive" {
  name = "overly-permissive-policy"
  role = "some-role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"          # ❌ Full wildcard permissions
        Resource = "*"          # ❌ All resources
      }
    ]
  })
}

# ❌ VIOLATION: KMS key without rotation
# Checkov: CKV_AWS_7
resource "aws_kms_key" "no_rotation" {
  description         = "KMS key without rotation - INSECURE"
  enable_key_rotation = false  # ❌ Key rotation disabled
}
