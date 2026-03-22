# =============================================================================
# Security Module — IAM, KMS, Cross-Account Roles, IRSA
# Centralized security configuration for multi-tenant architecture
# =============================================================================

# -----------------------------------------------------------------------------
# Data Sources
# -----------------------------------------------------------------------------
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# -----------------------------------------------------------------------------
# KMS Key — Master Encryption Key for all security-sensitive resources
# -----------------------------------------------------------------------------
resource "aws_kms_key" "master" {
  description             = "Master encryption key for ${var.project_name}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = false

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowS3ServiceEncryption"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowSQSServiceEncryption"
        Effect = "Allow"
        Principal = {
          Service = "sqs.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-master-key-${var.environment}"
  }
}

resource "aws_kms_alias" "master" {
  name          = "alias/${var.project_name}-master-${var.environment}"
  target_key_id = aws_kms_key.master.key_id
}

# -----------------------------------------------------------------------------
# Cross-Account Role — Security Account Assume Role
# Simulates a security account role that client accounts can assume
# -----------------------------------------------------------------------------
resource "aws_iam_role" "security_audit" {
  name = "${var.project_name}-security-audit-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.external_id
          }
        }
      }
    ]
  })

  tags = {
    Name    = "${var.project_name}-security-audit-role"
    Account = "security"
  }
}

resource "aws_iam_role_policy" "security_audit" {
  name = "${var.project_name}-security-audit-policy"
  role = aws_iam_role.security_audit.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOnlySecurityAudit"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "sqs:ReceiveMessage",
          "sqs:GetQueueAttributes",
          "logs:GetLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "cloudtrail:LookupEvents",
          "guardduty:ListFindings",
          "guardduty:GetFindings"
        ]
        Resource = "*"
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# IRSA Role — Fluent Bit Logging Agent
# Allows pods to write to Kinesis Firehose without embedded credentials
# -----------------------------------------------------------------------------
resource "aws_iam_role" "fluent_bit" {
  name = "${var.project_name}-fluent-bit-irsa-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = var.oidc_provider_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${var.oidc_provider_url}:sub" = "system:serviceaccount:logging:fluent-bit"
            "${var.oidc_provider_url}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-fluent-bit-irsa"
  }
}

resource "aws_iam_role_policy" "fluent_bit" {
  name = "${var.project_name}-fluent-bit-policy"
  role = aws_iam_role.fluent_bit.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "FirehoseWrite"
        Effect = "Allow"
        Action = [
          "firehose:PutRecord",
          "firehose:PutRecordBatch"
        ]
        Resource = var.firehose_arn != "" ? var.firehose_arn : "arn:${data.aws_partition.current.partition}:firehose:*:${data.aws_caller_identity.current.account_id}:deliverystream/${var.project_name}-*"
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:${data.aws_partition.current.partition}:logs:*:${data.aws_caller_identity.current.account_id}:log-group:/aws/eks/*"
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# IRSA Role — Lambda Log Transformer
# Allows Lambda to read from Firehose and write to S3
# -----------------------------------------------------------------------------
resource "aws_iam_role" "lambda_transformer" {
  name = "${var.project_name}-lambda-transformer-role-${var.environment}"

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
    Name = "${var.project_name}-lambda-transformer-role"
  }
}

resource "aws_iam_role_policy" "lambda_transformer" {
  name = "${var.project_name}-lambda-transformer-policy"
  role = aws_iam_role.lambda_transformer.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:${data.aws_partition.current.partition}:logs:*:${data.aws_caller_identity.current.account_id}:*"
      },
      {
        Sid    = "KMSDecrypt"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.master.arn
      }
    ]
  })
}

# Attach basic Lambda execution policy
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.lambda_transformer.name
}
