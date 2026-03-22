# =============================================================================
# Log Ingestion Module — S3 + SQS Bridge for SIEM Integration
# Secure, encrypted log storage with event-driven SIEM notification
# =============================================================================

# -----------------------------------------------------------------------------
# Data Sources
# -----------------------------------------------------------------------------
data "aws_caller_identity" "current" {}

# -----------------------------------------------------------------------------
# S3 Bucket — Centralized Log Storage
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "logs" {
  bucket        = "${var.project_name}-logs-${var.environment}-${data.aws_caller_identity.current.account_id}"
  force_destroy = var.environment == "dev" ? true : false

  tags = {
    Name        = "${var.project_name}-logs"
    DataClass   = "security-logs"
    Compliance  = "required"
  }
}

# Enable versioning for audit trail
resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Server-side encryption with KMS
resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle rules for cost optimization
resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "log-lifecycle"
    status = "Enabled"

    transition {
      days          = var.log_retention_days
      storage_class = "GLACIER"
    }

    expiration {
      days = var.log_retention_days * 4  # Delete after 4x retention period
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# Bucket logging for audit
resource "aws_s3_bucket_logging" "logs" {
  bucket = aws_s3_bucket.logs.id

  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "access-logs/"
}

# Bucket policy — least privilege
resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnencryptedTransport"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.logs.arn,
          "${aws_s3_bucket.logs.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "DenyIncorrectEncryption"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.logs.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid    = "AllowFirehoseDelivery"
        Effect = "Allow"
        Principal = {
          Service = "firehose.amazonaws.com"
        }
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl",
          "s3:GetBucketLocation",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.logs.arn,
          "${aws_s3_bucket.logs.arn}/*"
        ]
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# Per-tenant prefix organization
resource "aws_s3_object" "tenant_prefix" {
  for_each = toset(var.tenants)

  bucket  = aws_s3_bucket.logs.id
  key     = "${each.value}/"
  content = ""

  tags = {
    Tenant = each.value
  }
}

# -----------------------------------------------------------------------------
# SQS Queue — SIEM Notification Channel
# -----------------------------------------------------------------------------
resource "aws_sqs_queue" "siem_notifications" {
  name                       = "${var.project_name}-siem-notifications-${var.environment}"
  message_retention_seconds  = var.sqs_message_retention
  visibility_timeout_seconds = 300
  receive_wait_time_seconds  = 20  # Long polling for cost efficiency
  kms_master_key_id          = var.kms_key_id

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.siem_dlq.arn
    maxReceiveCount     = 3
  })

  tags = {
    Name = "${var.project_name}-siem-notifications"
  }
}

# Dead Letter Queue for failed SIEM notifications
resource "aws_sqs_queue" "siem_dlq" {
  name                      = "${var.project_name}-siem-dlq-${var.environment}"
  message_retention_seconds = 1209600  # 14 days max
  kms_master_key_id         = var.kms_key_id

  tags = {
    Name = "${var.project_name}-siem-dlq"
  }
}

# SQS Queue Policy — Allow S3 to send notifications
resource "aws_sqs_queue_policy" "siem_notifications" {
  queue_url = aws_sqs_queue.siem_notifications.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowS3Notification"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.siem_notifications.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_s3_bucket.logs.arn
          }
        }
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# S3 → SQS Event Notification
# Triggers SIEM ingestion when new log objects arrive
# -----------------------------------------------------------------------------
resource "aws_s3_bucket_notification" "siem" {
  bucket = aws_s3_bucket.logs.id

  queue {
    queue_arn     = aws_sqs_queue.siem_notifications.arn
    events        = ["s3:ObjectCreated:*"]
    filter_prefix = ""
    filter_suffix = ".json.gz"
  }

  depends_on = [aws_sqs_queue_policy.siem_notifications]
}
