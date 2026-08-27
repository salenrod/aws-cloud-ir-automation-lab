resource "aws_s3_bucket" "evidence" {
  bucket        = local.evidence_bucket_name
  force_destroy = true

  tags = {
    Name           = local.evidence_bucket_name
    Purpose        = "incident-evidence"
    DataClass      = "synthetic-security-evidence"
    RetentionDays  = tostring(var.evidence_retention_days)
    PublicExposure = "prohibited"
  }
}

resource "aws_s3_bucket_ownership_controls" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  depends_on = [
    aws_s3_bucket_versioning.evidence
  ]

  rule {
    id     = "expire-lab-evidence"
    status = "Enabled"

    filter {
      prefix = ""
    }

    expiration {
      days = var.evidence_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.evidence_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_dynamodb_table" "incidents" {
  name         = "${var.project_name}-incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "incident_id"
  table_class  = "STANDARD"

  deletion_protection_enabled = false

  attribute {
    name = "incident_id"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = {
    Name    = "${var.project_name}-incidents"
    Purpose = "incident-ledger-and-idempotency"
  }
}

resource "aws_sns_topic" "incidents" {
  name              = "${var.project_name}-notifications"
  display_name      = "Cloud IR Lab"
  kms_master_key_id = "alias/aws/sns"

  tags = {
    Name    = "${var.project_name}-notifications"
    Purpose = "incident-notification"
  }
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.incidents.arn
  protocol  = "email"
  endpoint  = var.alert_email
}