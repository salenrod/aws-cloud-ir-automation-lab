data "aws_iam_policy_document" "incident_notifications_kms" {
  statement {
    sid    = "EnableAccountAdministration"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
      ]
    }

    actions = [
      "kms:*",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    sid    = "AllowCloudWatchAlarmNotifications"
    effect = "Allow"

    principals {
      type = "Service"

      identifiers = [
        "cloudwatch.amazonaws.com",
      ]
    }

    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey*",
    ]

    resources = [
      "*",
    ]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"

      values = [
        data.aws_caller_identity.current.account_id,
      ]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"

      values = [
        "arn:aws:cloudwatch:${var.aws_region}:${data.aws_caller_identity.current.account_id}:alarm:${var.project_name}-*",
      ]
    }
  }
}

resource "aws_kms_key" "incident_notifications" {
  description              = "Encrypts Cloud IR incident and operational alarm notifications."
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = true
  deletion_window_in_days  = 7

  policy = data.aws_iam_policy_document.incident_notifications_kms.json

  tags = {
    Name    = "${var.project_name}-incident-notifications"
    Purpose = "incident-and-operational-notification-encryption"
  }
}

resource "aws_kms_alias" "incident_notifications" {
  name          = "alias/${var.project_name}-incident-notifications"
  target_key_id = aws_kms_key.incident_notifications.key_id
}