locals {
  containment_function_name = "${var.project_name}-containment"
}

data "archive_file" "containment" {
  type        = "zip"
  output_path = "${path.module}/containment_lambda.zip"

  source {
    content  = file("${path.module}/../src/containment/handler.py")
    filename = "handler.py"
  }
}

data "aws_iam_policy_document" "containment_assume_role" {
  statement {
    sid     = "AllowLambdaServiceToAssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "containment" {
  name               = "${local.containment_function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.containment_assume_role.json

  tags = {
    Name    = "${local.containment_function_name}-role"
    Purpose = "authorized-ec2-containment"
  }
}

resource "aws_cloudwatch_log_group" "containment" {
  name              = "/aws/lambda/${local.containment_function_name}"
  retention_in_days = 7

  tags = {
    Name    = "/aws/lambda/${local.containment_function_name}"
    Purpose = "containment-operational-logs"
  }
}

data "aws_iam_policy_document" "containment_permissions" {
  statement {
    sid    = "WriteContainmentLogs"
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = [
      "${aws_cloudwatch_log_group.containment.arn}:*",
    ]
  }

  statement {
    sid    = "DescribeTargetInstance"
    effect = "Allow"

    actions = [
      "ec2:DescribeInstances",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "ModifyOnlyLabTargetSecurityGroups"
    effect = "Allow"

    actions = [
      "ec2:ModifyInstanceAttribute",
    ]

    resources = [
      aws_instance.lab_target.arn,
      aws_security_group.quarantine.arn,
    ]
  }

  statement {
    sid    = "SetOnlyContainedIncidentStatus"
    effect = "Allow"

    actions = [
      "ec2:CreateTags",
    ]

    resources = [
      aws_instance.lab_target.arn,
    ]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/IncidentStatus"
      values   = ["contained"]
    }

    condition {
      test     = "ForAllValues:StringEquals"
      variable = "aws:TagKeys"
      values   = ["IncidentStatus"]
    }
  }

  statement {
    sid    = "AccessIncidentLedger"
    effect = "Allow"

    actions = [
      "dynamodb:GetItem",
      "dynamodb:UpdateItem",
    ]

    resources = [
      aws_dynamodb_table.incidents.arn,
    ]
  }

  statement {
    sid    = "PublishIncidentNotification"
    effect = "Allow"

    actions = [
      "sns:Publish",
    ]

    resources = [
      aws_sns_topic.incidents.arn,
    ]
  }

  statement {
    sid    = "UseSnsEncryptionKey"
    effect = "Allow"

    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey*",
    ]

    resources = [
      aws_kms_key.incident_notifications.arn,
    ]
  }
}

resource "aws_iam_role_policy" "containment" {
  name   = "${local.containment_function_name}-policy"
  role   = aws_iam_role.containment.id
  policy = data.aws_iam_policy_document.containment_permissions.json
}

resource "aws_lambda_function" "containment" {
  function_name = local.containment_function_name
  description   = "Safely quarantines the explicitly authorized EC2 lab target."

  role    = aws_iam_role.containment.arn
  handler = "handler.lambda_handler"
  runtime = "python3.14"

  architectures = ["x86_64"]
  memory_size   = 256
  timeout       = 20

  filename         = data.archive_file.containment.output_path
  source_code_hash = data.archive_file.containment.output_base64sha256

  environment {
    variables = {
      INCIDENTS_TABLE_NAME         = aws_dynamodb_table.incidents.name
      INCIDENT_TOPIC_ARN           = aws_sns_topic.incidents.arn
      TARGET_INSTANCE_ID           = aws_instance.lab_target.id
      BASELINE_SECURITY_GROUP_ID   = aws_security_group.baseline.id
      QUARANTINE_SECURITY_GROUP_ID = aws_security_group.quarantine.id
      REQUIRED_DATA_CLASSIFICATION = "synthetic"
      INCIDENT_RETENTION_SECONDS   = tostring(var.incident_retention_days * 86400)
      PROCESSING_LEASE_SECONDS     = tostring(var.containment_processing_lease_seconds)
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.containment,
    aws_iam_role_policy.containment,
  ]

  tags = {
    Name    = local.containment_function_name
    Purpose = "authorized-ec2-containment"
  }
}