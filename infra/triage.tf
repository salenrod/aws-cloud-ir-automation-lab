locals {
  triage_function_name = "${var.project_name}-triage"
}

data "archive_file" "triage" {
  type        = "zip"
  output_path = "${path.module}/triage_lambda.zip"

  source {
    content  = file("${path.module}/../src/triage/handler.py")
    filename = "handler.py"
  }
}

data "aws_iam_policy_document" "triage_assume_role" {
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

resource "aws_iam_role" "triage" {
  name               = "${local.triage_function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.triage_assume_role.json

  tags = {
    Name    = "${local.triage_function_name}-role"
    Purpose = "guardduty-finding-triage"
  }
}

resource "aws_cloudwatch_log_group" "triage" {
  name              = "/aws/lambda/${local.triage_function_name}"
  retention_in_days = 7

  tags = {
    Name    = "/aws/lambda/${local.triage_function_name}"
    Purpose = "triage-operational-logs"
  }
}

data "aws_iam_policy_document" "triage_permissions" {
  statement {
    sid    = "WriteTriageLogs"
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]

    resources = [
      "${aws_cloudwatch_log_group.triage.arn}:*"
    ]
  }

  statement {
    sid    = "DescribeTargetInstances"
    effect = "Allow"

    actions = [
      "ec2:DescribeInstances"
    ]

    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "triage" {
  name   = "${local.triage_function_name}-policy"
  role   = aws_iam_role.triage.id
  policy = data.aws_iam_policy_document.triage_permissions.json
}

resource "aws_lambda_function" "triage" {
  function_name = local.triage_function_name
  description   = "Normalizes and enriches GuardDuty findings for the Cloud IR lab."

  role    = aws_iam_role.triage.arn
  handler = "handler.lambda_handler"
  runtime = "python3.14"

  architectures = ["x86_64"]
  memory_size   = 128
  timeout       = 10

  filename         = data.archive_file.triage.output_path
  source_code_hash = data.archive_file.triage.output_base64sha256

  environment {
    variables = {
      MIN_SEVERITY = tostring(var.triage_minimum_severity)
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.triage,
    aws_iam_role_policy.triage
  ]

  tags = {
    Name    = local.triage_function_name
    Purpose = "guardduty-finding-triage"
  }
}