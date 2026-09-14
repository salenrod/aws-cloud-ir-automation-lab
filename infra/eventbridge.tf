locals {
  eventbridge_bus_name         = "${var.project_name}-security-events"
  eventbridge_rule_name        = "${var.project_name}-guardduty-ec2-findings"
  eventbridge_target_role_name = "${var.project_name}-eventbridge-target-role"
  eventbridge_dlq_name         = "${var.project_name}-eventbridge-dlq"
}

resource "aws_cloudwatch_event_bus" "security_events" {
  name = local.eventbridge_bus_name

  tags = {
    Name    = local.eventbridge_bus_name
    Purpose = "isolated-synthetic-security-event-ingestion"
  }
}

resource "aws_cloudwatch_event_rule" "guardduty_ec2_findings" {
  name           = local.eventbridge_rule_name
  description    = "Routes synthetic GuardDuty-shaped EC2 findings to the Cloud IR workflow."
  event_bus_name = aws_cloudwatch_event_bus.security_events.name
  state          = "ENABLED"

  event_pattern = jsonencode({
    source      = ["cloud-ir-lab.guardduty"]
    detail-type = ["GuardDuty Finding"]

    detail = {
      resource = {
        resourceType = ["Instance"]
      }
    }
  })

  tags = {
    Name    = local.eventbridge_rule_name
    Purpose = "synthetic-guardduty-ec2-ingestion"
  }
}

data "aws_iam_policy_document" "eventbridge_assume_role" {
  statement {
    sid     = "AllowEventBridgeServiceToAssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "eventbridge_target" {
  name               = local.eventbridge_target_role_name
  assume_role_policy = data.aws_iam_policy_document.eventbridge_assume_role.json

  tags = {
    Name    = local.eventbridge_target_role_name
    Purpose = "start-only-cloud-ir-state-machine"
  }
}

data "aws_iam_policy_document" "eventbridge_target_permissions" {
  statement {
    sid       = "StartOnlyCloudIrStateMachine"
    effect    = "Allow"
    actions   = ["states:StartExecution"]
    resources = [aws_sfn_state_machine.incident_response.arn]
  }
}

resource "aws_iam_role_policy" "eventbridge_target" {
  name   = "${local.eventbridge_target_role_name}-policy"
  role   = aws_iam_role.eventbridge_target.id
  policy = data.aws_iam_policy_document.eventbridge_target_permissions.json
}

resource "aws_sqs_queue" "eventbridge_dlq" {
  name                      = local.eventbridge_dlq_name
  message_retention_seconds = 345600
  sqs_managed_sse_enabled   = true

  tags = {
    Name    = local.eventbridge_dlq_name
    Purpose = "failed-eventbridge-deliveries"
  }
}

data "aws_iam_policy_document" "eventbridge_dlq" {
  statement {
    sid     = "AllowOnlyCloudIrRuleToSendMessages"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]

    resources = [
      aws_sqs_queue.eventbridge_dlq.arn,
    ]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.guardduty_ec2_findings.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "eventbridge_dlq" {
  queue_url = aws_sqs_queue.eventbridge_dlq.id
  policy    = data.aws_iam_policy_document.eventbridge_dlq.json
}

resource "aws_cloudwatch_event_target" "incident_response" {
  rule           = aws_cloudwatch_event_rule.guardduty_ec2_findings.name
  event_bus_name = aws_cloudwatch_event_bus.security_events.name
  target_id      = "CloudIRIncidentResponse"
  arn            = aws_sfn_state_machine.incident_response.arn
  role_arn       = aws_iam_role.eventbridge_target.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 2
  }

  dead_letter_config {
    arn = aws_sqs_queue.eventbridge_dlq.arn
  }

  depends_on = [
    aws_iam_role_policy.eventbridge_target,
    aws_sqs_queue_policy.eventbridge_dlq,
  ]
}

output "eventbridge_bus_name" {
  description = "Custom event bus used for isolated synthetic security events."
  value       = aws_cloudwatch_event_bus.security_events.name
}

output "eventbridge_bus_arn" {
  description = "ARN of the custom security event bus."
  value       = aws_cloudwatch_event_bus.security_events.arn
}

output "eventbridge_rule_name" {
  description = "Name of the rule that routes synthetic EC2 findings."
  value       = aws_cloudwatch_event_rule.guardduty_ec2_findings.name
}

output "eventbridge_dlq_url" {
  description = "URL of the dead-letter queue for failed target deliveries."
  value       = aws_sqs_queue.eventbridge_dlq.id
}

output "eventbridge_dlq_arn" {
  description = "ARN of the dead-letter queue for failed target deliveries."
  value       = aws_sqs_queue.eventbridge_dlq.arn
}
