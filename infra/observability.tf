locals {
  observability_dashboard_name = "${var.project_name}-secops-overview"

  observability_alarm_names = {
    eventbridge_failed_invocations = "${var.project_name}-eventbridge-failed-invocations"
    eventbridge_dlq_messages       = "${var.project_name}-eventbridge-dlq-messages"
    workflow_failed_executions     = "${var.project_name}-workflow-failed-executions"
    workflow_timed_out_executions  = "${var.project_name}-workflow-timed-out-executions"
    triage_lambda_errors           = "${var.project_name}-triage-lambda-errors"
    containment_lambda_errors      = "${var.project_name}-containment-lambda-errors"
  }
}

resource "aws_cloudwatch_metric_alarm" "eventbridge_failed_invocations" {
  alarm_name        = local.observability_alarm_names.eventbridge_failed_invocations
  alarm_description = "Detects failed deliveries from the Cloud IR EventBridge rule to its target."
  alarm_actions     = [aws_sns_topic.incidents.arn]

  namespace   = "AWS/Events"
  metric_name = "FailedInvocations"
  dimensions = {
    EventBusName = aws_cloudwatch_event_bus.security_events.name
    RuleName     = aws_cloudwatch_event_rule.guardduty_ec2_findings.name
  }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  tags = {
    Name    = local.observability_alarm_names.eventbridge_failed_invocations
    Purpose = "eventbridge-delivery-monitoring"
  }
}

resource "aws_cloudwatch_metric_alarm" "eventbridge_dlq_messages" {
  alarm_name        = local.observability_alarm_names.eventbridge_dlq_messages
  alarm_description = "Detects visible messages in the EventBridge target dead-letter queue."
  alarm_actions     = [aws_sns_topic.incidents.arn]

  namespace   = "AWS/SQS"
  metric_name = "ApproximateNumberOfMessagesVisible"
  dimensions = {
    QueueName = aws_sqs_queue.eventbridge_dlq.name
  }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  tags = {
    Name    = local.observability_alarm_names.eventbridge_dlq_messages
    Purpose = "eventbridge-dlq-monitoring"
  }
}

resource "aws_cloudwatch_metric_alarm" "workflow_failed_executions" {
  alarm_name        = local.observability_alarm_names.workflow_failed_executions
  alarm_description = "Detects failed Cloud IR Step Functions executions."
  alarm_actions     = [aws_sns_topic.incidents.arn]

  namespace   = "AWS/States"
  metric_name = "ExecutionsFailed"
  dimensions = {
    StateMachineArn = aws_sfn_state_machine.incident_response.arn
  }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  tags = {
    Name    = local.observability_alarm_names.workflow_failed_executions
    Purpose = "workflow-failure-monitoring"
  }
}

resource "aws_cloudwatch_metric_alarm" "workflow_timed_out_executions" {
  alarm_name        = local.observability_alarm_names.workflow_timed_out_executions
  alarm_description = "Detects timed-out Cloud IR Step Functions executions."
  alarm_actions     = [aws_sns_topic.incidents.arn]

  namespace   = "AWS/States"
  metric_name = "ExecutionsTimedOut"
  dimensions = {
    StateMachineArn = aws_sfn_state_machine.incident_response.arn
  }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  tags = {
    Name    = local.observability_alarm_names.workflow_timed_out_executions
    Purpose = "workflow-timeout-monitoring"
  }
}

resource "aws_cloudwatch_metric_alarm" "triage_lambda_errors" {
  alarm_name        = local.observability_alarm_names.triage_lambda_errors
  alarm_description = "Detects errors returned by the Cloud IR triage Lambda function."
  alarm_actions     = [aws_sns_topic.incidents.arn]

  namespace   = "AWS/Lambda"
  metric_name = "Errors"
  dimensions = {
    FunctionName = aws_lambda_function.triage.function_name
  }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  tags = {
    Name    = local.observability_alarm_names.triage_lambda_errors
    Purpose = "triage-error-monitoring"
  }
}

resource "aws_cloudwatch_metric_alarm" "containment_lambda_errors" {
  alarm_name        = local.observability_alarm_names.containment_lambda_errors
  alarm_description = "Detects errors returned by the Cloud IR containment Lambda function."
  alarm_actions     = [aws_sns_topic.incidents.arn]

  namespace   = "AWS/Lambda"
  metric_name = "Errors"
  dimensions = {
    FunctionName = aws_lambda_function.containment.function_name
  }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  tags = {
    Name    = local.observability_alarm_names.containment_lambda_errors
    Purpose = "containment-error-monitoring"
  }
}

resource "aws_cloudwatch_dashboard" "secops" {
  dashboard_name = local.observability_dashboard_name

  dashboard_body = jsonencode({
    start = "-PT6H"

    widgets = [
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 2

        properties = {
          markdown = "# AWS Cloud IR Automation Lab\nOperational view for event ingestion, orchestration, triage, containment and failed-delivery handling."
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 2
        width  = 12
        height = 6

        properties = {
          title   = "Incident workflow executions"
          view    = "timeSeries"
          region  = var.aws_region
          period  = 300
          stat    = "Sum"
          stacked = false

          metrics = [
            ["AWS/States", "ExecutionsStarted", "StateMachineArn", aws_sfn_state_machine.incident_response.arn, { label = "Started" }],
            ["AWS/States", "ExecutionsSucceeded", "StateMachineArn", aws_sfn_state_machine.incident_response.arn, { label = "Succeeded" }],
            ["AWS/States", "ExecutionsFailed", "StateMachineArn", aws_sfn_state_machine.incident_response.arn, { color = "#d62728", label = "Failed" }],
            ["AWS/States", "ExecutionsTimedOut", "StateMachineArn", aws_sfn_state_machine.incident_response.arn, { color = "#ff7f0e", label = "Timed out" }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 2
        width  = 12
        height = 6

        properties = {
          title   = "EventBridge rule delivery"
          view    = "timeSeries"
          region  = var.aws_region
          period  = 300
          stat    = "Sum"
          stacked = false

          metrics = [
            ["AWS/Events", "TriggeredRules", "EventBusName", aws_cloudwatch_event_bus.security_events.name, "RuleName", aws_cloudwatch_event_rule.guardduty_ec2_findings.name, { label = "Triggered rules" }],
            ["AWS/Events", "Invocations", "EventBusName", aws_cloudwatch_event_bus.security_events.name, "RuleName", aws_cloudwatch_event_rule.guardduty_ec2_findings.name, { label = "Target invocations" }],
            ["AWS/Events", "FailedInvocations", "EventBusName", aws_cloudwatch_event_bus.security_events.name, "RuleName", aws_cloudwatch_event_rule.guardduty_ec2_findings.name, { color = "#d62728", label = "Failed invocations" }],
            ["AWS/Events", "InvocationsSentToDlq", "EventBusName", aws_cloudwatch_event_bus.security_events.name, "RuleName", aws_cloudwatch_event_rule.guardduty_ec2_findings.name, { color = "#9467bd", label = "Sent to DLQ" }],
            ["AWS/Events", "InvocationsFailedToBeSentToDlq", "EventBusName", aws_cloudwatch_event_bus.security_events.name, "RuleName", aws_cloudwatch_event_rule.guardduty_ec2_findings.name, { color = "#8c564b", label = "Failed to reach DLQ" }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 8
        width  = 12
        height = 6

        properties = {
          title   = "Lambda invocations and errors"
          view    = "timeSeries"
          region  = var.aws_region
          period  = 300
          stat    = "Sum"
          stacked = false

          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", aws_lambda_function.triage.function_name, { label = "Triage invocations" }],
            ["AWS/Lambda", "Errors", "FunctionName", aws_lambda_function.triage.function_name, { color = "#d62728", label = "Triage errors" }],
            ["AWS/Lambda", "Invocations", "FunctionName", aws_lambda_function.containment.function_name, { label = "Containment invocations" }],
            ["AWS/Lambda", "Errors", "FunctionName", aws_lambda_function.containment.function_name, { color = "#ff9896", label = "Containment errors" }],
            ["AWS/Lambda", "Throttles", "FunctionName", aws_lambda_function.triage.function_name, { color = "#ff7f0e", label = "Triage throttles" }],
            ["AWS/Lambda", "Throttles", "FunctionName", aws_lambda_function.containment.function_name, { color = "#bcbd22", label = "Containment throttles" }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 8
        width  = 12
        height = 6

        properties = {
          title   = "Response duration p95"
          view    = "timeSeries"
          region  = var.aws_region
          period  = 300
          stacked = false
          yAxis = {
            left = {
              label     = "Milliseconds"
              showUnits = false
            }
          }

          metrics = [
            ["AWS/States", "ExecutionTime", "StateMachineArn", aws_sfn_state_machine.incident_response.arn, { label = "Workflow p95", stat = "p95" }],
            ["AWS/Lambda", "Duration", "FunctionName", aws_lambda_function.triage.function_name, { label = "Triage p95", stat = "p95" }],
            ["AWS/Lambda", "Duration", "FunctionName", aws_lambda_function.containment.function_name, { label = "Containment p95", stat = "p95" }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 14
        width  = 12
        height = 6

        properties = {
          title   = "EventBridge DLQ backlog"
          view    = "timeSeries"
          region  = var.aws_region
          period  = 300
          stat    = "Maximum"
          stacked = false

          metrics = [
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", aws_sqs_queue.eventbridge_dlq.name, { color = "#d62728", label = "Visible messages" }],
            ["AWS/SQS", "ApproximateAgeOfOldestMessage", "QueueName", aws_sqs_queue.eventbridge_dlq.name, { color = "#ff7f0e", label = "Oldest message age" }]
          ]
        }
      },
      {
        type   = "alarm"
        x      = 12
        y      = 14
        width  = 12
        height = 6

        properties = {
          title = "Operational alarm state"
          alarms = [
            aws_cloudwatch_metric_alarm.eventbridge_failed_invocations.arn,
            aws_cloudwatch_metric_alarm.eventbridge_dlq_messages.arn,
            aws_cloudwatch_metric_alarm.workflow_failed_executions.arn,
            aws_cloudwatch_metric_alarm.workflow_timed_out_executions.arn,
            aws_cloudwatch_metric_alarm.triage_lambda_errors.arn,
            aws_cloudwatch_metric_alarm.containment_lambda_errors.arn
          ]
        }
      }
    ]
  })
}

output "observability_dashboard_name" {
  description = "Name of the CloudWatch dashboard used for SecOps visibility."
  value       = aws_cloudwatch_dashboard.secops.dashboard_name
}

output "observability_alarm_names" {
  description = "Names of the CloudWatch alarms used for operational monitoring."
  value = [
    aws_cloudwatch_metric_alarm.eventbridge_failed_invocations.alarm_name,
    aws_cloudwatch_metric_alarm.eventbridge_dlq_messages.alarm_name,
    aws_cloudwatch_metric_alarm.workflow_failed_executions.alarm_name,
    aws_cloudwatch_metric_alarm.workflow_timed_out_executions.alarm_name,
    aws_cloudwatch_metric_alarm.triage_lambda_errors.alarm_name,
    aws_cloudwatch_metric_alarm.containment_lambda_errors.alarm_name
  ]
}
