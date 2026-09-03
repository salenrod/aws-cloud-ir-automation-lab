locals {
  orchestration_state_machine_name = "${var.project_name}-orchestration"
}

data "aws_iam_policy_document" "orchestration_assume_role" {
  statement {
    sid     = "AllowStepFunctionsServiceToAssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "orchestration" {
  name               = "${local.orchestration_state_machine_name}-role"
  assume_role_policy = data.aws_iam_policy_document.orchestration_assume_role.json

  tags = {
    Name    = "${local.orchestration_state_machine_name}-role"
    Purpose = "cloud-incident-response-orchestration"
  }
}

data "aws_iam_policy_document" "orchestration_permissions" {
  statement {
    sid    = "InvokeOnlyCloudIrFunctions"
    effect = "Allow"

    actions = [
      "lambda:InvokeFunction",
    ]

    resources = [
      aws_lambda_function.triage.arn,
      aws_lambda_function.containment.arn,
    ]
  }
}

resource "aws_iam_role_policy" "orchestration" {
  name   = "${local.orchestration_state_machine_name}-policy"
  role   = aws_iam_role.orchestration.id
  policy = data.aws_iam_policy_document.orchestration_permissions.json
}

resource "aws_sfn_state_machine" "incident_response" {
  name     = local.orchestration_state_machine_name
  role_arn = aws_iam_role.orchestration.arn
  type     = "STANDARD"

  definition = jsonencode({
    Comment = "Triage and controlled containment workflow for synthetic GuardDuty findings."
    StartAt = "TriageFinding"

    States = {
      TriageFinding = {
        Type           = "Task"
        Resource       = aws_lambda_function.triage.arn
        TimeoutSeconds = 30

        Retry = [
          {
            ErrorEquals = [
              "Lambda.ServiceException",
              "Lambda.AWSLambdaException",
              "Lambda.SdkClientException",
              "Lambda.TooManyRequestsException",
            ]
            IntervalSeconds = 2
            MaxAttempts     = 3
            BackoffRate     = 2
          },
        ]

        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            ResultPath  = "$.workflow_error"
            Next        = "WorkflowFailed"
          },
        ]

        Next = "EvaluateContainmentEligibility"
      }

      EvaluateContainmentEligibility = {
        Type = "Choice"

        Choices = [
          {
            And = [
              {
                Variable  = "$.decision.containment_eligible"
                IsPresent = true
              },
              {
                Variable      = "$.decision.containment_eligible"
                BooleanEquals = true
              },
            ]
            Next = "ContainTarget"
          },
        ]

        Default = "NoContainmentRequired"
      }

      ContainTarget = {
        Type           = "Task"
        Resource       = aws_lambda_function.containment.arn
        TimeoutSeconds = 45

        Retry = [
          {
            ErrorEquals = [
              "Lambda.ServiceException",
              "Lambda.AWSLambdaException",
              "Lambda.SdkClientException",
              "Lambda.TooManyRequestsException",
            ]
            IntervalSeconds = 2
            MaxAttempts     = 3
            BackoffRate     = 2
          },
        ]

        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            ResultPath  = "$.workflow_error"
            Next        = "WorkflowFailed"
          },
        ]

        End = true
      }

      NoContainmentRequired = {
        Type = "Pass"

        Result = {
          status     = "skipped"
          changed    = false
          idempotent = true
        }

        ResultPath = "$.workflow"
        End        = true
      }

      WorkflowFailed = {
        Type  = "Fail"
        Error = "CloudIRWorkflowFailed"
        Cause = "A task in the cloud incident response workflow failed. Inspect the execution history and Lambda logs."
      }
    }
  })

  depends_on = [
    aws_iam_role_policy.orchestration,
  ]

  tags = {
    Name    = local.orchestration_state_machine_name
    Purpose = "cloud-incident-response-orchestration"
  }
}
