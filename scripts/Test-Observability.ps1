[CmdletBinding()]
param(
    [string]$Profile = "cloud-ir-lab",
    [string]$Region = "us-east-1",
    [switch]$ExecuteNotificationTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:Passed = 0
$script:Failed = 0
$script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
$script:InfraPath = Join-Path $script:RepositoryRoot "infra"

function Write-Pass {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Evidence
    )

    $script:Passed++
    Write-Host "[PASS] $Name - $Evidence" -ForegroundColor Green
}

function Write-Fail {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Evidence
    )

    $script:Failed++
    Write-Host "[FAIL] $Name - $Evidence" -ForegroundColor Red
}

function Assert-Validation {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Evidence
    )

    if (-not $Condition) {
        throw "$Name failed: $Evidence"
    }

    Write-Pass -Name $Name -Evidence $Evidence
}

function Invoke-ExternalText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $commandOutput = @(
        & $Command @Arguments
    )

    $commandExitCode = $LASTEXITCODE

    if ($commandExitCode -ne 0) {
        throw "$Description failed with exit code $commandExitCode."
    }

    return ($commandOutput -join [Environment]::NewLine)
}

function Invoke-AwsJson {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $fullArguments = $Arguments + @(
        "--profile"
        $Profile
        "--region"
        $Region
        "--output"
        "json"
    )

    $responseText = Invoke-ExternalText `
      -Command "aws" `
      -Arguments $fullArguments `
      -Description $Description

    if ([string]::IsNullOrWhiteSpace($responseText)) {
        return $null
    }

    return $responseText | ConvertFrom-Json
}

function Get-TerraformOutputText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [switch]$Json
    )

    $arguments = @(
        "-chdir=$script:InfraPath"
        "output"
    )

    if ($Json) {
        $arguments += "-json"
    }
    else {
        $arguments += "-raw"
    }

    $arguments += $Name

    return Invoke-ExternalText `
      -Command "terraform" `
      -Arguments $arguments `
      -Description "Terraform output $Name"
}

function Invoke-NotificationTest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AlarmName,

        [Parameter(Mandatory = $true)]
        [string]$IncidentTopicArn
    )

    $alarmStateResponse = Invoke-AwsJson `
      -Arguments @(
          "cloudwatch"
          "describe-alarms"
          "--alarm-names"
          $AlarmName
      ) `
      -Description "CloudWatch alarm state lookup"

    $alarmItems = @($alarmStateResponse.MetricAlarms)

    if ($alarmItems.Count -ne 1) {
        throw "The notification test alarm was not found."
    }

    if ($alarmItems[0].StateValue -ne "OK") {
        throw (
            "The notification test requires an initial OK state; " +
            "current state is $($alarmItems[0].StateValue)."
        )
    }

    $testId = (
        "observability-test-" +
        [DateTimeOffset]::UtcNow.ToString("yyyyMMddTHHmmssfffZ")
    )

    $historyStartTime = (
        [DateTimeOffset]::UtcNow.AddSeconds(-5).ToString("o")
    )

    $alarmWasTriggered = $false
    $restoreFailure = $null
    $matchingActions = @()

    try {
        $null = Invoke-AwsJson `
          -Arguments @(
              "cloudwatch"
              "set-alarm-state"
              "--alarm-name"
              $AlarmName
              "--state-value"
              "ALARM"
              "--state-reason"
              "Controlled notification test $testId; no service failure occurred."
          ) `
          -Description "CloudWatch controlled alarm transition"

        $alarmWasTriggered = $true

        for ($attempt = 1; $attempt -le 6; $attempt++) {
            Start-Sleep -Seconds 5

            $history = Invoke-AwsJson `
              -Arguments @(
                  "cloudwatch"
                  "describe-alarm-history"
                  "--alarm-name"
                  $AlarmName
                  "--history-item-type"
                  "Action"
                  "--start-date"
                  $historyStartTime
                  "--scan-by"
                  "TimestampDescending"
                  "--max-records"
                  "20"
              ) `
              -Description "CloudWatch alarm action history lookup"

            $matchingActions = @(
                $history.AlarmHistoryItems |
                  Where-Object {
                      $historyText = (
                          [string]$_.HistorySummary +
                          " " +
                          [string]$_.HistoryData
                      )

                      $historyText -match "Successfully executed action" -and
                      $historyText -match [regex]::Escape($IncidentTopicArn)
                  }
            )

            if ($matchingActions.Count -gt 0) {
                break
            }
        }
    }
    finally {
        if ($alarmWasTriggered) {
            try {
                $null = Invoke-AwsJson `
                  -Arguments @(
                      "cloudwatch"
                      "set-alarm-state"
                      "--alarm-name"
                      $AlarmName
                      "--state-value"
                      "OK"
                      "--state-reason"
                      "Controlled notification test $testId completed; restoring baseline state."
                  ) `
                  -Description "CloudWatch alarm state recovery"
            }
            catch {
                $restoreFailure = $_.Exception.Message
            }
        }
    }

    if ($null -ne $restoreFailure) {
        throw "Alarm recovery failed: $restoreFailure"
    }

    if ($matchingActions.Count -eq 0) {
        throw "CloudWatch did not record successful execution of the SNS action."
    }

    Write-Pass `
      -Name "Controlled alarm transition" `
      -Evidence "OK-to-ALARM"

    Write-Pass `
      -Name "CloudWatch SNS action" `
      -Evidence "success-history-recorded"

    Write-Pass `
      -Name "Automatic alarm recovery" `
      -Evidence "State=OK"

    Write-Host "Notification test ID: $testId"
    Write-Host "Check the configured mailbox for the CloudWatch notification."
}

Write-Host ""
Write-Host "AWS Cloud IR Automation Lab"
Write-Host "Observability Validation"
Write-Host "Profile: $Profile"
Write-Host "Region:  $Region"

if ($ExecuteNotificationTest) {
    Write-Host "Mode:    controlled-notification"
}
else {
    Write-Host "Mode:    read-only"
}

Write-Host ""

try {
    Assert-Validation `
      -Condition ($null -ne (Get-Command "aws" -ErrorAction SilentlyContinue)) `
      -Name "AWS CLI available" `
      -Evidence "aws-command-found"

    Assert-Validation `
      -Condition ($null -ne (Get-Command "terraform" -ErrorAction SilentlyContinue)) `
      -Name "Terraform available" `
      -Evidence "terraform-command-found"

    $identity = Invoke-AwsJson `
      -Arguments @(
          "sts"
          "get-caller-identity"
      ) `
      -Description "AWS identity lookup"

    Assert-Validation `
      -Condition (-not [string]::IsNullOrWhiteSpace([string]$identity.Account)) `
      -Name "AWS identity available" `
      -Evidence "account-resolved"

    $dashboardName = (
        Get-TerraformOutputText `
          -Name "observability_dashboard_name"
    ).Trim()

    $incidentTopicArn = (
        Get-TerraformOutputText `
          -Name "incident_topic_arn"
    ).Trim()

    $alarmNamesText = Get-TerraformOutputText `
      -Name "observability_alarm_names" `
      -Json

    $expectedAlarmNames = [string[]](
        $alarmNamesText | ConvertFrom-Json
    )

    Assert-Validation `
      -Condition ($expectedAlarmNames.Count -eq 6) `
      -Name "Terraform observability alarm outputs" `
      -Evidence "AlarmCount=$($expectedAlarmNames.Count)"

    $dashboardResponse = Invoke-AwsJson `
      -Arguments @(
          "cloudwatch"
          "get-dashboard"
          "--dashboard-name"
          $dashboardName
      ) `
      -Description "CloudWatch dashboard lookup"

    $dashboardBody = $dashboardResponse.DashboardBody |
      ConvertFrom-Json

    $dashboardWidgets = @($dashboardBody.widgets)
    $textWidgetCount = @(
        $dashboardWidgets |
          Where-Object { $_.type -eq "text" }
    ).Count

    $metricWidgetCount = @(
        $dashboardWidgets |
          Where-Object { $_.type -eq "metric" }
    ).Count

    $alarmWidgets = @(
        $dashboardWidgets |
          Where-Object { $_.type -eq "alarm" }
    )

    Assert-Validation `
      -Condition ($dashboardWidgets.Count -eq 7) `
      -Name "CloudWatch dashboard widgets" `
      -Evidence "WidgetCount=$($dashboardWidgets.Count)"

    Assert-Validation `
      -Condition (
          $textWidgetCount -eq 1 -and
          $metricWidgetCount -eq 5 -and
          $alarmWidgets.Count -eq 1
      ) `
      -Name "CloudWatch dashboard layout" `
      -Evidence "Text=1; Metric=5; Alarm=1"

    $alarmArguments = @(
        "cloudwatch"
        "describe-alarms"
        "--alarm-names"
    ) + $expectedAlarmNames

    $alarmResponse = Invoke-AwsJson `
      -Arguments $alarmArguments `
      -Description "CloudWatch alarm lookup"

    $observabilityAlarms = @($alarmResponse.MetricAlarms)

    Assert-Validation `
      -Condition ($observabilityAlarms.Count -eq 6) `
      -Name "CloudWatch operational alarms" `
      -Evidence "AlarmCount=$($observabilityAlarms.Count)"

    $actualAlarmNames = [string[]]@(
        $observabilityAlarms |
          ForEach-Object { [string]$_.AlarmName }
    )

    $missingAlarmNames = @(
        $expectedAlarmNames |
          Where-Object { $actualAlarmNames -notcontains $_ }
    )

    Assert-Validation `
      -Condition ($missingAlarmNames.Count -eq 0) `
      -Name "Expected alarm names" `
      -Evidence "missing=0"

    $unexpectedAlarmConfiguration = @(
        $observabilityAlarms |
          Where-Object {
              $_.ComparisonOperator -ne "GreaterThanOrEqualToThreshold" -or
              [double]$_.Threshold -ne 1 -or
              [int]$_.Period -ne 300 -or
              [int]$_.EvaluationPeriods -ne 1 -or
              [int]$_.DatapointsToAlarm -ne 1 -or
              $_.TreatMissingData -ne "notBreaching" -or
              $_.ActionsEnabled -ne $true
          }
    )

    Assert-Validation `
      -Condition ($unexpectedAlarmConfiguration.Count -eq 0) `
      -Name "Alarm threshold and evaluation configuration" `
      -Evidence "unexpected=0"

    $alarmsWithoutTopic = @(
        $observabilityAlarms |
          Where-Object {
              @($_.AlarmActions) -notcontains $incidentTopicArn
          }
    )

    Assert-Validation `
      -Condition ($alarmsWithoutTopic.Count -eq 0) `
      -Name "Alarm SNS actions" `
      -Evidence "configured=6/6"

    $alarmsOutsideOk = @(
        $observabilityAlarms |
          Where-Object { $_.StateValue -ne "OK" }
    )

    Assert-Validation `
      -Condition ($alarmsOutsideOk.Count -eq 0) `
      -Name "Operational alarm state" `
      -Evidence "OK=6/6"

    $expectedMetricPairs = [string[]]@(
        "AWS/Events|FailedInvocations"
        "AWS/SQS|ApproximateNumberOfMessagesVisible"
        "AWS/States|ExecutionsFailed"
        "AWS/States|ExecutionsTimedOut"
        "AWS/Lambda|Errors"
        "AWS/Lambda|Errors"
    )

    $actualMetricPairs = [string[]]@(
        $observabilityAlarms |
          ForEach-Object {
              "$($_.Namespace)|$($_.MetricName)"
          }
    )

    $expectedMetricGroups = @(
        $expectedMetricPairs | Group-Object
    )

    $actualMetricGroups = @(
        $actualMetricPairs | Group-Object
    )

    $metricProblems = @(
        $expectedMetricGroups |
          Where-Object {
              $expectedGroup = $_
              $actualGroup = @(
                  $actualMetricGroups |
                    Where-Object { $_.Name -eq $expectedGroup.Name }
              )

              $actualGroup.Count -ne 1 -or
              $actualGroup[0].Count -ne $expectedGroup.Count
          }
    )

    Assert-Validation `
      -Condition ($metricProblems.Count -eq 0) `
      -Name "Operational metric coverage" `
      -Evidence "EventBridge, DLQ, StepFunctions, Lambda"

    $alarmArns = [string[]]@(
        $observabilityAlarms |
          ForEach-Object { [string]$_.AlarmArn }
    )

    $dashboardAlarmArns = [string[]]@(
        $alarmWidgets[0].properties.alarms
    )

    $alarmsMissingFromDashboard = @(
        $alarmArns |
          Where-Object { $dashboardAlarmArns -notcontains $_ }
    )

    Assert-Validation `
      -Condition ($alarmsMissingFromDashboard.Count -eq 0) `
      -Name "Dashboard alarm coverage" `
      -Evidence "represented=6/6"

    $kmsAliasName = "alias/cloud-ir-lab-incident-notifications"

    $kmsResponse = Invoke-AwsJson `
      -Arguments @(
          "kms"
          "describe-key"
          "--key-id"
          $kmsAliasName
      ) `
      -Description "KMS key lookup"

    $kmsMetadata = $kmsResponse.KeyMetadata
    $kmsKeyId = [string]$kmsMetadata.KeyId
    $kmsKeyArn = [string]$kmsMetadata.Arn

    Assert-Validation `
      -Condition (
          $kmsMetadata.Enabled -eq $true -and
          $kmsMetadata.KeyState -eq "Enabled" -and
          $kmsMetadata.KeyManager -eq "CUSTOMER"
      ) `
      -Name "Notification KMS key" `
      -Evidence "State=Enabled; Manager=CUSTOMER"

    $rotationStatus = Invoke-AwsJson `
      -Arguments @(
          "kms"
          "get-key-rotation-status"
          "--key-id"
          $kmsKeyId
      ) `
      -Description "KMS rotation status lookup"

    Assert-Validation `
      -Condition ($rotationStatus.KeyRotationEnabled -eq $true) `
      -Name "Notification KMS key rotation" `
      -Evidence "PeriodDays=$($rotationStatus.RotationPeriodInDays)"

    $topicAttributes = Invoke-AwsJson `
      -Arguments @(
          "sns"
          "get-topic-attributes"
          "--topic-arn"
          $incidentTopicArn
      ) `
      -Description "SNS topic attribute lookup"

    $topicKeyReference = [string](
        $topicAttributes.Attributes.KmsMasterKeyId
    )

    Assert-Validation `
      -Condition (-not [string]::IsNullOrWhiteSpace($topicKeyReference)) `
      -Name "SNS topic server-side encryption" `
      -Evidence "KmsMasterKeyId=present"

    $topicKeyResponse = Invoke-AwsJson `
      -Arguments @(
          "kms"
          "describe-key"
          "--key-id"
          $topicKeyReference
      ) `
      -Description "SNS KMS key resolution"

    Assert-Validation `
      -Condition ($topicKeyResponse.KeyMetadata.KeyId -eq $kmsKeyId) `
      -Name "SNS project key assignment" `
      -Evidence "project-key-confirmed"

    $containmentPolicy = Invoke-AwsJson `
      -Arguments @(
          "iam"
          "get-role-policy"
          "--role-name"
          "cloud-ir-lab-containment-role"
          "--policy-name"
          "cloud-ir-lab-containment-policy"
      ) `
      -Description "Containment IAM policy lookup"

    $kmsStatements = @(
        $containmentPolicy.PolicyDocument.Statement |
          Where-Object { $_.Sid -eq "UseSnsEncryptionKey" }
    )

    $containmentKmsResources = [string[]]@()

    if ($kmsStatements.Count -eq 1) {
        $containmentKmsResources = [string[]]@(
            $kmsStatements[0].Resource
        )
    }

    Assert-Validation `
      -Condition (
          $kmsStatements.Count -eq 1 -and
          $containmentKmsResources -contains $kmsKeyArn
      ) `
      -Name "Containment KMS authorization" `
      -Evidence "project-key-confirmed"

    $subscriptions = Invoke-AwsJson `
      -Arguments @(
          "sns"
          "list-subscriptions-by-topic"
          "--topic-arn"
          $incidentTopicArn
      ) `
      -Description "SNS subscription lookup"

    $emailSubscriptions = @(
        $subscriptions.Subscriptions |
          Where-Object { $_.Protocol -eq "email" }
    )

    $confirmedEmailSubscriptions = @(
        $emailSubscriptions |
          Where-Object {
              $_.SubscriptionArn -ne "PendingConfirmation"
          }
    )

    Assert-Validation `
      -Condition ($emailSubscriptions.Count -gt 0) `
      -Name "SNS email subscription" `
      -Evidence "EmailSubscriptions=$($emailSubscriptions.Count)"

    Assert-Validation `
      -Condition (
          $confirmedEmailSubscriptions.Count -eq
          $emailSubscriptions.Count
      ) `
      -Name "SNS email confirmation" `
      -Evidence "Confirmed=$($confirmedEmailSubscriptions.Count)"

    if ($ExecuteNotificationTest) {
        $notificationAlarmNames = @(
            $expectedAlarmNames |
              Where-Object {
                  $_ -eq "cloud-ir-lab-triage-lambda-errors"
              }
        )

        if ($notificationAlarmNames.Count -ne 1) {
            throw "The controlled notification alarm output is missing."
        }

        Write-Host ""
        Write-Host "Executing controlled CloudWatch notification test..."
        Write-Host ""

        Invoke-NotificationTest `
          -AlarmName $notificationAlarmNames[0] `
          -IncidentTopicArn $incidentTopicArn
    }
    else {
        Write-Pass `
          -Name "Notification test safety" `
          -Evidence "not-requested"
    }
}
catch {
    Write-Host ""
    Write-Fail `
      -Name "Observability validation" `
      -Evidence $_.Exception.Message
}

Write-Host ""
Write-Host "Validation summary"
Write-Host "Passed: $script:Passed"
Write-Host "Failed: $script:Failed"

if ($script:Failed -gt 0) {
    exit 1
}

exit 0
