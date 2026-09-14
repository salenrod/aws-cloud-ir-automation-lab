[CmdletBinding()]
param(
    [string]$Profile = "cloud-ir-lab",
    [string]$Region = "us-east-1"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:Passed = 0
$script:Failed = 0
$script:TemporaryDirectory = $null
$script:Succeeded = $false

function Write-Pass {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Detail
    )

    $script:Passed++
    Write-Host "[PASS] $Name - $Detail" -ForegroundColor Green
}

function Assert-Test {
    param(
        [Parameter(Mandatory)]
        [bool]$Condition,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Detail
    )

    if (-not $Condition) {
        throw "$Name failed: $Detail"
    }

    Write-Pass -Name $Name -Detail $Detail
}

function Get-PropertyValue {
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Invoke-AwsJson {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    $output = & aws @Arguments
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        throw "AWS CLI failed with exit code ${exitCode}: aws $($Arguments -join ' ')"
    }

    $text = ($output -join [Environment]::NewLine).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    return $text | ConvertFrom-Json
}

function Invoke-TerraformOutput {
    param(
        [Parameter(Mandatory)]
        [string]$InfraDirectory,

        [Parameter(Mandatory)]
        [string]$Name
    )

    $output = & terraform "-chdir=$InfraDirectory" output -raw $Name
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        throw "Terraform output '$Name' failed with exit code $exitCode."
    }

    return ($output -join [Environment]::NewLine).Trim()
}

function Write-Utf8NoBomJson {
    param(
        [Parameter(Mandatory)]
        [object]$Value,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $json = ConvertTo-Json -InputObject $Value -Depth 50
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json, $utf8NoBom)
}

function Get-TagMap {
    param(
        [Parameter(Mandatory)]
        [object]$Instance
    )

    $tagMap = @{}
    foreach ($tag in @($Instance.Tags)) {
        if ($null -ne $tag.Key) {
            $tagMap[[string]$tag.Key] = [string]$tag.Value
        }
    }

    return $tagMap
}

function Get-LabInstance {
    param(
        [Parameter(Mandatory)]
        [string]$InstanceId
    )

    $response = Invoke-AwsJson -Arguments @(
        "ec2", "describe-instances",
        "--instance-ids", $InstanceId,
        "--profile", $Profile,
        "--region", $Region,
        "--output", "json"
    )

    $instances = @(
        $response.Reservations |
            ForEach-Object { $_.Instances }
    )

    if ($instances.Count -ne 1) {
        throw "Expected exactly one lab instance, found $($instances.Count)."
    }

    return $instances[0]
}

function Get-DlqAttributes {
    param(
        [Parameter(Mandatory)]
        [string]$QueueUrl
    )

    return Invoke-AwsJson -Arguments @(
        "sqs", "get-queue-attributes",
        "--queue-url", $QueueUrl,
        "--attribute-names",
        "QueueArn",
        "ApproximateNumberOfMessages",
        "MessageRetentionPeriod",
        "SqsManagedSseEnabled",
        "--profile", $Profile,
        "--region", $Region,
        "--output", "json"
    )
}

function Find-ExecutionByIncident {
    param(
        [Parameter(Mandatory)]
        [string]$StateMachineArn,

        [Parameter(Mandatory)]
        [string]$IncidentId,

        [Parameter(Mandatory)]
        [string]$ListingPath
    )

    for ($attempt = 1; $attempt -le 30; $attempt++) {
        $listing = Invoke-AwsJson -Arguments @(
            "stepfunctions", "list-executions",
            "--state-machine-arn", $StateMachineArn,
            "--max-results", "10",
            "--no-paginate",
            "--profile", $Profile,
            "--region", $Region,
            "--output", "json"
        )

        Write-Utf8NoBomJson -Value $listing -Path $ListingPath

        foreach ($candidate in @($listing.executions)) {
            $candidateArn = [string]$candidate.executionArn
            if ([string]::IsNullOrWhiteSpace($candidateArn)) {
                continue
            }

            $execution = Invoke-AwsJson -Arguments @(
                "stepfunctions", "describe-execution",
                "--execution-arn", $candidateArn,
                "--profile", $Profile,
                "--region", $Region,
                "--output", "json"
            )

            $inputText = [string](Get-PropertyValue `
                    -InputObject $execution `
                    -Name "input")

            if ([string]::IsNullOrWhiteSpace($inputText)) {
                continue
            }

            try {
                $executionInput = $inputText | ConvertFrom-Json
            }
            catch {
                continue
            }

            $detail = Get-PropertyValue `
                -InputObject $executionInput `
                -Name "detail"
            $candidateIncidentId = [string](Get-PropertyValue `
                    -InputObject $detail `
                    -Name "id")

            if ($candidateIncidentId -eq $IncidentId) {
                return $execution
            }
        }

        if ($attempt -lt 30) {
            Start-Sleep -Seconds 2
        }
    }

    return $null
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$infraDirectory = Join-Path $projectRoot "infra"
$eventTemplatePath = Join-Path $projectRoot "events\guardduty-crypto-ec2.json"
$exitCode = 0

Write-Host ""
Write-Host "AWS Cloud IR Automation Lab"
Write-Host "EventBridge Safe Ingestion Validation"
Write-Host "Profile: $Profile"
Write-Host "Region:  $Region"
Write-Host "Mode:    safe-skip"
Write-Host ""

try {
    Assert-Test `
        -Condition ($null -ne (Get-Command aws -ErrorAction SilentlyContinue)) `
        -Name "AWS CLI available" `
        -Detail "aws-command-found"

    Assert-Test `
        -Condition ($null -ne (Get-Command terraform -ErrorAction SilentlyContinue)) `
        -Name "Terraform available" `
        -Detail "terraform-command-found"

    Assert-Test `
        -Condition (Test-Path -LiteralPath $eventTemplatePath -PathType Leaf) `
        -Name "Synthetic event template exists" `
        -Detail $eventTemplatePath

    $env:AWS_PROFILE = $Profile
    $env:AWS_REGION = $Region
    $env:AWS_DEFAULT_REGION = $Region
    $env:AWS_SDK_LOAD_CONFIG = "1"
    $env:AWS_EC2_METADATA_DISABLED = "true"

    $identity = Invoke-AwsJson -Arguments @(
        "sts", "get-caller-identity",
        "--profile", $Profile,
        "--output", "json"
    )
    $accountId = [string]$identity.Account

    Assert-Test `
        -Condition (-not [string]::IsNullOrWhiteSpace($accountId)) `
        -Name "AWS identity available" `
        -Detail "account-resolved"

    $eventBusName = Invoke-TerraformOutput `
        -InfraDirectory $infraDirectory `
        -Name "eventbridge_bus_name"
    $eventRuleName = Invoke-TerraformOutput `
        -InfraDirectory $infraDirectory `
        -Name "eventbridge_rule_name"
    $eventBridgeDlqUrl = Invoke-TerraformOutput `
        -InfraDirectory $infraDirectory `
        -Name "eventbridge_dlq_url"
    $eventBridgeDlqArn = Invoke-TerraformOutput `
        -InfraDirectory $infraDirectory `
        -Name "eventbridge_dlq_arn"
    $stateMachineArn = Invoke-TerraformOutput `
        -InfraDirectory $infraDirectory `
        -Name "orchestration_state_machine_arn"
    $labInstanceId = Invoke-TerraformOutput `
        -InfraDirectory $infraDirectory `
        -Name "lab_instance_id"
    $baselineSecurityGroupId = Invoke-TerraformOutput `
        -InfraDirectory $infraDirectory `
        -Name "baseline_security_group_id"
    $triageFunctionName = Invoke-TerraformOutput `
        -InfraDirectory $infraDirectory `
        -Name "triage_lambda_name"

    $eventBus = Invoke-AwsJson -Arguments @(
        "events", "describe-event-bus",
        "--name", $eventBusName,
        "--profile", $Profile,
        "--region", $Region,
        "--output", "json"
    )

    Assert-Test `
        -Condition ($eventBus.Name -eq $eventBusName) `
        -Name "Custom event bus exists" `
        -Detail "Name=$eventBusName"

    $eventRule = Invoke-AwsJson -Arguments @(
        "events", "describe-rule",
        "--name", $eventRuleName,
        "--event-bus-name", $eventBusName,
        "--profile", $Profile,
        "--region", $Region,
        "--output", "json"
    )

    Assert-Test `
        -Condition ($eventRule.State -eq "ENABLED") `
        -Name "EventBridge rule state" `
        -Detail "State=$($eventRule.State)"

    $eventPattern = $eventRule.EventPattern | ConvertFrom-Json
    $patternSources = @($eventPattern.source)
    $patternDetailTypes = @(
        Get-PropertyValue `
            -InputObject $eventPattern `
            -Name "detail-type"
    )
    $patternResourceTypes = @(
        $eventPattern.detail.resource.resourceType
    )

    Assert-Test `
        -Condition (
            $patternSources.Count -eq 1 -and
            $patternSources[0] -eq "cloud-ir-lab.guardduty" -and
            $patternDetailTypes.Count -eq 1 -and
            $patternDetailTypes[0] -eq "GuardDuty Finding" -and
            $patternResourceTypes.Count -eq 1 -and
            $patternResourceTypes[0] -eq "Instance"
        ) `
        -Name "EventBridge rule is fail-closed" `
        -Detail "source, detail-type and resource-type constrained"

    $targetResponse = Invoke-AwsJson -Arguments @(
        "events", "list-targets-by-rule",
        "--rule", $eventRuleName,
        "--event-bus-name", $eventBusName,
        "--profile", $Profile,
        "--region", $Region,
        "--output", "json"
    )
    $targets = @($targetResponse.Targets)

    Assert-Test `
        -Condition ($targets.Count -eq 1) `
        -Name "EventBridge rule has one target" `
        -Detail "TargetCount=$($targets.Count)"

    $target = $targets[0]

    Assert-Test `
        -Condition ($target.Arn -eq $stateMachineArn) `
        -Name "EventBridge target is the IR workflow" `
        -Detail "state-machine-target-confirmed"

    Assert-Test `
        -Condition (
            -not [string]::IsNullOrWhiteSpace([string]$target.RoleArn)
        ) `
        -Name "EventBridge target role exists" `
        -Detail "role-present"

    Assert-Test `
        -Condition ($target.DeadLetterConfig.Arn -eq $eventBridgeDlqArn) `
        -Name "EventBridge target DLQ" `
        -Detail "dlq-target-confirmed"

    $triageConfiguration = Invoke-AwsJson -Arguments @(
        "lambda", "get-function-configuration",
        "--function-name", $triageFunctionName,
        "--profile", $Profile,
        "--region", $Region,
        "--output", "json"
    )
    $minimumSeverity = [double]$triageConfiguration.Environment.Variables.MIN_SEVERITY

    Assert-Test `
        -Condition ($minimumSeverity -gt 0 -and $minimumSeverity -le 10) `
        -Name "Triage threshold supports safe EventBridge test" `
        -Detail "MinimumSeverity=$minimumSeverity"

    $testSeverity = [Math]::Max(0, $minimumSeverity - 1)

    $initialInstance = Get-LabInstance -InstanceId $labInstanceId
    $initialTags = Get-TagMap -Instance $initialInstance
    $initialSecurityGroupIds = @(
        $initialInstance.SecurityGroups |
            ForEach-Object { [string]$_.GroupId }
    )

    Assert-Test `
        -Condition ($initialTags["IncidentStatus"] -eq "clean") `
        -Name "Target starts clean" `
        -Detail "IncidentStatus=$($initialTags['IncidentStatus'])"

    Assert-Test `
        -Condition (
            $initialSecurityGroupIds.Count -eq 1 -and
            $initialSecurityGroupIds[0] -eq $baselineSecurityGroupId
        ) `
        -Name "Target starts with baseline security group" `
        -Detail "SecurityGroups=$($initialSecurityGroupIds -join ',')"

    $initialDlq = Get-DlqAttributes -QueueUrl $eventBridgeDlqUrl
    $initialDlqMessages = [int]$initialDlq.Attributes.ApproximateNumberOfMessages

    Assert-Test `
        -Condition ($initialDlqMessages -eq 0) `
        -Name "EventBridge DLQ starts empty" `
        -Detail "Messages=$initialDlqMessages"

    $script:TemporaryDirectory = Join-Path (
        [System.IO.Path]::GetTempPath()
    ) ("cloud-ir-eventbridge-" + [guid]::NewGuid().ToString("N"))
    $null = New-Item `
        -ItemType Directory `
        -Path $script:TemporaryDirectory `
        -Force

    $eventPath = Join-Path $script:TemporaryDirectory "matched-event.json"
    $nonMatchingEventPath = Join-Path $script:TemporaryDirectory "non-matching-event.json"
    $eventPatternPath = Join-Path $script:TemporaryDirectory "event-pattern.json"
    $matchedPatternPath = Join-Path $script:TemporaryDirectory "matched-pattern-result.json"
    $nonMatchedPatternPath = Join-Path $script:TemporaryDirectory "non-matching-pattern-result.json"
    $entriesPath = Join-Path $script:TemporaryDirectory "put-events-entries.json"
    $putEventsResponsePath = Join-Path $script:TemporaryDirectory "put-events-response.json"
    $executionListingPath = Join-Path $script:TemporaryDirectory "list-executions.json"
    $executionPath = Join-Path $script:TemporaryDirectory "describe-execution.json"
    $executionHistoryPath = Join-Path $script:TemporaryDirectory "execution-history.json"
    $finalInstancePath = Join-Path $script:TemporaryDirectory "final-instance.json"
    $finalDlqPath = Join-Path $script:TemporaryDirectory "final-dlq-attributes.json"

    $incidentId = (
        "eventbridge-skip-" +
        [DateTimeOffset]::UtcNow.ToString("yyyyMMddTHHmmssfffZ") +
        "-" +
        [guid]::NewGuid().ToString("N").Substring(0, 8)
    )
    $eventTime = [DateTimeOffset]::UtcNow.ToString(
        "yyyy-MM-dd'T'HH:mm:ss'Z'",
        [System.Globalization.CultureInfo]::InvariantCulture
    )

    $event = Get-Content `
        -LiteralPath $eventTemplatePath `
        -Raw |
        ConvertFrom-Json

    $event.id = "test-$incidentId"
    $event.source = "cloud-ir-lab.guardduty"
    $event.'detail-type' = "GuardDuty Finding"
    $event.account = $accountId
    $event.region = $Region
    $event.time = $eventTime
    $event.detail.accountId = $accountId
    $event.detail.region = $Region
    $event.detail.id = $incidentId
    $event.detail.severity = $testSeverity
    $event.detail.resource.resourceType = "Instance"
    $event.detail.resource.instanceDetails.instanceId = $labInstanceId
    $event.detail.createdAt = $eventTime
    $event.detail.updatedAt = $eventTime

    Write-Utf8NoBomJson -Value $eventPattern -Path $eventPatternPath
    Write-Utf8NoBomJson -Value $event -Path $eventPath

    $nonMatchingEvent = (
        $event |
            ConvertTo-Json -Depth 50 |
            ConvertFrom-Json
    )
    $nonMatchingEvent.detail.resource.resourceType = "S3Bucket"
    Write-Utf8NoBomJson `
        -Value $nonMatchingEvent `
        -Path $nonMatchingEventPath

    $matchingResult = Invoke-AwsJson -Arguments @(
        "events", "test-event-pattern",
        "--event-pattern", "file://$eventPatternPath",
        "--event", "file://$eventPath",
        "--profile", $Profile,
        "--region", $Region,
        "--output", "json"
    )
    Write-Utf8NoBomJson -Value $matchingResult -Path $matchedPatternPath

    Assert-Test `
        -Condition ($matchingResult.Result -eq $true) `
        -Name "Synthetic EC2 finding matches the rule" `
        -Detail "Result=True"

    $nonMatchingResult = Invoke-AwsJson -Arguments @(
        "events", "test-event-pattern",
        "--event-pattern", "file://$eventPatternPath",
        "--event", "file://$nonMatchingEventPath",
        "--profile", $Profile,
        "--region", $Region,
        "--output", "json"
    )
    Write-Utf8NoBomJson `
        -Value $nonMatchingResult `
        -Path $nonMatchedPatternPath

    Assert-Test `
        -Condition ($nonMatchingResult.Result -eq $false) `
        -Name "Non-EC2 finding does not match the rule" `
        -Detail "Result=False"

    $detailJson = $event.detail | ConvertTo-Json -Depth 50 -Compress
    $entries = @(
        @{
            Source       = "cloud-ir-lab.guardduty"
            DetailType   = "GuardDuty Finding"
            Detail       = $detailJson
            EventBusName = $eventBusName
        }
    )
    Write-Utf8NoBomJson -Value $entries -Path $entriesPath

    Write-Host ""
    Write-Host "Incident: $incidentId"
    Write-Host "Publishing one low-severity event to the isolated event bus."
    Write-Host "Severity: $testSeverity"
    Write-Host ""

    $putEventsResponse = Invoke-AwsJson -Arguments @(
        "events", "put-events",
        "--entries", "file://$entriesPath",
        "--profile", $Profile,
        "--region", $Region,
        "--output", "json"
    )
    Write-Utf8NoBomJson `
        -Value $putEventsResponse `
        -Path $putEventsResponsePath

    Assert-Test `
        -Condition ([int]$putEventsResponse.FailedEntryCount -eq 0) `
        -Name "EventBridge accepted the custom event" `
        -Detail "FailedEntryCount=$($putEventsResponse.FailedEntryCount)"

    $putEventResults = @($putEventsResponse.Entries)
    $eventId = if ($putEventResults.Count -eq 1) {
        [string]$putEventResults[0].EventId
    }
    else {
        ""
    }

    Assert-Test `
        -Condition (-not [string]::IsNullOrWhiteSpace($eventId)) `
        -Name "EventBridge returned an event identifier" `
        -Detail "event-id-present"

    $execution = Find-ExecutionByIncident `
        -StateMachineArn $stateMachineArn `
        -IncidentId $incidentId `
        -ListingPath $executionListingPath

    Assert-Test `
        -Condition ($null -ne $execution) `
        -Name "EventBridge started the IR workflow" `
        -Detail "correlated-execution-found"

    $executionArn = [string]$execution.executionArn

    for ($attempt = 1; $attempt -le 30; $attempt++) {
        $execution = Invoke-AwsJson -Arguments @(
            "stepfunctions", "describe-execution",
            "--execution-arn", $executionArn,
            "--profile", $Profile,
            "--region", $Region,
            "--output", "json"
        )

        if ($execution.status -ne "RUNNING") {
            break
        }

        if ($attempt -lt 30) {
            Start-Sleep -Seconds 2
        }
    }

    Write-Utf8NoBomJson -Value $execution -Path $executionPath

    $executionError = [string](Get-PropertyValue `
            -InputObject $execution `
            -Name "error")
    $executionCause = [string](Get-PropertyValue `
            -InputObject $execution `
            -Name "cause")

    $errorDetail = if ([string]::IsNullOrWhiteSpace($executionError)) {
        "absent"
    }
    else {
        $executionError
    }
    $causeDetail = if ([string]::IsNullOrWhiteSpace($executionCause)) {
        "absent"
    }
    else {
        $executionCause
    }

    Assert-Test `
        -Condition ($execution.status -eq "SUCCEEDED") `
        -Name "Event-driven workflow execution status" `
        -Detail "Status=$($execution.status); Error=$errorDetail; Cause=$causeDetail"

    $executionInputText = [string](Get-PropertyValue `
            -InputObject $execution `
            -Name "input")
    $executionInput = $executionInputText | ConvertFrom-Json

    Assert-Test `
        -Condition ($executionInput.detail.id -eq $incidentId) `
        -Name "Workflow input preserves incident identifier" `
        -Detail "IncidentId=$incidentId"

    Assert-Test `
        -Condition ($executionInput.source -eq "cloud-ir-lab.guardduty") `
        -Name "Workflow input preserves synthetic source" `
        -Detail "Source=$($executionInput.source)"

    $executionDetailType = [string](Get-PropertyValue `
            -InputObject $executionInput `
            -Name "detail-type")

    Assert-Test `
        -Condition ($executionDetailType -eq "GuardDuty Finding") `
        -Name "Workflow input preserves detail type" `
        -Detail "DetailType=$executionDetailType"

    Assert-Test `
        -Condition ([double]$executionInput.detail.severity -eq $testSeverity) `
        -Name "Workflow input preserves test severity" `
        -Detail "Severity=$($executionInput.detail.severity)"

    $executionOutputText = [string](Get-PropertyValue `
            -InputObject $execution `
            -Name "output")

    Assert-Test `
        -Condition (-not [string]::IsNullOrWhiteSpace($executionOutputText)) `
        -Name "Event-driven workflow output" `
        -Detail "output-present"

    $workflowResult = $executionOutputText | ConvertFrom-Json

    Assert-Test `
        -Condition ($workflowResult.incident_id -eq $incidentId) `
        -Name "Workflow output preserves incident identifier" `
        -Detail "IncidentId=$incidentId"

    Assert-Test `
        -Condition ($workflowResult.decision.containment_eligible -eq $false) `
        -Name "Low severity event is not eligible" `
        -Detail "Eligible=False"

    $decisionReasons = @($workflowResult.decision.reasons)

    Assert-Test `
        -Condition ($decisionReasons -contains "severity_below_threshold") `
        -Name "Triage records safe skip reason" `
        -Detail "Reason=severity_below_threshold"

    Assert-Test `
        -Condition ($workflowResult.workflow.status -eq "skipped") `
        -Name "Event-driven workflow follows skip branch" `
        -Detail "Status=$($workflowResult.workflow.status)"

    Assert-Test `
        -Condition ($workflowResult.workflow.changed -eq $false) `
        -Name "Event-driven skip does not change resources" `
        -Detail "Changed=False"

    Assert-Test `
        -Condition ($workflowResult.workflow.idempotent -eq $true) `
        -Name "Event-driven skip result is idempotent" `
        -Detail "Idempotent=True"

    $executionHistory = Invoke-AwsJson -Arguments @(
        "stepfunctions", "get-execution-history",
        "--execution-arn", $executionArn,
        "--no-paginate",
        "--no-include-execution-data",
        "--profile", $Profile,
        "--region", $Region,
        "--output", "json"
    )
    Write-Utf8NoBomJson `
        -Value $executionHistory `
        -Path $executionHistoryPath

    $enteredTaskNames = @(
        $executionHistory.events |
            Where-Object { $_.type -eq "TaskStateEntered" } |
            ForEach-Object { [string]$_.stateEnteredEventDetails.name }
    )

    Assert-Test `
        -Condition ($enteredTaskNames -contains "TriageFinding") `
        -Name "Execution history contains triage task" `
        -Detail "TriageFinding=entered"

    Assert-Test `
        -Condition ($enteredTaskNames -notcontains "ContainTarget") `
        -Name "Execution history excludes containment task" `
        -Detail "ContainTarget=not-entered"

    $finalInstance = Get-LabInstance -InstanceId $labInstanceId
    Write-Utf8NoBomJson -Value $finalInstance -Path $finalInstancePath
    $finalTags = Get-TagMap -Instance $finalInstance
    $finalSecurityGroupIds = @(
        $finalInstance.SecurityGroups |
            ForEach-Object { [string]$_.GroupId }
    )

    Assert-Test `
        -Condition ($finalTags["IncidentStatus"] -eq "clean") `
        -Name "Event-driven skip preserves clean incident status" `
        -Detail "IncidentStatus=$($finalTags['IncidentStatus'])"

    Assert-Test `
        -Condition (
            $finalSecurityGroupIds.Count -eq 1 -and
            $finalSecurityGroupIds[0] -eq $baselineSecurityGroupId
        ) `
        -Name "Event-driven skip preserves baseline security group" `
        -Detail "SecurityGroups=$($finalSecurityGroupIds -join ',')"

    $finalDlq = Get-DlqAttributes -QueueUrl $eventBridgeDlqUrl
    Write-Utf8NoBomJson -Value $finalDlq -Path $finalDlqPath
    $finalDlqMessages = [int]$finalDlq.Attributes.ApproximateNumberOfMessages

    Assert-Test `
        -Condition ($finalDlqMessages -eq 0) `
        -Name "EventBridge DLQ remains empty" `
        -Detail "Messages=$finalDlqMessages"

    Write-Host ""
    Write-Host "Event-driven evidence"
    Write-Host "Incident ID:  $incidentId"
    Write-Host "Event ID:     $eventId"
    Write-Host "Execution:    $($execution.name)"
    Write-Host "Result:       skipped"
    Write-Host "Target state: clean"

    $script:Succeeded = $true
}
catch {
    $script:Failed++
    $exitCode = 1

    Write-Host ""
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    if ($null -ne $script:TemporaryDirectory) {
        if ($script:Succeeded) {
            Write-Host "Evidence artifacts: $script:TemporaryDirectory" -ForegroundColor Yellow
        }
        else {
            Write-Host "Diagnostic artifacts: $script:TemporaryDirectory" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "Validation summary"
    Write-Host "Passed: $($script:Passed)"
    Write-Host "Failed: $($script:Failed)"
}

exit $exitCode
