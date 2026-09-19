[CmdletBinding()]
param(
    [string]$Profile = "cloud-ir-lab",
    [string]$Region = "us-east-1",
    [switch]$ExecuteContainment
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:Passed = 0
$script:Failed = 0
$script:TemporaryDirectory = $null
$script:Succeeded = $false
$script:LabInstanceId = $null
$script:BaselineSecurityGroupId = $null
$script:RecoveryArmed = $false
$script:ExecutionArn = $null

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

function Invoke-AwsCommand {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    $null = & aws @Arguments
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        throw "AWS CLI failed with exit code ${exitCode}: aws $($Arguments -join ' ')"
    }
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

    $json = $Value | ConvertTo-Json -Depth 50
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json, $utf8NoBom)
}

function Convert-HexToBase64 {
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[0-9a-fA-F]{64}$')]
        [string]$Hex
    )

    $bytes = New-Object byte[] 32
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [Convert]::ToByte(
            $Hex.Substring($index * 2, 2),
            16
        )
    }

    return [Convert]::ToBase64String($bytes)
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

function Get-IncidentItem {
    param(
        [Parameter(Mandatory)]
        [string]$TableName,

        [Parameter(Mandatory)]
        [string]$IncidentId,

        [Parameter(Mandatory)]
        [string]$KeyPath
    )

    $key = @{
        incident_id = @{
            S = $IncidentId
        }
    }
    Write-Utf8NoBomJson -Value $key -Path $KeyPath

    $response = Invoke-AwsJson -Arguments @(
        "dynamodb", "get-item",
        "--table-name", $TableName,
        "--key", "file://$KeyPath",
        "--consistent-read",
        "--profile", $Profile,
        "--region", $Region,
        "--output", "json"
    )

    $itemProperty = $response.PSObject.Properties["Item"]
    if ($null -eq $itemProperty -or $null -eq $itemProperty.Value) {
        throw "Incident '$IncidentId' was not found in DynamoDB."
    }

    return $itemProperty.Value
}

function Get-ContainmentLogEvent {
    param(
        [Parameter(Mandatory)]
        [string]$LogGroupName,

        [Parameter(Mandatory)]
        [long]$StartTimeMilliseconds,

        [Parameter(Mandatory)]
        [string]$IncidentId,

        [Parameter(Mandatory)]
        [string]$QueryResponsePath
    )

    for ($attempt = 1; $attempt -le 20; $attempt++) {
        $response = Invoke-AwsJson -Arguments @(
            "logs", "filter-log-events",
            "--log-group-name", $LogGroupName,
            "--start-time", ([string]$StartTimeMilliseconds),
            "--profile", $Profile,
            "--region", $Region,
            "--output", "json"
        )

        Write-Utf8NoBomJson `
            -Value $response `
            -Path $QueryResponsePath

        $matchingEvents = @(
            $response.events |
                Where-Object {
                    [string]$_.message -match '"event"\s*:\s*"containment_complete"' -and
                    [string]$_.message -match [regex]::Escape($IncidentId)
                }
        )

        if ($matchingEvents.Count -gt 0) {
            return $matchingEvents[0]
        }

        if ($attempt -lt 20) {
            Start-Sleep -Seconds 3
        }
    }

    return $null
}

function Restore-LabTarget {
    param(
        [Parameter(Mandatory)]
        [string]$InstanceId,

        [Parameter(Mandatory)]
        [string]$BaselineSecurityGroupId
    )

    Invoke-AwsCommand -Arguments @(
        "ec2", "modify-instance-attribute",
        "--instance-id", $InstanceId,
        "--groups", $BaselineSecurityGroupId,
        "--profile", $Profile,
        "--region", $Region
    )

    Invoke-AwsCommand -Arguments @(
        "ec2", "create-tags",
        "--resources", $InstanceId,
        "--tags", "Key=IncidentStatus,Value=clean",
        "--profile", $Profile,
        "--region", $Region
    )

    for ($attempt = 1; $attempt -le 15; $attempt++) {
        $instance = Get-LabInstance -InstanceId $InstanceId
        $tags = Get-TagMap -Instance $instance
        $securityGroupIds = @(
            $instance.SecurityGroups |
                ForEach-Object { [string]$_.GroupId }
        )

        if (
            $securityGroupIds.Count -eq 1 -and
            $securityGroupIds[0] -eq $BaselineSecurityGroupId -and
            $tags["IncidentStatus"] -eq "clean"
        ) {
            return $instance
        }

        if ($attempt -lt 15) {
            Start-Sleep -Seconds 2
        }
    }

    throw "Automatic recovery could not confirm the baseline target state."
}

function Stop-ExecutionIfRunning {
    param(
        [Parameter(Mandatory)]
        [string]$ExecutionArn
    )

    $execution = Invoke-AwsJson -Arguments @(
        "stepfunctions", "describe-execution",
        "--execution-arn", $ExecutionArn,
        "--profile", $Profile,
        "--region", $Region,
        "--output", "json"
    )

    if ($execution.status -ne "RUNNING") {
        return
    }

    try {
        Invoke-AwsCommand -Arguments @(
            "stepfunctions", "stop-execution",
            "--execution-arn", $ExecutionArn,
            "--error", "ValidationRecovery",
            "--cause", "The local validation script is entering automatic recovery.",
            "--profile", $Profile,
            "--region", $Region
        )
    }
    catch {
        $execution = Invoke-AwsJson -Arguments @(
            "stepfunctions", "describe-execution",
            "--execution-arn", $ExecutionArn,
            "--profile", $Profile,
            "--region", $Region,
            "--output", "json"
        )

        if ($execution.status -eq "RUNNING") {
            throw
        }

        return
    }

    for ($attempt = 1; $attempt -le 30; $attempt++) {
        $execution = Invoke-AwsJson -Arguments @(
            "stepfunctions", "describe-execution",
            "--execution-arn", $ExecutionArn,
            "--profile", $Profile,
            "--region", $Region,
            "--output", "json"
        )

        if ($execution.status -ne "RUNNING") {
            return
        }

        if ($attempt -lt 30) {
            Start-Sleep -Seconds 2
        }
    }

    throw "The workflow is still running; automatic EC2 recovery was not attempted."
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$infraDirectory = Join-Path $projectRoot "infra"
$eventTemplatePath = Join-Path $projectRoot "events\guardduty-crypto-ec2.json"
$testStartMilliseconds = [DateTimeOffset]::UtcNow.
    AddMinutes(-5).
    ToUnixTimeMilliseconds()
$exitCode = 0

Write-Host ""
Write-Host "AWS Cloud IR Automation Lab"
Write-Host "Step Functions Orchestration Validation"
Write-Host "Profile: $Profile"
Write-Host "Region:  $Region"
Write-Host "Mode:    $(if ($ExecuteContainment) { 'authorized-containment' } else { 'safe-skip' })"
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

    $script:LabInstanceId = $labInstanceId
    $script:BaselineSecurityGroupId = $baselineSecurityGroupId

    if ($ExecuteContainment) {
        $quarantineSecurityGroupId = Invoke-TerraformOutput `
            -InfraDirectory $infraDirectory `
            -Name "quarantine_security_group_id"
        $incidentsTableName = Invoke-TerraformOutput `
            -InfraDirectory $infraDirectory `
            -Name "incidents_table_name"
        $containmentLogGroupName = Invoke-TerraformOutput `
            -InfraDirectory $infraDirectory `
            -Name "containment_log_group_name"
        $evidenceBucketName = Invoke-TerraformOutput `
            -InfraDirectory $infraDirectory `
            -Name "evidence_bucket_name"
    }

    $stateMachine = Invoke-AwsJson -Arguments @(
        "stepfunctions", "describe-state-machine",
        "--state-machine-arn", $stateMachineArn,
        "--profile", $Profile,
        "--region", $Region,
        "--output", "json"
    )

    Assert-Test `
        -Condition ($stateMachine.status -eq "ACTIVE") `
        -Name "State machine status" `
        -Detail "Status=$($stateMachine.status)"

    Assert-Test `
        -Condition ($stateMachine.type -eq "STANDARD") `
        -Name "State machine workflow type" `
        -Detail "Type=$($stateMachine.type)"

    Assert-Test `
        -Condition (-not [string]::IsNullOrWhiteSpace([string]$stateMachine.roleArn)) `
        -Name "State machine execution role" `
        -Detail "role-present"

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
        -Name "Triage threshold supports orchestration test" `
        -Detail "MinimumSeverity=$minimumSeverity"

    $testSeverity = if ($ExecuteContainment) {
        [Math]::Min(10, $minimumSeverity + 1)
    }
    else {
        [Math]::Max(0, $minimumSeverity - 1)
    }

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

    if ($ExecuteContainment) {
        $initialNetworkInterfaceIds = @(
            $initialInstance.NetworkInterfaces |
                ForEach-Object { [string]$_.NetworkInterfaceId }
        )

        Assert-Test `
            -Condition (@("running", "stopped") -contains [string]$initialInstance.State.Name) `
            -Name "Target instance state is supported" `
            -Detail "State=$($initialInstance.State.Name)"

        Assert-Test `
            -Condition ($initialTags["AutoContainment"] -eq "true") `
            -Name "Target authorizes auto-containment" `
            -Detail "AutoContainment=$($initialTags['AutoContainment'])"

        Assert-Test `
            -Condition ($initialTags["DataClassification"] -eq "synthetic") `
            -Name "Target contains only synthetic data" `
            -Detail "DataClassification=$($initialTags['DataClassification'])"

        Assert-Test `
            -Condition ($initialNetworkInterfaceIds.Count -eq 1) `
            -Name "Target has one network interface" `
            -Detail "NetworkInterfaces=$($initialNetworkInterfaceIds.Count)"

        $quarantineRules = Invoke-AwsJson -Arguments @(
            "ec2", "describe-security-group-rules",
            "--filters", "Name=group-id,Values=$quarantineSecurityGroupId",
            "--profile", $Profile,
            "--region", $Region,
            "--query", "SecurityGroupRules",
            "--output", "json"
        )
        $quarantineRuleList = @($quarantineRules)

        Assert-Test `
            -Condition ($quarantineRuleList.Count -eq 0) `
            -Name "Quarantine security group blocks all traffic" `
            -Detail "rules=0"
    }

    $script:TemporaryDirectory = Join-Path (
        [System.IO.Path]::GetTempPath()
    ) ("cloud-ir-orchestration-" + [guid]::NewGuid().ToString("N"))
    $null = New-Item `
        -ItemType Directory `
        -Path $script:TemporaryDirectory `
        -Force

    $eventPath = Join-Path $script:TemporaryDirectory "guardduty-event.json"
    $executionPath = Join-Path $script:TemporaryDirectory "describe-execution.json"
    $executionHistoryPath = Join-Path $script:TemporaryDirectory "execution-history.json"
    $dynamoKeyPath = Join-Path $script:TemporaryDirectory "dynamodb-key.json"
    $dynamoItemPath = Join-Path $script:TemporaryDirectory "dynamodb-item.json"
    $cloudWatchQueryPath = Join-Path $script:TemporaryDirectory "cloudwatch-query.json"
    $containmentLogPath = Join-Path $script:TemporaryDirectory "containment-log-event.json"
    $evidenceObjectPath = Join-Path $script:TemporaryDirectory "pre-containment-evidence.json"
    $incidentPrefix = if ($ExecuteContainment) {
        "orchestration-containment-"
    }
    else {
        "orchestration-skip-"
    }
    $incidentId = (
        $incidentPrefix +
        [DateTimeOffset]::UtcNow.ToString("yyyyMMddTHHmmssfffZ") +
        "-" +
        [guid]::NewGuid().ToString("N").Substring(0, 8)
    )
    $eventTime = [DateTimeOffset]::UtcNow.ToString("o")

    $event = Get-Content -LiteralPath $eventTemplatePath -Raw | ConvertFrom-Json
    $event.id = "event-$incidentId"
    $event.account = $accountId
    $event.region = $Region
    $event.time = $eventTime
    $event.detail.accountId = $accountId
    $event.detail.region = $Region
    $event.detail.id = $incidentId
    $event.detail.severity = $testSeverity
    $event.detail.resource.instanceDetails.instanceId = $labInstanceId
    $event.detail.createdAt = $eventTime
    $event.detail.updatedAt = $eventTime

    Write-Utf8NoBomJson -Value $event -Path $eventPath

    Write-Host ""
    Write-Host "Execution: $incidentId"
    if ($ExecuteContainment) {
        Write-Host "Using severity $testSeverity to execute authorized synthetic containment." -ForegroundColor Yellow
    }
    else {
        Write-Host "Using severity $testSeverity to validate the non-containment branch."
    }
    Write-Host ""

    if ($ExecuteContainment) {
        $script:RecoveryArmed = $true
    }

    $executionStart = Invoke-AwsJson -Arguments @(
        "stepfunctions", "start-execution",
        "--state-machine-arn", $stateMachineArn,
        "--name", $incidentId,
        "--input", "file://$eventPath",
        "--profile", $Profile,
        "--region", $Region,
        "--output", "json"
    )
    $executionArn = [string]$executionStart.executionArn
    $script:ExecutionArn = $executionArn

    Assert-Test `
        -Condition (-not [string]::IsNullOrWhiteSpace($executionArn)) `
        -Name "Workflow execution started" `
        -Detail "execution-arn-present"

    $execution = $null
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

    $executionErrorProperty = $execution.PSObject.Properties["error"]
    $executionCauseProperty = $execution.PSObject.Properties["cause"]
    $executionError = if ($null -eq $executionErrorProperty) {
        "absent"
    }
    else {
        [string]$executionErrorProperty.Value
    }
    $executionCause = if ($null -eq $executionCauseProperty) {
        "absent"
    }
    else {
        [string]$executionCauseProperty.Value
    }

    Assert-Test `
        -Condition ($execution.status -eq "SUCCEEDED") `
        -Name "Workflow execution status" `
        -Detail "Status=$($execution.status); Error=$executionError; Cause=$executionCause"

    $executionOutput = [string]$execution.output

    Assert-Test `
        -Condition (-not [string]::IsNullOrWhiteSpace($executionOutput)) `
        -Name "Workflow execution output" `
        -Detail "output-present"

    $workflowResult = $executionOutput | ConvertFrom-Json

    Assert-Test `
        -Condition ($workflowResult.incident_id -eq $incidentId) `
        -Name "Workflow preserves incident identifier" `
        -Detail "IncidentId=$incidentId"

    if ($ExecuteContainment) {
        Assert-Test `
            -Condition ($workflowResult.status -eq "contained") `
            -Name "Workflow containment status" `
            -Detail "Status=$($workflowResult.status)"

        Assert-Test `
            -Condition ($workflowResult.changed -eq $true) `
            -Name "Workflow containment changes the target" `
            -Detail "Changed=True"

        Assert-Test `
            -Condition ($workflowResult.idempotent -eq $false) `
            -Name "First workflow containment is not a duplicate" `
            -Detail "Idempotent=False"

        Assert-Test `
            -Condition ($workflowResult.notification_status -eq "published") `
            -Name "Workflow containment notification published" `
            -Detail "NotificationStatus=published"

        $expectedEvidenceKey = "incidents/$incidentId/pre-containment.json"
        $evidenceReference = $workflowResult.evidence

        Assert-Test `
            -Condition (
                $evidenceReference.bucket -eq $evidenceBucketName -and
                $evidenceReference.key -eq $expectedEvidenceKey
            ) `
            -Name "Workflow evidence location" `
            -Detail "Key=$expectedEvidenceKey"

        Assert-Test `
            -Condition (
                $evidenceReference.status -eq "created" -and
                -not [string]::IsNullOrWhiteSpace(
                    [string]$evidenceReference.version_id
                )
            ) `
            -Name "Workflow immutable evidence version" `
            -Detail "Status=created; VersionId=present"

        Assert-Test `
            -Condition (
                [string]$evidenceReference.sha256 -match
                '^[0-9a-f]{64}$'
            ) `
            -Name "Workflow evidence SHA-256 reference" `
            -Detail "Sha256=present"

        Assert-Test `
            -Condition (
                @($workflowResult.security_group_ids_before).Count -eq 1 -and
                @($workflowResult.security_group_ids_before)[0] -eq $baselineSecurityGroupId
            ) `
            -Name "Workflow records baseline security group" `
            -Detail "Before=$baselineSecurityGroupId"

        Assert-Test `
            -Condition (
                @($workflowResult.security_group_ids_after).Count -eq 1 -and
                @($workflowResult.security_group_ids_after)[0] -eq $quarantineSecurityGroupId
            ) `
            -Name "Workflow records quarantine security group" `
            -Detail "After=$quarantineSecurityGroupId"
    }
    else {
        Assert-Test `
            -Condition ($workflowResult.decision.containment_eligible -eq $false) `
            -Name "Low severity finding is not eligible" `
            -Detail "Eligible=False"

        $decisionReasons = @($workflowResult.decision.reasons)
        Assert-Test `
            -Condition ($decisionReasons -contains "severity_below_threshold") `
            -Name "Triage records skip reason" `
            -Detail "Reason=severity_below_threshold"

        Assert-Test `
            -Condition ($workflowResult.workflow.status -eq "skipped") `
            -Name "Workflow follows non-containment branch" `
            -Detail "Status=$($workflowResult.workflow.status)"

        Assert-Test `
            -Condition ($workflowResult.workflow.changed -eq $false) `
            -Name "Skip branch does not change resources" `
            -Detail "Changed=False"

        Assert-Test `
            -Condition ($workflowResult.workflow.idempotent -eq $true) `
            -Name "Skip branch is idempotent" `
            -Detail "Idempotent=True"
    }

    $executionHistory = Invoke-AwsJson -Arguments @(
        "stepfunctions", "get-execution-history",
        "--execution-arn", $executionArn,
        "--no-paginate",
        "--no-include-execution-data",
        "--profile", $Profile,
        "--region", $Region,
        "--output", "json"
    )

    $enteredTaskNames = @(
        $executionHistory.events |
            Where-Object { $_.type -eq "TaskStateEntered" } |
            ForEach-Object { [string]$_.stateEnteredEventDetails.name }
    )

    Assert-Test `
        -Condition ($enteredTaskNames -contains "TriageFinding") `
        -Name "Execution history contains triage task" `
        -Detail "TriageFinding=entered"

    if ($ExecuteContainment) {
        $enteredChoiceNames = @(
            $executionHistory.events |
                Where-Object { $_.type -eq "ChoiceStateEntered" } |
                ForEach-Object { [string]$_.stateEnteredEventDetails.name }
        )

        Assert-Test `
            -Condition ($enteredChoiceNames -contains "EvaluateContainmentEligibility") `
            -Name "Execution history contains eligibility choice" `
            -Detail "EvaluateContainmentEligibility=entered"

        Assert-Test `
            -Condition ($enteredTaskNames -contains "ContainTarget") `
            -Name "Execution history contains containment task" `
            -Detail "ContainTarget=entered"
    }
    else {
        Assert-Test `
            -Condition ($enteredTaskNames -notcontains "ContainTarget") `
            -Name "Execution history excludes containment task" `
            -Detail "ContainTarget=not-entered"
    }

    $finalInstance = Get-LabInstance -InstanceId $labInstanceId
    $finalTags = Get-TagMap -Instance $finalInstance
    $finalSecurityGroupIds = @(
        $finalInstance.SecurityGroups |
            ForEach-Object { [string]$_.GroupId }
    )

    if ($ExecuteContainment) {
        Assert-Test `
            -Condition ($finalTags["IncidentStatus"] -eq "contained") `
            -Name "Workflow sets contained incident status" `
            -Detail "IncidentStatus=$($finalTags['IncidentStatus'])"

        Assert-Test `
            -Condition (
                $finalSecurityGroupIds.Count -eq 1 -and
                $finalSecurityGroupIds[0] -eq $quarantineSecurityGroupId
            ) `
            -Name "Workflow applies quarantine security group" `
            -Detail "SecurityGroups=$($finalSecurityGroupIds -join ',')"

        Assert-Test `
            -Condition ($finalInstance.State.Name -eq $initialInstance.State.Name) `
            -Name "Workflow preserves instance power state" `
            -Detail "State=$($finalInstance.State.Name)"

        $incidentItem = Get-IncidentItem `
            -TableName $incidentsTableName `
            -IncidentId $incidentId `
            -KeyPath $dynamoKeyPath

        Assert-Test `
            -Condition ($incidentItem.status.S -eq "contained") `
            -Name "DynamoDB incident status" `
            -Detail "Status=$($incidentItem.status.S)"

        Assert-Test `
            -Condition ($incidentItem.instance_id.S -eq $labInstanceId) `
            -Name "DynamoDB target identifier" `
            -Detail "InstanceId=$labInstanceId"

        Assert-Test `
            -Condition ($incidentItem.containment_changed_resource.BOOL -eq $true) `
            -Name "DynamoDB records resource mutation" `
            -Detail "Changed=True"

        $ledgerGroupsBefore = @(
            $incidentItem.security_group_ids_before.L |
                ForEach-Object { [string]$_.S }
        )
        $ledgerGroupsAfter = @(
            $incidentItem.security_group_ids_after.L |
                ForEach-Object { [string]$_.S }
        )

        Assert-Test `
            -Condition (
                $ledgerGroupsBefore.Count -eq 1 -and
                $ledgerGroupsBefore[0] -eq $baselineSecurityGroupId
            ) `
            -Name "DynamoDB preserves pre-containment state" `
            -Detail "Before=$baselineSecurityGroupId"

        Assert-Test `
            -Condition (
                $ledgerGroupsAfter.Count -eq 1 -and
                $ledgerGroupsAfter[0] -eq $quarantineSecurityGroupId
            ) `
            -Name "DynamoDB preserves post-containment state" `
            -Detail "After=$quarantineSecurityGroupId"

        $expiresAt = [long]$incidentItem.expires_at.N
        $nowEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

        Assert-Test `
            -Condition ($expiresAt -gt $nowEpoch) `
            -Name "DynamoDB incident TTL" `
            -Detail "ExpiresInFuture=True"

        Assert-Test `
            -Condition ($null -eq $incidentItem.PSObject.Properties["lease_until"]) `
            -Name "DynamoDB processing lease released" `
            -Detail "lease_until=absent"

        Assert-Test `
            -Condition (
                $incidentItem.evidence_bucket.S -eq $evidenceBucketName -and
                $incidentItem.evidence_key.S -eq $expectedEvidenceKey
            ) `
            -Name "DynamoDB evidence location" `
            -Detail "BucketAndKey=confirmed"

        Assert-Test `
            -Condition (
                $incidentItem.evidence_sha256.S -eq
                [string]$evidenceReference.sha256 -and
                $incidentItem.evidence_version_id.S -eq
                [string]$evidenceReference.version_id
            ) `
            -Name "DynamoDB evidence integrity reference" `
            -Detail "ChecksumAndVersion=confirmed"

        $evidenceDownload = Invoke-AwsJson -Arguments @(
            "s3api", "get-object",
            "--bucket", $evidenceBucketName,
            "--key", $expectedEvidenceKey,
            "--version-id", ([string]$evidenceReference.version_id),
            "--checksum-mode", "ENABLED",
            "--profile", $Profile,
            "--region", $Region,
            "--output", "json",
            $evidenceObjectPath
        )

        $localEvidenceSha256 = (
            Get-FileHash `
                -LiteralPath $evidenceObjectPath `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        $expectedChecksumSha256 = Convert-HexToBase64 `
            -Hex ([string]$evidenceReference.sha256)

        Assert-Test `
            -Condition (
                $localEvidenceSha256 -eq
                [string]$evidenceReference.sha256 -and
                $evidenceDownload.ChecksumSHA256 -eq
                $expectedChecksumSha256
            ) `
            -Name "Downloaded workflow evidence checksum" `
            -Detail "LocalAndS3Checksums=confirmed"

        Assert-Test `
            -Condition (
                $evidenceDownload.VersionId -eq
                [string]$evidenceReference.version_id -and
                $evidenceDownload.ServerSideEncryption -eq "AES256"
            ) `
            -Name "Workflow evidence version and encryption" `
            -Detail "VersionId=confirmed; SSE=AES256"

        $evidenceDocument = Get-Content `
            -LiteralPath $evidenceObjectPath `
            -Raw |
            ConvertFrom-Json
        $evidenceSecurityGroups = @(
            $evidenceDocument.instance.security_group_ids
        )

        Assert-Test `
            -Condition (
                $evidenceDocument.schema_version -eq "1.0" -and
                $evidenceDocument.evidence_type -eq "pre-containment" -and
                $evidenceDocument.incident.id -eq $incidentId
            ) `
            -Name "Workflow evidence document contract" `
            -Detail "Schema=1.0; Type=pre-containment"

        Assert-Test `
            -Condition (
                $evidenceDocument.resource.instance_id -eq
                $labInstanceId -and
                $evidenceDocument.decision.containment_eligible -eq $true
            ) `
            -Name "Workflow evidence incident decision" `
            -Detail "InstanceAndDecision=confirmed"

        Assert-Test `
            -Condition (
                $evidenceSecurityGroups.Count -eq 1 -and
                $evidenceSecurityGroups[0] -eq
                $baselineSecurityGroupId -and
                $evidenceDocument.instance.tags.IncidentStatus -eq "clean"
            ) `
            -Name "Workflow evidence pre-containment state" `
            -Detail "SecurityGroup=baseline; IncidentStatus=clean"

        Write-Utf8NoBomJson -Value $execution -Path $executionPath
        Write-Utf8NoBomJson -Value $executionHistory -Path $executionHistoryPath
        Write-Utf8NoBomJson -Value $incidentItem -Path $dynamoItemPath

        $containmentLogEvent = Get-ContainmentLogEvent `
            -LogGroupName $containmentLogGroupName `
            -StartTimeMilliseconds $testStartMilliseconds `
            -IncidentId $incidentId `
            -QueryResponsePath $cloudWatchQueryPath

        Assert-Test `
            -Condition ($null -ne $containmentLogEvent) `
            -Name "CloudWatch containment completion event" `
            -Detail "event=containment_complete"

        Write-Utf8NoBomJson -Value $containmentLogEvent -Path $containmentLogPath

        Write-Host ""
        Write-Host "Preserved S3 evidence"
        Write-Host "Object:     s3://$evidenceBucketName/$expectedEvidenceKey"
        Write-Host "SHA-256:    $($evidenceReference.sha256)"
        Write-Host "Version ID: $($evidenceReference.version_id)"
    }
    else {
        Assert-Test `
            -Condition ($finalTags["IncidentStatus"] -eq "clean") `
            -Name "Workflow preserves clean incident status" `
            -Detail "IncidentStatus=$($finalTags['IncidentStatus'])"

        Assert-Test `
            -Condition (
                $finalSecurityGroupIds.Count -eq 1 -and
                $finalSecurityGroupIds[0] -eq $baselineSecurityGroupId
            ) `
            -Name "Workflow preserves baseline security group" `
            -Detail "SecurityGroups=$($finalSecurityGroupIds -join ',')"
    }

    $script:Succeeded = $true
}
catch {
    $script:Failed++
    $exitCode = 1
    Write-Host ""
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red

    if ($null -ne $script:TemporaryDirectory) {
        Write-Host "Diagnostic artifacts: $script:TemporaryDirectory"
    }
}
finally {
    if (
        $ExecuteContainment -and
        $script:RecoveryArmed -and
        -not [string]::IsNullOrWhiteSpace([string]$script:LabInstanceId) -and
        -not [string]::IsNullOrWhiteSpace([string]$script:BaselineSecurityGroupId)
    ) {
        try {
            Write-Host ""
            Write-Host "Restoring the disposable target to its baseline state..." -ForegroundColor Yellow

            if (-not [string]::IsNullOrWhiteSpace([string]$script:ExecutionArn)) {
                Stop-ExecutionIfRunning -ExecutionArn $script:ExecutionArn
            }

            $recoveredInstance = Restore-LabTarget `
                -InstanceId $script:LabInstanceId `
                -BaselineSecurityGroupId $script:BaselineSecurityGroupId

            $recoveredTags = Get-TagMap -Instance $recoveredInstance
            $recoveredSecurityGroupIds = @(
                $recoveredInstance.SecurityGroups |
                    ForEach-Object { [string]$_.GroupId }
            )

            Write-Pass `
                -Name "Automatic target recovery" `
                -Detail "IncidentStatus=$($recoveredTags['IncidentStatus']); SecurityGroups=$($recoveredSecurityGroupIds -join ',')"

            if (
                $null -ne $script:TemporaryDirectory -and
                (Test-Path -LiteralPath $script:TemporaryDirectory)
            ) {
                $recoveryState = @{
                    instance_id        = $script:LabInstanceId
                    instance_state     = [string]$recoveredInstance.State.Name
                    incident_status    = [string]$recoveredTags["IncidentStatus"]
                    security_group_ids = $recoveredSecurityGroupIds
                    recovered_at       = [DateTimeOffset]::UtcNow.ToString("o")
                }
                $recoveryStatePath = Join-Path `
                    $script:TemporaryDirectory `
                    "recovery-state.json"
                Write-Utf8NoBomJson `
                    -Value $recoveryState `
                    -Path $recoveryStatePath
            }
        }
        catch {
            $script:Failed++
            $script:Succeeded = $false
            $exitCode = 1

            Write-Host ""
            Write-Host "[RECOVERY ERROR] $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "The target may still be quarantined. Inspect it before running another test." -ForegroundColor Yellow
            Write-Host "Instance: $($script:LabInstanceId)" -ForegroundColor Yellow
            Write-Host "Expected baseline security group: $($script:BaselineSecurityGroupId)" -ForegroundColor Yellow
        }
    }

    if (
        $script:Succeeded -and
        $null -ne $script:TemporaryDirectory -and
        (Test-Path -LiteralPath $script:TemporaryDirectory)
    ) {
        if ($ExecuteContainment) {
            Write-Host ""
            Write-Host "Evidence artifacts: $script:TemporaryDirectory" -ForegroundColor Yellow
            Write-Host "These files contain account-specific identifiers and must not be committed." -ForegroundColor Yellow
        }
        else {
            Remove-Item `
                -LiteralPath $script:TemporaryDirectory `
                -Recurse `
                -Force
        }
    }
    elseif (
        $null -ne $script:TemporaryDirectory -and
        (Test-Path -LiteralPath $script:TemporaryDirectory)
    ) {
        Write-Host "Diagnostic artifacts: $script:TemporaryDirectory" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Validation summary"
Write-Host "Passed: $script:Passed"
Write-Host "Failed: $script:Failed"

exit $exitCode
