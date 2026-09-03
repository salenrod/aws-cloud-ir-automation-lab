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

    $json = $Value | ConvertTo-Json -Depth 50
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

$projectRoot = Split-Path -Parent $PSScriptRoot
$infraDirectory = Join-Path $projectRoot "infra"
$eventTemplatePath = Join-Path $projectRoot "events\guardduty-crypto-ec2.json"
$exitCode = 0

Write-Host ""
Write-Host "AWS Cloud IR Automation Lab"
Write-Host "Step Functions Orchestration Validation"
Write-Host "Profile: $Profile"
Write-Host "Region:  $Region"
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
        -Condition ($minimumSeverity -gt 0) `
        -Name "Triage threshold supports safe skip test" `
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

    $script:TemporaryDirectory = Join-Path (
        [System.IO.Path]::GetTempPath()
    ) ("cloud-ir-orchestration-" + [guid]::NewGuid().ToString("N"))
    $null = New-Item `
        -ItemType Directory `
        -Path $script:TemporaryDirectory `
        -Force

    $eventPath = Join-Path $script:TemporaryDirectory "guardduty-event.json"
    $incidentId = (
        "orchestration-skip-" +
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
    Write-Host "Using severity $testSeverity to validate the non-containment branch."
    Write-Host ""

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

    Assert-Test `
        -Condition ($enteredTaskNames -notcontains "ContainTarget") `
        -Name "Execution history excludes containment task" `
        -Detail "ContainTarget=not-entered"

    $finalInstance = Get-LabInstance -InstanceId $labInstanceId
    $finalTags = Get-TagMap -Instance $finalInstance
    $finalSecurityGroupIds = @(
        $finalInstance.SecurityGroups |
            ForEach-Object { [string]$_.GroupId }
    )

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
        $script:Succeeded -and
        $null -ne $script:TemporaryDirectory -and
        (Test-Path -LiteralPath $script:TemporaryDirectory)
    ) {
        Remove-Item `
            -LiteralPath $script:TemporaryDirectory `
            -Recurse `
            -Force
    }
}

Write-Host ""
Write-Host "Validation summary"
Write-Host "Passed: $script:Passed"
Write-Host "Failed: $script:Failed"

exit $exitCode
