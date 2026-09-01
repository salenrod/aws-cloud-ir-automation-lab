[CmdletBinding()]
param(
    [string]$Profile = "cloud-ir-lab",
    [string]$Region = "us-east-1"
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

$script:Passed = 0
$script:Failed = 0

$projectRoot = (
    Resolve-Path (Join-Path $PSScriptRoot "..")
).Path

$infraPath = Join-Path $projectRoot "infra"
$eventTemplatePath = Join-Path `
    $projectRoot `
    "events\guardduty-crypto-ec2.json"

$runId = [Guid]::NewGuid().ToString()

$payloadRelativePath = (
    "events/triage-validation-{0}-live.json" -f $runId
)

$responseRelativePath = (
    "events/triage-validation-{0}-response.json" -f $runId
)

$payloadPath = Join-Path `
    $projectRoot `
    ($payloadRelativePath.Replace("/", "\"))

$responsePath = Join-Path `
    $projectRoot `
    ($responseRelativePath.Replace("/", "\"))

$locationPushed = $false

function Add-Result {
    param(
        [string]$Name,
        [bool]$Condition,
        [string]$Evidence
    )

    if ($Condition) {
        $script:Passed++
        Write-Host "[PASS] $Name - $Evidence" -ForegroundColor Green
    }
    else {
        $script:Failed++
        Write-Host "[FAIL] $Name - $Evidence" -ForegroundColor Red
    }
}

function Invoke-ExternalText {
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )

    $output = & $FilePath @Arguments 2>&1
    $exitCode = $LASTEXITCODE

    $text = (
        $output |
        ForEach-Object { $_.ToString() }
    ) -join [Environment]::NewLine

    if ($exitCode -ne 0) {
        throw "$FilePath failed with exit code ${exitCode}: $text"
    }

    return $text.Trim()
}

function Invoke-AwsJson {
    param(
        [string[]]$Arguments
    )

    $fullArguments = @($Arguments)

    $fullArguments += @(
        "--profile", $Profile,
        "--region", $Region,
        "--output", "json",
        "--no-cli-pager"
    )

    $text = Invoke-ExternalText `
        -FilePath "aws" `
        -Arguments $fullArguments

    return $text | ConvertFrom-Json
}

function Get-TerraformOutput {
    param(
        [string]$Name
    )

    $text = Invoke-ExternalText `
        -FilePath "terraform" `
        -Arguments @(
            "-chdir=$infraPath",
            "output",
            "-raw",
            $Name
        )

    return $text.Trim()
}

function Get-TagValue {
    param(
        [object[]]$Tags,
        [string]$Key
    )

    $tag = $Tags |
        Where-Object { $_.Key -eq $Key } |
        Select-Object -First 1

    if ($null -eq $tag) {
        return $null
    }

    return $tag.Value
}

function Get-SecurityGroupIds {
    param(
        [object]$Instance
    )

    return @(
        $Instance.SecurityGroups |
        ForEach-Object { $_.GroupId } |
        Sort-Object
    )
}

Write-Host ""
Write-Host "AWS Cloud IR Automation Lab"
Write-Host "Triage Lambda Validation"
Write-Host "Profile: $Profile"
Write-Host "Region:  $Region"
Write-Host ""

try {
    Push-Location $projectRoot
    $locationPushed = $true

    $awsCommand = Get-Command "aws" -ErrorAction SilentlyContinue
    $terraformCommand = Get-Command "terraform" -ErrorAction SilentlyContinue

    Add-Result `
        -Name "AWS CLI available" `
        -Condition ($null -ne $awsCommand) `
        -Evidence "aws-command-found"

    Add-Result `
        -Name "Terraform available" `
        -Condition ($null -ne $terraformCommand) `
        -Evidence "terraform-command-found"

    Add-Result `
        -Name "Synthetic event template exists" `
        -Condition (Test-Path $eventTemplatePath) `
        -Evidence $eventTemplatePath

    if ($null -eq $awsCommand) {
        throw "AWS CLI is not available."
    }

    if ($null -eq $terraformCommand) {
        throw "Terraform is not available."
    }

    if (-not (Test-Path $eventTemplatePath)) {
        throw "Synthetic event template was not found."
    }

    $functionName = Get-TerraformOutput "triage_lambda_name"
    $instanceId = Get-TerraformOutput "lab_instance_id"
    $baselineSecurityGroupId = Get-TerraformOutput `
        "baseline_security_group_id"
    $logGroupName = Get-TerraformOutput "triage_log_group_name"

    $callerIdentity = Invoke-AwsJson @(
        "sts",
        "get-caller-identity"
    )

    $accountId = $callerIdentity.Account

    $functionConfiguration = Invoke-AwsJson @(
        "lambda",
        "get-function-configuration",
        "--function-name",
        $functionName
    )

    Add-Result `
        -Name "Lambda state" `
        -Condition ($functionConfiguration.State -eq "Active") `
        -Evidence "State=$($functionConfiguration.State)"

    Add-Result `
        -Name "Lambda update state" `
        -Condition (
            $functionConfiguration.LastUpdateStatus -eq "Successful"
        ) `
        -Evidence (
            "LastUpdateStatus=" +
            $functionConfiguration.LastUpdateStatus
        )

    Add-Result `
        -Name "Lambda runtime" `
        -Condition ($functionConfiguration.Runtime -eq "python3.14") `
        -Evidence "Runtime=$($functionConfiguration.Runtime)"

    Add-Result `
        -Name "Lambda handler" `
        -Condition (
            $functionConfiguration.Handler -eq "handler.lambda_handler"
        ) `
        -Evidence "Handler=$($functionConfiguration.Handler)"

    Add-Result `
        -Name "Minimum severity configuration" `
        -Condition (
            [double]$functionConfiguration.Environment.Variables.MIN_SEVERITY `
                -eq 7
        ) `
        -Evidence (
            "MIN_SEVERITY=" +
            $functionConfiguration.Environment.Variables.MIN_SEVERITY
        )

    $vpcId = ""

    $vpcConfigProperty = (
        $functionConfiguration.PSObject.Properties["VpcConfig"]
    )

    if (
        $null -ne $vpcConfigProperty -and
        $null -ne $vpcConfigProperty.Value
    ) {
        $vpcIdProperty = (
            $vpcConfigProperty.Value.PSObject.Properties["VpcId"]
        )

        if ($null -ne $vpcIdProperty) {
            $vpcId = [string]$vpcIdProperty.Value
        }
    }

    Add-Result `
        -Name "Lambda has no VPC attachment" `
        -Condition ([string]::IsNullOrWhiteSpace($vpcId)) `
        -Evidence "VpcId=absent"

    $instanceBefore = Invoke-AwsJson @(
        "ec2",
        "describe-instances",
        "--instance-ids",
        $instanceId,
        "--query",
        "Reservations[0].Instances[0]"
    )

    $stateBefore = $instanceBefore.State.Name
    $authorizationTag = Get-TagValue `
        -Tags $instanceBefore.Tags `
        -Key "AutoContainment"
    $incidentStatusBefore = Get-TagValue `
        -Tags $instanceBefore.Tags `
        -Key "IncidentStatus"
    $securityGroupsBefore = @(
    Get-SecurityGroupIds $instanceBefore
)

    Add-Result `
        -Name "Target instance state is supported" `
        -Condition ($stateBefore -in @("running", "stopped")) `
        -Evidence "State=$stateBefore"

    Add-Result `
        -Name "Target authorizes auto-containment" `
        -Condition ($authorizationTag -eq "true") `
        -Evidence "AutoContainment=$authorizationTag"

    Add-Result `
        -Name "Target starts clean" `
        -Condition ($incidentStatusBefore -eq "clean") `
        -Evidence "IncidentStatus=$incidentStatusBefore"

    Add-Result `
        -Name "Target starts with only baseline security group" `
        -Condition (
            $securityGroupsBefore.Count -eq 1 -and
            $securityGroupsBefore[0] -eq $baselineSecurityGroupId
        ) `
        -Evidence (
            "SecurityGroups=" +
            ($securityGroupsBefore -join ",")
        )

    $event = Get-Content `
        $eventTemplatePath `
        -Raw |
        ConvertFrom-Json

    $timestamp = [DateTime]::UtcNow.ToString(
        "yyyy-MM-ddTHH:mm:ss.fffZ"
    )

    $event.id = $runId
    $event.time = $timestamp
    $event.account = $accountId
    $event.detail.accountId = $accountId
    $event.detail.createdAt = $timestamp
    $event.detail.updatedAt = $timestamp
    $event.detail.resource.instanceDetails.instanceId = $instanceId

    $utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)

    $eventJson = $event |
        ConvertTo-Json -Depth 100

    [System.IO.File]::WriteAllText(
        $payloadPath,
        $eventJson,
        $utf8WithoutBom
    )

    $invokeArguments = @(
        "lambda",
        "invoke",
        "--function-name", $functionName,
        "--invocation-type", "RequestResponse",
        "--payload", "fileb://$payloadRelativePath",
        "--cli-binary-format", "raw-in-base64-out",
        "--profile", $Profile,
        "--region", $Region,
        "--output", "json",
        "--no-cli-pager",
        $responseRelativePath
    )

    $invokeText = Invoke-ExternalText `
        -FilePath "aws" `
        -Arguments $invokeArguments

    $invokeMetadata = $invokeText |
        ConvertFrom-Json

    $functionError = $null

    if (
        $invokeMetadata.PSObject.Properties.Name `
            -contains "FunctionError"
    ) {
        $functionError = $invokeMetadata.FunctionError
    }

    Add-Result `
        -Name "Synchronous invocation status" `
        -Condition ($invokeMetadata.StatusCode -eq 200) `
        -Evidence "StatusCode=$($invokeMetadata.StatusCode)"

    Add-Result `
        -Name "Invocation has no function error" `
        -Condition ([string]::IsNullOrWhiteSpace($functionError)) `
        -Evidence "FunctionError=absent"

    if ($invokeMetadata.StatusCode -ne 200) {
        throw "Lambda invocation did not return status 200."
    }

    if (-not [string]::IsNullOrWhiteSpace($functionError)) {
        throw "Lambda returned FunctionError=$functionError."
    }

    $response = Get-Content `
        $responsePath `
        -Raw |
        ConvertFrom-Json

    Add-Result `
        -Name "Finding identifier preserved" `
        -Condition ($response.incident_id -eq $event.detail.id) `
        -Evidence "IncidentId=$($response.incident_id)"

    Add-Result `
        -Name "Finding type preserved" `
        -Condition ($response.finding.type -eq $event.detail.type) `
        -Evidence "FindingType=$($response.finding.type)"

    Add-Result `
        -Name "Instance identifier enriched" `
        -Condition ($response.instance.instance_id -eq $instanceId) `
        -Evidence "InstanceId=$($response.instance.instance_id)"

    Add-Result `
        -Name "Instance state enriched" `
        -Condition ($response.instance.state -eq $stateBefore) `
        -Evidence "State=$($response.instance.state)"

    Add-Result `
        -Name "Authorization tag enriched" `
        -Condition (
            $response.instance.tags.AutoContainment -eq "true"
        ) `
        -Evidence (
            "AutoContainment=" +
            $response.instance.tags.AutoContainment
        )

    Add-Result `
        -Name "MITRE technique mapping" `
        -Condition (
            $response.mitre_attack.technique_id -eq "T1496.001"
        ) `
        -Evidence (
            "Technique=" +
            $response.mitre_attack.technique_id
        )

    Add-Result `
        -Name "MITRE tactic mapping" `
        -Condition ($response.mitre_attack.tactic -eq "Impact") `
        -Evidence "Tactic=$($response.mitre_attack.tactic)"

    Add-Result `
        -Name "Containment eligibility decision" `
        -Condition (
            $response.decision.containment_eligible -eq $true
        ) `
        -Evidence (
            "Eligible=" +
            $response.decision.containment_eligible
        )

    $decisionReasons = @(
    $response.decision.reasons
)

Add-Result `
    -Name "Eligibility has no blocking reasons" `
    -Condition ($decisionReasons.Count -eq 0) `
    -Evidence (
        "ReasonCount=" +
        $decisionReasons.Count
    )

    $instanceAfter = Invoke-AwsJson @(
        "ec2",
        "describe-instances",
        "--instance-ids",
        $instanceId,
        "--query",
        "Reservations[0].Instances[0]"
    )

    $incidentStatusAfter = Get-TagValue `
        -Tags $instanceAfter.Tags `
        -Key "IncidentStatus"

    $securityGroupsAfter = @(
    Get-SecurityGroupIds $instanceAfter
)

    Add-Result `
        -Name "Triage does not change incident status" `
        -Condition ($incidentStatusAfter -eq "clean") `
        -Evidence "IncidentStatus=$incidentStatusAfter"

    Add-Result `
        -Name "Triage does not change security groups" `
        -Condition (
            ($securityGroupsBefore -join ",") -eq
            ($securityGroupsAfter -join ",")
        ) `
        -Evidence (
            "SecurityGroups=" +
            ($securityGroupsAfter -join ",")
        )

    $latestLogStream = ""

    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $latestLogStream = Invoke-ExternalText `
            -FilePath "aws" `
            -Arguments @(
                "logs",
                "describe-log-streams",
                "--log-group-name", $logGroupName,
                "--order-by", "LastEventTime",
                "--descending",
                "--limit", "1",
                "--query", "logStreams[0].logStreamName",
                "--output", "text",
                "--profile", $Profile,
                "--region", $Region,
                "--no-cli-pager"
            )

        if (
            -not [string]::IsNullOrWhiteSpace($latestLogStream) -and
            $latestLogStream -ne "None"
        ) {
            break
        }

        if ($attempt -lt 3) {
            Start-Sleep -Seconds 2
        }
    }

    Add-Result `
        -Name "CloudWatch log stream exists" `
        -Condition (
            -not [string]::IsNullOrWhiteSpace($latestLogStream) -and
            $latestLogStream -ne "None"
        ) `
        -Evidence "LogStream=$latestLogStream"
}
catch {
    $script:Failed++
    Write-Host ""
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    if ($locationPushed) {
        Pop-Location
    }

    Remove-Item `
        $payloadPath `
        -Force `
        -ErrorAction SilentlyContinue

    Remove-Item `
        $responsePath `
        -Force `
        -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Validation summary"
Write-Host "Passed: $($script:Passed)"
Write-Host "Failed: $($script:Failed)"

if ($script:Failed -gt 0) {
    exit 1
}

exit 0