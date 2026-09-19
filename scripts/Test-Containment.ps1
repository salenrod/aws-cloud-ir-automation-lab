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

function Invoke-LambdaSynchronously {
    param(
        [Parameter(Mandatory)]
        [string]$FunctionName,

        [Parameter(Mandatory)]
        [string]$PayloadPath,

        [Parameter(Mandatory)]
        [string]$ResponsePath,

        [Parameter(Mandatory)]
        [string]$Label
    )

    $metadata = Invoke-AwsJson -Arguments @(
        "lambda", "invoke",
        "--function-name", $FunctionName,
        "--invocation-type", "RequestResponse",
        "--cli-binary-format", "raw-in-base64-out",
        "--payload", "fileb://$PayloadPath",
        $ResponsePath,
        "--profile", $Profile,
        "--region", $Region,
        "--output", "json"
    )

    Assert-Test `
        -Condition ($metadata.StatusCode -eq 200) `
        -Name "$Label synchronous invocation" `
        -Detail "StatusCode=$($metadata.StatusCode)"

    $functionErrorProperty = $metadata.PSObject.Properties["FunctionError"]
    $functionError = if ($null -eq $functionErrorProperty) {
        $null
    }
    else {
        [string]$functionErrorProperty.Value
    }

    Assert-Test `
        -Condition ([string]::IsNullOrWhiteSpace($functionError)) `
        -Name "$Label function error" `
        -Detail "FunctionError=absent"

    Assert-Test `
        -Condition (Test-Path -LiteralPath $ResponsePath -PathType Leaf) `
        -Name "$Label response payload" `
        -Detail "response-file-present"

    return (Get-Content -LiteralPath $ResponsePath -Raw | ConvertFrom-Json)
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

function Find-ContainmentLogEvent {
    param(
        [Parameter(Mandatory)]
        [string]$LogGroupName,

        [Parameter(Mandatory)]
        [long]$StartTimeMilliseconds,

        [Parameter(Mandatory)]
        [string]$EventName
    )

    for ($attempt = 1; $attempt -le 15; $attempt++) {
        $response = Invoke-AwsJson -Arguments @(
            "logs", "filter-log-events",
            "--log-group-name", $LogGroupName,
            "--start-time", ([string]$StartTimeMilliseconds),
            "--profile", $Profile,
            "--region", $Region,
            "--output", "json"
        )

        $messages = @(
            $response.events |
                ForEach-Object { [string]$_.message }
        )
        $combinedMessages = $messages -join [Environment]::NewLine

        if ($combinedMessages -match ('"event"\s*:\s*"' + [regex]::Escape($EventName) + '"')) {
            return $true
        }

        if ($attempt -lt 15) {
            Start-Sleep -Seconds 2
        }
    }

    return $false
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$infraDirectory = Join-Path $projectRoot "infra"
$eventTemplatePath = Join-Path $projectRoot "events\guardduty-crypto-ec2.json"
$testStartMilliseconds = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$exitCode = 0

Write-Host ""
Write-Host "AWS Cloud IR Automation Lab"
Write-Host "Controlled Containment Validation"
Write-Host "Profile: $Profile"
Write-Host "Region:  $Region"
Write-Host ""

try {
    if (-not $ExecuteContainment) {
        throw (
            "This validation changes the lab EC2 security group. " +
            "Run again with -ExecuteContainment after reviewing the script."
        )
    }

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

    $triageFunctionName = Invoke-TerraformOutput `
        -InfraDirectory $infraDirectory `
        -Name "triage_lambda_name"
    $containmentFunctionName = Invoke-TerraformOutput `
        -InfraDirectory $infraDirectory `
        -Name "containment_lambda_name"
    $containmentLogGroupName = Invoke-TerraformOutput `
        -InfraDirectory $infraDirectory `
        -Name "containment_log_group_name"
    $labInstanceId = Invoke-TerraformOutput `
        -InfraDirectory $infraDirectory `
        -Name "lab_instance_id"
    $baselineSecurityGroupId = Invoke-TerraformOutput `
        -InfraDirectory $infraDirectory `
        -Name "baseline_security_group_id"
    $quarantineSecurityGroupId = Invoke-TerraformOutput `
        -InfraDirectory $infraDirectory `
        -Name "quarantine_security_group_id"
    $incidentsTableName = Invoke-TerraformOutput `
        -InfraDirectory $infraDirectory `
        -Name "incidents_table_name"
    $evidenceBucketName = Invoke-TerraformOutput `
        -InfraDirectory $infraDirectory `
        -Name "evidence_bucket_name"

    $containmentConfiguration = Invoke-AwsJson -Arguments @(
        "lambda", "get-function-configuration",
        "--function-name", $containmentFunctionName,
        "--profile", $Profile,
        "--region", $Region,
        "--output", "json"
    )

    Assert-Test `
        -Condition ($containmentConfiguration.State -eq "Active") `
        -Name "Containment Lambda state" `
        -Detail "State=$($containmentConfiguration.State)"

    Assert-Test `
        -Condition ($containmentConfiguration.LastUpdateStatus -eq "Successful") `
        -Name "Containment Lambda update state" `
        -Detail "LastUpdateStatus=$($containmentConfiguration.LastUpdateStatus)"

    Assert-Test `
        -Condition ($containmentConfiguration.Runtime -eq "python3.14") `
        -Name "Containment Lambda runtime" `
        -Detail "Runtime=$($containmentConfiguration.Runtime)"

    Assert-Test `
        -Condition ($containmentConfiguration.Handler -eq "handler.lambda_handler") `
        -Name "Containment Lambda handler" `
        -Detail "Handler=$($containmentConfiguration.Handler)"

    Assert-Test `
        -Condition (
            $containmentConfiguration.Environment.Variables.EVIDENCE_BUCKET_NAME -eq
            $evidenceBucketName
        ) `
        -Name "Containment evidence bucket configuration" `
        -Detail "Bucket=terraform-output-confirmed"

    $initialInstance = Get-LabInstance -InstanceId $labInstanceId
    $initialTags = Get-TagMap -Instance $initialInstance
    $initialSecurityGroupIds = @(
        $initialInstance.SecurityGroups |
            ForEach-Object { [string]$_.GroupId }
    )
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
        -Condition ($initialTags["IncidentStatus"] -eq "clean") `
        -Name "Target starts clean" `
        -Detail "IncidentStatus=$($initialTags['IncidentStatus'])"

    Assert-Test `
        -Condition ($initialNetworkInterfaceIds.Count -eq 1) `
        -Name "Target has one network interface" `
        -Detail "NetworkInterfaces=$($initialNetworkInterfaceIds.Count)"

    Assert-Test `
        -Condition (
            $initialSecurityGroupIds.Count -eq 1 -and
            $initialSecurityGroupIds[0] -eq $baselineSecurityGroupId
        ) `
        -Name "Target starts with baseline security group" `
        -Detail "SecurityGroups=$($initialSecurityGroupIds -join ',')"

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

    $script:TemporaryDirectory = Join-Path (
        [System.IO.Path]::GetTempPath()
    ) ("cloud-ir-containment-" + [guid]::NewGuid().ToString("N"))
    $null = New-Item `
        -ItemType Directory `
        -Path $script:TemporaryDirectory `
        -Force

    $eventPath = Join-Path $script:TemporaryDirectory "guardduty-event.json"
    $triageResponsePath = Join-Path $script:TemporaryDirectory "triage-response.json"
    $containmentResponsePath = Join-Path $script:TemporaryDirectory "containment-response.json"
    $duplicateResponsePath = Join-Path $script:TemporaryDirectory "containment-duplicate-response.json"
    $dynamoKeyPath = Join-Path $script:TemporaryDirectory "dynamodb-key.json"
    $evidenceObjectPath = Join-Path $script:TemporaryDirectory "pre-containment-evidence.json"

    $event = Get-Content -LiteralPath $eventTemplatePath -Raw | ConvertFrom-Json
    $incidentId = (
        "e2e-containment-" +
        [DateTimeOffset]::UtcNow.ToString("yyyyMMddTHHmmssfffZ") +
        "-" +
        [guid]::NewGuid().ToString("N").Substring(0, 8)
    )
    $eventTime = [DateTimeOffset]::UtcNow.ToString("o")

    $event.id = "event-$incidentId"
    $event.account = $accountId
    $event.region = $Region
    $event.time = $eventTime
    $event.detail.accountId = $accountId
    $event.detail.region = $Region
    $event.detail.id = $incidentId
    $event.detail.resource.instanceDetails.instanceId = $labInstanceId
    $event.detail.createdAt = $eventTime
    $event.detail.updatedAt = $eventTime

    Write-Utf8NoBomJson -Value $event -Path $eventPath

    Write-Host ""
    Write-Host "Incident: $incidentId"
    Write-Host "Executing authorized synthetic containment..."
    Write-Host ""

    $triageResult = Invoke-LambdaSynchronously `
        -FunctionName $triageFunctionName `
        -PayloadPath $eventPath `
        -ResponsePath $triageResponsePath `
        -Label "Triage"

    Assert-Test `
        -Condition ($triageResult.incident_id -eq $incidentId) `
        -Name "Triage preserves incident identifier" `
        -Detail "IncidentId=$incidentId"

    Assert-Test `
        -Condition ($triageResult.resource.instance_id -eq $labInstanceId) `
        -Name "Triage enriches the authorized target" `
        -Detail "InstanceId=$labInstanceId"

    Assert-Test `
        -Condition ($triageResult.decision.containment_eligible -eq $true) `
        -Name "Triage authorizes containment" `
        -Detail "Eligible=True"

    Assert-Test `
        -Condition (@($triageResult.decision.reasons).Count -eq 0) `
        -Name "Triage decision has no blocking reasons" `
        -Detail "ReasonCount=0"

    $containmentResult = Invoke-LambdaSynchronously `
        -FunctionName $containmentFunctionName `
        -PayloadPath $triageResponsePath `
        -ResponsePath $containmentResponsePath `
        -Label "Containment"

    Assert-Test `
        -Condition ($containmentResult.incident_id -eq $incidentId) `
        -Name "Containment preserves incident identifier" `
        -Detail "IncidentId=$incidentId"

    Assert-Test `
        -Condition ($containmentResult.status -eq "contained") `
        -Name "Containment result status" `
        -Detail "Status=$($containmentResult.status)"

    Assert-Test `
        -Condition ($containmentResult.changed -eq $true) `
        -Name "Containment changes the target" `
        -Detail "Changed=True"

    Assert-Test `
        -Condition ($containmentResult.idempotent -eq $false) `
        -Name "First containment is not a duplicate" `
        -Detail "Idempotent=False"

    Assert-Test `
        -Condition ($containmentResult.notification_status -eq "published") `
        -Name "Containment notification published" `
        -Detail "NotificationStatus=published"

    $expectedEvidenceKey = "incidents/$incidentId/pre-containment.json"
    $evidenceReference = $containmentResult.evidence

    Assert-Test `
        -Condition (
            $evidenceReference.bucket -eq $evidenceBucketName -and
            $evidenceReference.key -eq $expectedEvidenceKey
        ) `
        -Name "Pre-containment evidence location" `
        -Detail "Key=$expectedEvidenceKey"

    Assert-Test `
        -Condition (
            $evidenceReference.status -eq "created" -and
            -not [string]::IsNullOrWhiteSpace(
                [string]$evidenceReference.version_id
            )
        ) `
        -Name "Immutable evidence version" `
        -Detail "Status=created; VersionId=present"

    Assert-Test `
        -Condition (
            [string]$evidenceReference.sha256 -match
            '^[0-9a-f]{64}$'
        ) `
        -Name "Evidence SHA-256 reference" `
        -Detail "Sha256=present"

    Assert-Test `
        -Condition (
            @($containmentResult.security_group_ids_before).Count -eq 1 -and
            @($containmentResult.security_group_ids_before)[0] -eq $baselineSecurityGroupId
        ) `
        -Name "Baseline security group recorded" `
        -Detail "Before=$baselineSecurityGroupId"

    Assert-Test `
        -Condition (
            @($containmentResult.security_group_ids_after).Count -eq 1 -and
            @($containmentResult.security_group_ids_after)[0] -eq $quarantineSecurityGroupId
        ) `
        -Name "Quarantine security group recorded" `
        -Detail "After=$quarantineSecurityGroupId"

    $quarantineObserved = $false
    $containedInstance = $null

    for ($attempt = 1; $attempt -le 15; $attempt++) {
        $candidateInstance = Get-LabInstance -InstanceId $labInstanceId
        $candidateTags = Get-TagMap -Instance $candidateInstance
        $candidateSecurityGroupIds = @(
            $candidateInstance.SecurityGroups |
                ForEach-Object { [string]$_.GroupId }
        )

        if (
            $candidateSecurityGroupIds.Count -eq 1 -and
            $candidateSecurityGroupIds[0] -eq $quarantineSecurityGroupId -and
            $candidateTags["IncidentStatus"] -eq "contained"
        ) {
            $quarantineObserved = $true
            $containedInstance = $candidateInstance
            break
        }

        if ($attempt -lt 15) {
            Start-Sleep -Seconds 2
        }
    }

    Assert-Test `
        -Condition $quarantineObserved `
        -Name "Live EC2 quarantine state" `
        -Detail "SecurityGroup=quarantine; IncidentStatus=contained"

    Assert-Test `
        -Condition ($containedInstance.State.Name -eq $initialInstance.State.Name) `
        -Name "Containment preserves instance power state" `
        -Detail "State=$($containedInstance.State.Name)"

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
            $localEvidenceSha256 -eq [string]$evidenceReference.sha256 -and
            $evidenceDownload.ChecksumSHA256 -eq $expectedChecksumSha256
        ) `
        -Name "Downloaded evidence checksum" `
        -Detail "LocalAndS3Checksums=confirmed"

    Assert-Test `
        -Condition (
            $evidenceDownload.VersionId -eq
            [string]$evidenceReference.version_id -and
            $evidenceDownload.ServerSideEncryption -eq "AES256"
        ) `
        -Name "Evidence version and encryption" `
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
        -Name "Evidence document contract" `
        -Detail "Schema=1.0; Type=pre-containment"

    Assert-Test `
        -Condition (
            $evidenceDocument.resource.instance_id -eq $labInstanceId -and
            $evidenceDocument.decision.containment_eligible -eq $true
        ) `
        -Name "Evidence incident decision" `
        -Detail "InstanceAndDecision=confirmed"

    Assert-Test `
        -Condition (
            $evidenceSecurityGroups.Count -eq 1 -and
            $evidenceSecurityGroups[0] -eq $baselineSecurityGroupId -and
            $evidenceDocument.instance.tags.IncidentStatus -eq "clean"
        ) `
        -Name "Evidence captures pre-containment state" `
        -Detail "SecurityGroup=baseline; IncidentStatus=clean"

    $containedAtBeforeDuplicate = [string]$incidentItem.contained_at.S

    $containmentCompleteFound = Find-ContainmentLogEvent `
        -LogGroupName $containmentLogGroupName `
        -StartTimeMilliseconds $testStartMilliseconds `
        -EventName "containment_complete"

    Assert-Test `
        -Condition $containmentCompleteFound `
        -Name "CloudWatch containment completion event" `
        -Detail "event=containment_complete"

    Write-Host ""
    Write-Host "Repeating the same incident to validate idempotency..."
    Write-Host ""

    $duplicateResult = Invoke-LambdaSynchronously `
        -FunctionName $containmentFunctionName `
        -PayloadPath $triageResponsePath `
        -ResponsePath $duplicateResponsePath `
        -Label "Duplicate containment"

    Assert-Test `
        -Condition ($duplicateResult.incident_id -eq $incidentId) `
        -Name "Duplicate preserves incident identifier" `
        -Detail "IncidentId=$incidentId"

    Assert-Test `
        -Condition ($duplicateResult.status -eq "already_contained") `
        -Name "Duplicate containment status" `
        -Detail "Status=$($duplicateResult.status)"

    Assert-Test `
        -Condition ($duplicateResult.changed -eq $false) `
        -Name "Duplicate does not change the target" `
        -Detail "Changed=False"

    Assert-Test `
        -Condition ($duplicateResult.idempotent -eq $true) `
        -Name "Duplicate is idempotent" `
        -Detail "Idempotent=True"

    Assert-Test `
        -Condition (
            $duplicateResult.evidence.key -eq $expectedEvidenceKey -and
            $duplicateResult.evidence.version_id -eq
            [string]$evidenceReference.version_id -and
            $duplicateResult.evidence.sha256 -eq
            [string]$evidenceReference.sha256
        ) `
        -Name "Duplicate preserves evidence reference" `
        -Detail "KeyChecksumAndVersionUnchanged=True"

    $incidentItemAfterDuplicate = Get-IncidentItem `
        -TableName $incidentsTableName `
        -IncidentId $incidentId `
        -KeyPath $dynamoKeyPath

    Assert-Test `
        -Condition ($incidentItemAfterDuplicate.status.S -eq "contained") `
        -Name "Duplicate preserves DynamoDB status" `
        -Detail "Status=contained"

    Assert-Test `
        -Condition ($incidentItemAfterDuplicate.contained_at.S -eq $containedAtBeforeDuplicate) `
        -Name "Duplicate preserves original completion time" `
        -Detail "ContainedAtUnchanged=True"

    $finalInstance = Get-LabInstance -InstanceId $labInstanceId
    $finalTags = Get-TagMap -Instance $finalInstance
    $finalSecurityGroupIds = @(
        $finalInstance.SecurityGroups |
            ForEach-Object { [string]$_.GroupId }
    )

    Assert-Test `
        -Condition (
            $finalSecurityGroupIds.Count -eq 1 -and
            $finalSecurityGroupIds[0] -eq $quarantineSecurityGroupId
        ) `
        -Name "Duplicate preserves quarantine security group" `
        -Detail "SecurityGroups=$($finalSecurityGroupIds -join ',')"

    Assert-Test `
        -Condition ($finalTags["IncidentStatus"] -eq "contained") `
        -Name "Duplicate preserves incident status tag" `
        -Detail "IncidentStatus=contained"

    $idempotentLogFound = Find-ContainmentLogEvent `
        -LogGroupName $containmentLogGroupName `
        -StartTimeMilliseconds $testStartMilliseconds `
        -EventName "containment_idempotent"

    Assert-Test `
        -Condition $idempotentLogFound `
        -Name "CloudWatch idempotency event" `
        -Detail "event=containment_idempotent"

    Write-Host ""
    Write-Host "Containment evidence"
    Write-Host "Incident ID:    $incidentId"
    Write-Host "Instance state: $($finalInstance.State.Name)"
    Write-Host "Security group: $quarantineSecurityGroupId"
    Write-Host "Incident tag:   $($finalTags['IncidentStatus'])"
    Write-Host "S3 evidence:    s3://$evidenceBucketName/$expectedEvidenceKey"
    Write-Host "SHA-256:        $($evidenceReference.sha256)"
    Write-Host "Version ID:     $($evidenceReference.version_id)"
    Write-Host ""
    Write-Host "The lab target remains intentionally quarantined." -ForegroundColor Yellow
    Write-Host "Do not run Test-Foundation.ps1 or Test-Triage.ps1 until the target is reset." -ForegroundColor Yellow
    Write-Host "Check the configured mailbox for the SNS containment notification." -ForegroundColor Yellow
}
catch {
    $script:Failed++
    $exitCode = 1
    Write-Host ""
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "The target may be partially or fully quarantined. Do not rerun blindly." -ForegroundColor Yellow
}
finally {
    if (
        $null -ne $script:TemporaryDirectory -and
        (Test-Path -LiteralPath $script:TemporaryDirectory)
    ) {
        if ($exitCode -eq 0) {
            Remove-Item `
                -LiteralPath $script:TemporaryDirectory `
                -Recurse `
                -Force
        }
        else {
            Write-Host "Diagnostic artifacts: $script:TemporaryDirectory" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "Validation summary"
    Write-Host "Passed: $script:Passed"
    Write-Host "Failed: $script:Failed"
}

exit $exitCode
