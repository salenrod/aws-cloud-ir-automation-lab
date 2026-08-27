[CmdletBinding()]
param(
    [string]$Profile = "cloud-ir-lab",
    [string]$Region = "us-east-1",
    [string]$TerraformDirectory = (Join-Path $PSScriptRoot "..\infra")
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

$script:Passed = 0
$script:Failed = 0

function Write-ControlResult {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [bool]$Condition,

        [Parameter(Mandatory)]
        [string]$Actual
    )

    if ($Condition) {
        $script:Passed++
        Write-Host "[PASS] $Name - $Actual" -ForegroundColor Green
    }
    else {
        $script:Failed++
        Write-Host "[FAIL] $Name - $Actual" -ForegroundColor Red
    }
}

function Invoke-NativeJson {
    param(
        [Parameter(Mandatory)]
        [string]$Command,

        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    $rawOutput = & $Command @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    $outputText = ($rawOutput | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine

    if ($exitCode -ne 0) {
        throw "$Command failed with exit code $exitCode.`n$outputText"
    }

    if ([string]::IsNullOrWhiteSpace($outputText)) {
        return $null
    }

    return $outputText | ConvertFrom-Json
}

function Invoke-AwsJson {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    $finalArguments = $Arguments + @(
        "--profile", $Profile,
        "--region", $Region,
        "--output", "json",
        "--no-cli-pager"
    )

    return Invoke-NativeJson `
        -Command "aws" `
        -Arguments $finalArguments
}

function Get-TerraformOutput {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $rawOutput = & terraform output -raw $Name 2>&1
    $exitCode = $LASTEXITCODE
    $value = ($rawOutput | ForEach-Object { $_.ToString() }) -join ""

    if ($exitCode -ne 0) {
        throw "Unable to read Terraform output '$Name': $value"
    }

    return $value.Trim()
}

function Get-OptionalPropertyValue {
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$PropertyName
    )

    $property = $InputObject.PSObject.Properties[$PropertyName]

    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

$terraformPath = (Resolve-Path $TerraformDirectory).Path

Push-Location $terraformPath

try {
    foreach ($requiredCommand in @("aws", "terraform")) {
        if ($null -eq (Get-Command $requiredCommand -ErrorAction SilentlyContinue)) {
            throw "Required command not found: $requiredCommand"
        }
    }

    Write-Host ""
    Write-Host "AWS Cloud IR Automation Lab" -ForegroundColor Cyan
    Write-Host "Foundation Security Validation" -ForegroundColor Cyan
    Write-Host "Profile: $Profile"
    Write-Host "Region:  $Region"
    Write-Host ""

    $labInstanceId = Get-TerraformOutput "lab_instance_id"
    $baselineSgId = Get-TerraformOutput "baseline_security_group_id"
    $quarantineSgId = Get-TerraformOutput "quarantine_security_group_id"
    $isolatedSubnetId = Get-TerraformOutput "isolated_subnet_id"
    $vpcId = Get-TerraformOutput "vpc_id"
    $evidenceBucket = Get-TerraformOutput "evidence_bucket_name"
    $incidentsTable = Get-TerraformOutput "incidents_table_name"
    $topicArn = Get-TerraformOutput "incident_topic_arn"

    # Terraform state

    $stateAddresses = @(& terraform state list)

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read Terraform state."
    }

    $expectedFoundationResources = @(
        "aws_dynamodb_table.incidents",
        "aws_instance.lab_target",
        "aws_route_table.isolated",
        "aws_route_table_association.isolated",
        "aws_s3_bucket.evidence",
        "aws_s3_bucket_lifecycle_configuration.evidence",
        "aws_s3_bucket_ownership_controls.evidence",
        "aws_s3_bucket_public_access_block.evidence",
        "aws_s3_bucket_server_side_encryption_configuration.evidence",
        "aws_s3_bucket_versioning.evidence",
        "aws_security_group.baseline",
        "aws_security_group.quarantine",
        "aws_sns_topic.incidents",
        "aws_sns_topic_subscription.email",
        "aws_subnet.isolated",
        "aws_vpc.lab",
        "aws_vpc_security_group_egress_rule.baseline_all"
    )

    $missingResources = @(
        $expectedFoundationResources |
            Where-Object { $_ -notin $stateAddresses }
    )

    Write-ControlResult `
        -Name "Foundation resources present in state" `
        -Condition ($missingResources.Count -eq 0) `
        -Actual "missing=$($missingResources.Count)"

    # EC2

    $instanceResponse = Invoke-AwsJson -Arguments @(
        "ec2", "describe-instances",
        "--instance-ids", $labInstanceId
    )

    $instance = $instanceResponse.Reservations[0].Instances[0]
    $instanceSgIds = @($instance.SecurityGroups | ForEach-Object { $_.GroupId })

    Write-ControlResult `
        -Name "EC2 state" `
        -Condition ($instance.State.Name -eq "running") `
        -Actual $instance.State.Name

$publicIpAddress = Get-OptionalPropertyValue `
    -InputObject $instance `
    -PropertyName "PublicIpAddress"

Write-ControlResult `
    -Name "EC2 has no public IPv4" `
    -Condition ([string]::IsNullOrWhiteSpace([string]$publicIpAddress)) `
    -Actual "public-ip-absent"

    Write-ControlResult `
        -Name "EC2 requires IMDSv2" `
        -Condition ($instance.MetadataOptions.HttpTokens -eq "required") `
        -Actual "HttpTokens=$($instance.MetadataOptions.HttpTokens)"

    Write-ControlResult `
        -Name "EC2 uses only baseline security group" `
        -Condition (
            $instanceSgIds.Count -eq 1 -and
            $instanceSgIds[0] -eq $baselineSgId
        ) `
        -Actual "security-group-count=$($instanceSgIds.Count)"

    $rootVolumeId = $instance.BlockDeviceMappings[0].Ebs.VolumeId

    $volumeResponse = Invoke-AwsJson -Arguments @(
        "ec2", "describe-volumes",
        "--volume-ids", $rootVolumeId
    )

    $rootVolume = $volumeResponse.Volumes[0]

    Write-ControlResult `
        -Name "Root EBS volume encrypted" `
        -Condition ([bool]$rootVolume.Encrypted) `
        -Actual "encrypted=$($rootVolume.Encrypted)"

    # Network isolation

    $routeResponse = Invoke-AwsJson -Arguments @(
        "ec2", "describe-route-tables",
        "--filters", "Name=association.subnet-id,Values=$isolatedSubnetId"
    )

    $routes = @($routeResponse.RouteTables[0].Routes)

    Write-ControlResult `
        -Name "Subnet has no default internet route" `
        -Condition (
            "0.0.0.0/0" -notin $routes.DestinationCidrBlock
        ) `
        -Actual "default-route-absent"

    $internetGatewayResponse = Invoke-AwsJson -Arguments @(
        "ec2", "describe-internet-gateways",
        "--filters", "Name=attachment.vpc-id,Values=$vpcId"
    )

    Write-ControlResult `
        -Name "VPC has no Internet Gateway" `
        -Condition (@($internetGatewayResponse.InternetGateways).Count -eq 0) `
        -Actual "count=$(@($internetGatewayResponse.InternetGateways).Count)"

    $natGatewayResponse = Invoke-AwsJson -Arguments @(
        "ec2", "describe-nat-gateways",
        "--filter", "Name=vpc-id,Values=$vpcId"
    )

    Write-ControlResult `
        -Name "VPC has no NAT Gateway" `
        -Condition (@($natGatewayResponse.NatGateways).Count -eq 0) `
        -Actual "count=$(@($natGatewayResponse.NatGateways).Count)"

    # Security groups

    $baselineRulesResponse = Invoke-AwsJson -Arguments @(
        "ec2", "describe-security-group-rules",
        "--filters", "Name=group-id,Values=$baselineSgId"
    )

    $baselineRules = @($baselineRulesResponse.SecurityGroupRules)
    $baselineIngress = @($baselineRules | Where-Object { -not $_.IsEgress })
    $baselineEgressAll = @(
        $baselineRules | Where-Object {
            $_.IsEgress -and
            $_.IpProtocol -eq "-1" -and
            $_.CidrIpv4 -eq "0.0.0.0/0"
        }
    )

    Write-ControlResult `
        -Name "Baseline security group has no ingress" `
        -Condition ($baselineIngress.Count -eq 0) `
        -Actual "ingress-rules=$($baselineIngress.Count)"

    Write-ControlResult `
        -Name "Baseline security group has expected egress" `
        -Condition ($baselineEgressAll.Count -eq 1) `
        -Actual "matching-egress-rules=$($baselineEgressAll.Count)"

    $quarantineRulesResponse = Invoke-AwsJson -Arguments @(
        "ec2", "describe-security-group-rules",
        "--filters", "Name=group-id,Values=$quarantineSgId"
    )

    $quarantineRules = @($quarantineRulesResponse.SecurityGroupRules)

    Write-ControlResult `
        -Name "Quarantine security group blocks all traffic" `
        -Condition ($quarantineRules.Count -eq 0) `
        -Actual "rules=$($quarantineRules.Count)"

    # S3

    $publicAccessResponse = Invoke-AwsJson -Arguments @(
        "s3api", "get-public-access-block",
        "--bucket", $evidenceBucket
    )

    $publicAccess = $publicAccessResponse.PublicAccessBlockConfiguration

    $allPublicAccessControlsEnabled =
        $publicAccess.BlockPublicAcls -and
        $publicAccess.IgnorePublicAcls -and
        $publicAccess.BlockPublicPolicy -and
        $publicAccess.RestrictPublicBuckets

    Write-ControlResult `
        -Name "S3 Block Public Access" `
        -Condition $allPublicAccessControlsEnabled `
        -Actual "all-four-controls-enabled"

    $ownershipResponse = Invoke-AwsJson -Arguments @(
        "s3api", "get-bucket-ownership-controls",
        "--bucket", $evidenceBucket
    )

    $objectOwnership = $ownershipResponse.OwnershipControls.Rules[0].ObjectOwnership

    Write-ControlResult `
        -Name "S3 Object Ownership" `
        -Condition ($objectOwnership -eq "BucketOwnerEnforced") `
        -Actual $objectOwnership

    $versioningResponse = Invoke-AwsJson -Arguments @(
        "s3api", "get-bucket-versioning",
        "--bucket", $evidenceBucket
    )

    Write-ControlResult `
        -Name "S3 versioning" `
        -Condition ($versioningResponse.Status -eq "Enabled") `
        -Actual ([string]$versioningResponse.Status)

    $encryptionResponse = Invoke-AwsJson -Arguments @(
        "s3api", "get-bucket-encryption",
        "--bucket", $evidenceBucket
    )

    $s3Encryption = $encryptionResponse.ServerSideEncryptionConfiguration.
        Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm

    Write-ControlResult `
        -Name "S3 default encryption" `
        -Condition ($s3Encryption -eq "AES256") `
        -Actual $s3Encryption

    $lifecycleResponse = Invoke-AwsJson -Arguments @(
        "s3api", "get-bucket-lifecycle-configuration",
        "--bucket", $evidenceBucket
    )

    $lifecycleRule = @(
        $lifecycleResponse.Rules |
            Where-Object { $_.ID -eq "expire-lab-evidence" }
    ) | Select-Object -First 1

    Write-ControlResult `
        -Name "S3 lifecycle rule exists" `
        -Condition ($null -ne $lifecycleRule) `
        -Actual "expire-lab-evidence"

    if ($null -ne $lifecycleRule) {
        Write-ControlResult `
            -Name "S3 current evidence retention" `
            -Condition ($lifecycleRule.Expiration.Days -eq 7) `
            -Actual "days=$($lifecycleRule.Expiration.Days)"

        Write-ControlResult `
            -Name "S3 noncurrent evidence retention" `
            -Condition (
                $lifecycleRule.NoncurrentVersionExpiration.NoncurrentDays -eq 7
            ) `
            -Actual "days=$($lifecycleRule.NoncurrentVersionExpiration.NoncurrentDays)"
    }

    # DynamoDB

    $tableResponse = Invoke-AwsJson -Arguments @(
        "dynamodb", "describe-table",
        "--table-name", $incidentsTable
    )

    $table = $tableResponse.Table

    Write-ControlResult `
        -Name "DynamoDB table state" `
        -Condition ($table.TableStatus -eq "ACTIVE") `
        -Actual $table.TableStatus

    Write-ControlResult `
        -Name "DynamoDB billing mode" `
        -Condition (
            $table.BillingModeSummary.BillingMode -eq "PAY_PER_REQUEST"
        ) `
        -Actual $table.BillingModeSummary.BillingMode

    Write-ControlResult `
        -Name "DynamoDB encryption" `
        -Condition ($table.SSEDescription.Status -eq "ENABLED") `
        -Actual $table.SSEDescription.Status

    $ttlResponse = Invoke-AwsJson -Arguments @(
        "dynamodb", "describe-time-to-live",
        "--table-name", $incidentsTable
    )

    $ttl = $ttlResponse.TimeToLiveDescription

    Write-ControlResult `
        -Name "DynamoDB TTL" `
        -Condition (
            $ttl.AttributeName -eq "expires_at" -and
            $ttl.TimeToLiveStatus -eq "ENABLED"
        ) `
        -Actual "$($ttl.AttributeName)/$($ttl.TimeToLiveStatus)"

    # SNS

    $subscriptionsResponse = Invoke-AwsJson -Arguments @(
        "sns", "list-subscriptions-by-topic",
        "--topic-arn", $topicArn
    )

    $emailSubscriptions = @(
        $subscriptionsResponse.Subscriptions |
            Where-Object { $_.Protocol -eq "email" }
    )

    Write-ControlResult `
        -Name "SNS email subscription exists" `
        -Condition ($emailSubscriptions.Count -eq 1) `
        -Actual "email-subscriptions=$($emailSubscriptions.Count)"

    if ($emailSubscriptions.Count -eq 1) {
        $subscriptionAttributes = Invoke-AwsJson -Arguments @(
            "sns", "get-subscription-attributes",
            "--subscription-arn", $emailSubscriptions[0].SubscriptionArn
        )

        $pendingConfirmation =
            $subscriptionAttributes.Attributes.PendingConfirmation

        Write-ControlResult `
            -Name "SNS email subscription confirmed" `
            -Condition ($pendingConfirmation -eq "false") `
            -Actual "pending=$pendingConfirmation"
    }

    # Terraform drift

    $planOutput = & terraform plan `
        -detailed-exitcode `
        -input=false `
        -no-color 2>&1

    $planExitCode = $LASTEXITCODE

    Write-ControlResult `
        -Name "Terraform configuration has no drift" `
        -Condition ($planExitCode -eq 0) `
        -Actual "exit-code=$planExitCode"

    if ($planExitCode -ne 0) {
        Write-Host ""
        Write-Host "Terraform plan tail:" -ForegroundColor Yellow
        $planOutput | Select-Object -Last 20
    }
}
catch {
    $script:Failed++
    Write-Host ""
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    Pop-Location
}

Write-Host ""
Write-Host "Validation summary" -ForegroundColor Cyan
Write-Host "Passed: $script:Passed"
Write-Host "Failed: $script:Failed"

if ($script:Failed -gt 0) {
    exit 1
}

exit 0