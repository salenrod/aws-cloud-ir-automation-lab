# Foundation Security Validation

## Status

**PASS**

| Metric | Result |
|---|---:|
| Controls passed | 26 |
| Controls failed | 0 |
| Terraform drift | None |
| AWS Region | `us-east-1` |
| Validation date | 2026-08-27 |

## Objective

Validate the security controls implemented in the foundation of the AWS Cloud Incident Response Automation Lab before deploying the event-driven incident response workflow.

The validation is automated by `scripts/Test-Foundation.ps1` and can be repeated without exposing AWS account IDs, resource IDs, ARNs, email addresses, Terraform state or credentials.

## Scope

The validation covers:

- Terraform state consistency
- EC2 configuration
- Network isolation
- Security Groups
- EBS encryption
- S3 evidence storage
- DynamoDB incident ledger
- SNS email notification
- Terraform configuration drift

## Validation results

| Area | Control | Result |
|---|---|---|
| Terraform | Expected foundation resources are present in state | PASS |
| EC2 | Instance is running | PASS |
| EC2 | No public IPv4 address | PASS |
| EC2 | IMDSv2 is required | PASS |
| EC2 | Only the baseline Security Group is attached | PASS |
| EBS | Root volume encryption is enabled | PASS |
| Network | Isolated subnet has no default internet route | PASS |
| Network | VPC has no Internet Gateway | PASS |
| Network | VPC has no NAT Gateway | PASS |
| Security Group | Baseline group has no ingress rules | PASS |
| Security Group | Baseline group has the expected egress rule | PASS |
| Security Group | Quarantine group has no ingress or egress rules | PASS |
| S3 | All four Block Public Access controls are enabled | PASS |
| S3 | Object Ownership is set to BucketOwnerEnforced | PASS |
| S3 | Versioning is enabled | PASS |
| S3 | Default SSE-S3 encryption is enabled | PASS |
| S3 | Evidence lifecycle rule exists | PASS |
| S3 | Current evidence retention is seven days | PASS |
| S3 | Noncurrent evidence retention is seven days | PASS |
| DynamoDB | Table is active | PASS |
| DynamoDB | Billing mode is PAY_PER_REQUEST | PASS |
| DynamoDB | Encryption at rest is enabled | PASS |
| DynamoDB | TTL uses the `expires_at` attribute | PASS |
| SNS | Email subscription exists | PASS |
| SNS | Email subscription is confirmed | PASS |
| Terraform | No configuration drift was detected | PASS |

## Security architecture decisions

### Isolated workload

The disposable EC2 target is deployed in an isolated subnet without an Internet Gateway, NAT Gateway or public IPv4 address.

The associated route table contains only the local VPC route. Although the baseline Security Group has an outbound rule, the instance has no route to the internet.

This design creates two independent layers of control:

1. The Security Group controls whether traffic is authorized.
2. The route table determines whether a network path exists.

### Pre-provisioned containment

Two Security Groups are maintained:

- **Baseline Security Group:** no ingress rules and one outbound rule.
- **Quarantine Security Group:** no ingress or egress rules.

The quarantine group is created before an incident occurs. The response automation can therefore isolate the EC2 instance by replacing its attached Security Group instead of creating a new security control during the incident.

### Instance Metadata Service protection

The EC2 instance requires IMDSv2 session tokens. Requests to the Instance Metadata Service without a valid token are rejected.

### Evidence protection

The evidence bucket implements:

- S3 Block Public Access
- BucketOwnerEnforced Object Ownership
- Versioning
- SSE-S3 encryption
- Seven-day lifecycle retention

The short retention period is appropriate for a disposable laboratory and reduces unnecessary storage costs.

### Incident ledger

The DynamoDB table uses:

- `incident_id` as its partition key
- On-demand billing
- Encryption at rest
- TTL through the `expires_at` attribute

The table will provide incident state tracking and idempotency for the response workflow.

### Notification channel

The SNS topic has a confirmed email subscription. It will notify the analyst about triage, containment and workflow execution results.

## Framework mapping

| Implementation | NIST CSF 2.0 category | Purpose |
|---|---|---|
| Terraform-managed baseline | PR.PS — Platform Security | Maintain secure infrastructure configurations |
| Isolated VPC and Security Groups | PR.IR — Technology Infrastructure Resilience | Restrict connectivity and support containment |
| EBS, S3 and DynamoDB encryption | PR.DS — Data Security | Protect data at rest |
| S3 versioning and evidence retention | PR.DS — Data Security | Preserve investigation evidence |
| SNS notification channel | RS.CO — Incident Response Reporting and Communication | Support incident notification |
| Repeatable validation script | PR.PS — Platform Security | Validate that security controls remain correctly configured |

## Reproduction

Authenticate to AWS:

```powershell
aws login --profile cloud-ir-signin
```

Run the automated validation from the repository root:

```powershell
.\scripts\Test-Foundation.ps1
```

A successful execution must finish with:

```text
Validation summary
Passed: 26
Failed: 0
```

The script must also return exit code zero:

```powershell
$LASTEXITCODE
```

## Current limitations

This validation covers only the secure AWS foundation.

The following components will be implemented in the next phase:

- GuardDuty
- EventBridge
- Step Functions
- Lambda triage and enrichment
- Automated EC2 containment
- EBS evidence snapshots
- Incident persistence
- CloudWatch metrics and logs
- Synthetic incident simulation
- Recovery and restoration procedure

## Evidence handling

The following artifacts must never be committed:

- Terraform state and state backups
- Saved Terraform plans
- Files containing real Terraform variable values
- AWS credentials or session tokens
- Raw logs containing AWS account or resource identifiers

The validation script intentionally reports control status without printing account IDs, resource IDs, ARNs or email addresses.

## AMI lifecycle stability

The lab instance is initially created from the latest Amazon Linux 2023 AMI
published through the AWS public Systems Manager parameter.

Because the public parameter advances when AWS publishes a new image, using
its value directly can cause Terraform to propose an unplanned EC2
replacement. The instance therefore ignores later changes to the `ami`
attribute after its initial creation.

This preserves the stable target required by the incident-response scenarios
while keeping other EC2 attributes under Terraform management.

AMI upgrades must be performed as an explicit and reviewed maintenance
operation. Recreating the disposable lab instance will use the current AMI
returned by the public parameter.

## References

- [NIST Cybersecurity Framework 2.0](https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [Terraform sensitive data guidance](https://developer.hashicorp.com/terraform/language/manage-sensitive-data)