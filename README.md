# AWS Cloud IR Automation Lab

Laboratório de resposta automatizada a incidentes em AWS, desenvolvido para demonstrar investigação, enriquecimento, contenção, preservação de evidências, métricas e recuperação de uma instância EC2 potencialmente comprometida.

## Scenario

O cenário simula uma instância EC2 envolvida em uso indevido de recursos computacionais.

- MITRE ATT&CK: T1496.001 — Compute Hijacking
- NIST CSF 2.0: Detect, Respond, Recover and Improve
- Environment: isolated AWS laboratory
- Default response mode: DRY_RUN

No malware or cryptocurrency miner is executed.

## Planned architecture

1. Amazon GuardDuty detects or simulates a high-severity finding.
2. Amazon EventBridge sends the finding to AWS Step Functions.
3. A Python Lambda validates and enriches the finding.
4. A policy decision determines whether containment is authorized.
5. The containment Lambda preserves EBS evidence and applies a quarantine security group.
6. Incident records are stored in Amazon S3 and DynamoDB.
7. Amazon SNS and CloudWatch provide notification and operational metrics.

## Security guardrails

- Automatic containment requires severity >= 7.0.
- Automatic containment requires the EC2 tag `AutoContainment=true`.
- The initial deployment uses `DRY_RUN=true`.
- The laboratory VPC has no Internet Gateway or NAT Gateway.
- The EC2 instance has no public IPv4 address.
- IMDSv2 is mandatory.
- EBS volumes are encrypted.
- S3 Block Public Access is enabled.
- Evidence objects are versioned and expire automatically.
- Runtime roles follow least privilege.

## Repository structure

```text
infra/                   Terraform infrastructure
src/                     Python Lambda functions
scripts/                 Test, simulation, restoration and cleanup
events/                  Safe test events
tests/                   Automated tests
docs/                    Architecture, playbooks and evidence
.github/workflows/        CI validation

## Implemented: GuardDuty finding triage

The project currently includes a read-only AWS Lambda triage stage that:

- accepts GuardDuty-compatible EC2 findings;
- validates severity and resource type;
- enriches findings through the EC2 API;
- requires the explicit `AutoContainment=true` authorization tag;
- maps cryptocurrency-mining activity to MITRE ATT&CK `T1496.001`;
- determines containment eligibility without changing the target;
- produces structured operational logs in CloudWatch.

Validation results:

- 5 isolated Python unit tests passed;
- 27 live AWS validation controls passed;
- 0 validation failures;
- no security group, instance state or incident-status changes during triage.

Detailed evidence is available in
[`docs/triage-validation.md`](docs/triage-validation.md).

### Validate the triage stage

From the repository root:

`python -m pytest ".\tests\test_triage.py" -q`

`.\scripts\Test-Triage.ps1`

### Roadmap

- [x] Secure isolated AWS foundation
- [x] GuardDuty-compatible finding normalization
- [x] EC2 resource enrichment
- [x] MITRE ATT&CK mapping
- [x] Read-only containment eligibility decision
- [x] Automated live validation
- [ ] EventBridge ingestion
- [ ] Controlled EC2 quarantine
- [ ] Incident persistence and idempotency
- [ ] Evidence collection
- [ ] Notifications and response orchestration
- [ ] Operational metrics and post-incident reporting