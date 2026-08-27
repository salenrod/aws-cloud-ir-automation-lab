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