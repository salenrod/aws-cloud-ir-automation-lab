# Step Functions orchestration validation

## Purpose

This document describes the safe validation of the AWS Step Functions workflow that connects GuardDuty finding triage to controlled EC2 containment.

The first orchestration test deliberately uses a severity below the configured triage threshold. It validates the state machine and its conditional branch without changing the EC2 target.

## Architecture

```mermaid
flowchart TD
    A["Synthetic GuardDuty finding"] --> B["TriageFinding"]
    B --> C{"Containment eligible?"}
    C -->|Yes| D["ContainTarget"]
    C -->|No| E["NoContainmentRequired"]
```

The workflow is a Step Functions Standard Workflow. Its execution role can invoke only the triage and containment Lambda functions managed by this laboratory.

## Why Standard Workflow

Standard Workflow was selected because incident response benefits from durable state, exactly-once workflow execution semantics, and execution history that can be inspected through the API or console after completion.

The Lambda functions still implement their own safety and idempotency controls. Workflow-level guarantees do not replace resource-level revalidation.

## Workflow states

| State | Type | Purpose |
| --- | --- | --- |
| `TriageFinding` | Task | Invokes the triage Lambda with the original finding |
| `EvaluateContainmentEligibility` | Choice | Reads `decision.containment_eligible` |
| `ContainTarget` | Task | Invokes controlled containment only when explicitly eligible |
| `NoContainmentRequired` | Pass | Records that the workflow skipped mutation |
| `WorkflowFailed` | Fail | Terminates a failed task path for investigation |

Only transient Lambda service errors are retried automatically. Application and safety errors follow the failure path so an analyst can inspect the execution instead of repeatedly attempting an unsafe action.

## Safe validation scenario

`Test-Orchestration.ps1` performs the following checks:

1. Confirms that AWS CLI, Terraform and the synthetic finding template are present.
2. Resolves the deployed state machine and target through Terraform outputs.
3. Confirms that the workflow is active and uses type `STANDARD`.
4. Confirms that the target starts clean with the baseline security group.
5. Reads the current minimum severity from the triage Lambda.
6. Generates a unique finding below that threshold.
7. Starts a Step Functions execution and waits for completion.
8. Confirms that triage marked the finding as ineligible.
9. Confirms that execution history entered `TriageFinding` but never entered `ContainTarget`.
10. Confirms that the EC2 security group and incident tag remain unchanged.

The test does not insert a containment record into DynamoDB because the containment Lambda is intentionally not invoked on the skip path.

## Commands

Run from the repository root:

```powershell
.\scripts\Test-Orchestration.ps1
```

Capture the result immediately:

```powershell
$orchestrationExitCode = $LASTEXITCODE
Write-Host "Orchestration validation exit code: $orchestrationExitCode"
```

Expected result:

```text
Passed: 23
Failed: 0
Orchestration validation exit code: 0
```

## Recorded validation

The first AWS validation completed successfully on 2026-09-03:

```text
Passed: 23
Failed: 0
Orchestration validation exit code: 0
```

The execution history confirmed:

```text
TriageFinding=entered
ContainTarget=not-entered
```

Post-execution validation confirmed that the target remained `clean` and retained only the baseline security group.

Regression checks also completed successfully:

```text
Foundation: 26 passed, 0 failed
Python:     13 passed
Terraform:  No changes, exit code 0
```

## Failure investigation

If the execution does not succeed, do not start the containment test. Preserve the diagnostic directory printed by the script and inspect:

```powershell
aws stepfunctions describe-execution `
  --execution-arn <execution-arn> `
  --profile cloud-ir-lab `
  --region us-east-1
```

```powershell
aws stepfunctions get-execution-history `
  --execution-arn <execution-arn> `
  --profile cloud-ir-lab `
  --region us-east-1
```

Also inspect the triage or containment Lambda log group corresponding to the failed task.

## Cost controls

The laboratory does not enable Step Functions execution logging in this phase. Standard Workflow execution history is available natively, while the invoked Lambda functions continue writing their operational logs to CloudWatch.

This avoids a new log group and the broad CloudWatch Logs delivery permissions required by Step Functions logging. Only a small number of state transitions are used during validation.

## Operational observation: transient S3 refresh

The first Terraform drift check after orchestration validation incorrectly reported the evidence bucket as deleted and proposed recreating the S3 resource family.

The proposed plan was not applied. Direct checks confirmed that:

- `HeadBucket` succeeded for the expected account;
- classic S3 bucket tagging succeeded;
- S3 Control `ListTagsForResource` succeeded;
- DNS resolution and TCP port 443 for the S3 Control endpoint succeeded;
- all six S3 resources remained in Terraform state.

After clearing the local DNS cache, the next Terraform plan returned `No changes` with exit code `0`. No state removal, import or resource recreation was performed.

## Security properties

- The workflow role can invoke only the two laboratory Lambda functions.
- The read-only test cannot reach the containment task.
- The choice has an explicit default skip path.
- Missing or false eligibility never falls through to containment.
- The containment Lambda independently revalidates the instance, tags, interface count and security groups.
- No real account ID, ARN, instance ID or security group ID is stored in this document.

## Next validation

After the safe skip path succeeds, a separately authorized test can exercise the eligible path through Step Functions. That test must reuse the established recovery runbook and leave the target in its baseline state when finished.

## References

- [Invoke AWS Lambda with Step Functions](https://docs.aws.amazon.com/step-functions/latest/dg/connect-lambda.html)
- [Choice workflow state](https://docs.aws.amazon.com/step-functions/latest/dg/state-choice.html)
- [Choosing a Step Functions workflow type](https://docs.aws.amazon.com/step-functions/latest/dg/choosing-workflow-type.html)
- [AWS Step Functions pricing](https://aws.amazon.com/step-functions/pricing/)
