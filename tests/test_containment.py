"""Unit tests for the controlled containment Lambda."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from copy import deepcopy
from typing import Any

import pytest
from botocore.exceptions import ClientError


os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")

from src.containment import handler  # noqa: E402


INSTANCE_ID = "i-0123456789abcdef0"
BASELINE_SG_ID = "sg-0123456789abcdef0"
QUARANTINE_SG_ID = "sg-0fedcba9876543210"
EVIDENCE_BUCKET = "cloud-ir-lab-synthetic-evidence"


class FakeEC2Client:
    """State-aware fake for the EC2 calls made by containment."""

    def __init__(
        self,
        response: dict[str, Any],
        operations: list[str] | None = None,
    ) -> None:
        self.response = deepcopy(response)
        self.operations = operations
        self.describe_calls: list[list[str]] = []
        self.modify_calls: list[dict[str, Any]] = []
        self.tag_calls: list[dict[str, Any]] = []

    def describe_instances(
        self,
        *,
        InstanceIds: list[str],
    ) -> dict[str, Any]:
        self.describe_calls.append(InstanceIds)
        return deepcopy(self.response)

    def modify_instance_attribute(
        self,
        *,
        InstanceId: str,
        Groups: list[str],
    ) -> None:
        if self.operations is not None:
            self.operations.append("ec2:ModifyInstanceAttribute")
        self.modify_calls.append(
            {
                "InstanceId": InstanceId,
                "Groups": Groups,
            }
        )
        instance = self.response["Reservations"][0]["Instances"][0]
        instance["SecurityGroups"] = [
            {
                "GroupId": group_id,
                "GroupName": "quarantine",
            }
            for group_id in Groups
        ]

    def create_tags(
        self,
        *,
        Resources: list[str],
        Tags: list[dict[str, str]],
    ) -> None:
        self.tag_calls.append(
            {
                "Resources": Resources,
                "Tags": Tags,
            }
        )


class FakeIncidentTable:
    """Fake DynamoDB table with conditional-claim behavior."""

    def __init__(
        self,
        existing_item: dict[str, Any] | None = None,
    ) -> None:
        self.existing_item = deepcopy(existing_item)
        self.update_calls: list[dict[str, Any]] = []
        self.get_calls: list[dict[str, Any]] = []

    def update_item(self, **kwargs: Any) -> dict[str, Any]:
        self.update_calls.append(deepcopy(kwargs))
        condition = kwargs.get("ConditionExpression", "")

        if (
            "attribute_not_exists" in condition
            and self.existing_item is not None
            and self.existing_item.get("status") != "failed"
        ):
            raise ClientError(
                {
                    "Error": {
                        "Code": "ConditionalCheckFailedException",
                        "Message": "The conditional request failed",
                    }
                },
                "UpdateItem",
            )

        if (
            "attribute_not_exists" in condition
            and self.existing_item is not None
        ):
            return {"Attributes": deepcopy(self.existing_item)}

        return {}

    def get_item(self, **kwargs: Any) -> dict[str, Any]:
        self.get_calls.append(deepcopy(kwargs))
        return (
            {"Item": deepcopy(self.existing_item)}
            if self.existing_item is not None
            else {}
        )


class FakeDynamoDBResource:
    """Return the configured fake incident table."""

    def __init__(self, table: FakeIncidentTable) -> None:
        self.table = table
        self.requested_table_names: list[str] = []

    def Table(self, table_name: str) -> FakeIncidentTable:  # noqa: N802
        self.requested_table_names.append(table_name)
        return self.table


class FakeSNSClient:
    """Capture SNS publications."""

    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.publish_calls: list[dict[str, Any]] = []

    def publish(self, **kwargs: Any) -> dict[str, str]:
        self.publish_calls.append(deepcopy(kwargs))
        if self.fail:
            raise ClientError(
                {
                    "Error": {
                        "Code": "InternalError",
                        "Message": "Synthetic SNS failure",
                    }
                },
                "Publish",
            )
        return {"MessageId": "synthetic-message-id"}


class FakeS3Body:
    """Provide the streaming-body method used by get_object."""

    def __init__(self, value: bytes) -> None:
        self.value = value

    def read(self) -> bytes:
        return self.value


class FakeS3Client:
    """Capture checksum-protected evidence writes and reads."""

    def __init__(
        self,
        *,
        fail_put: bool = False,
        corrupt_read: bool = False,
        existing_body: bytes | None = None,
        operations: list[str] | None = None,
    ) -> None:
        self.fail_put = fail_put
        self.corrupt_read = corrupt_read
        self.body = existing_body
        self.operations = operations
        self.version_id = "synthetic-version-1"
        self.put_calls: list[dict[str, Any]] = []
        self.get_calls: list[dict[str, Any]] = []

    def put_object(self, **kwargs: Any) -> dict[str, str]:
        self.put_calls.append(deepcopy(kwargs))
        if self.operations is not None:
            self.operations.append("s3:PutObject")

        if self.fail_put:
            raise ClientError(
                {
                    "Error": {
                        "Code": "ServiceUnavailable",
                        "Message": "Synthetic S3 failure",
                    }
                },
                "PutObject",
            )

        if self.body is not None:
            raise ClientError(
                {
                    "Error": {
                        "Code": "PreconditionFailed",
                        "Message": "Object already exists",
                    }
                },
                "PutObject",
            )

        self.body = bytes(kwargs["Body"])
        return {
            "ChecksumSHA256": kwargs["ChecksumSHA256"],
            "VersionId": self.version_id,
        }

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        self.get_calls.append(deepcopy(kwargs))
        if self.operations is not None:
            self.operations.append("s3:GetObject")

        if self.body is None:
            raise AssertionError("Evidence was read before it existed.")

        returned_body = (
            self.body + b"corrupted" if self.corrupt_read else self.body
        )
        checksum = base64.b64encode(
            hashlib.sha256(returned_body).digest()
        ).decode("ascii")
        return {
            "Body": FakeS3Body(returned_body),
            "ChecksumSHA256": checksum,
            "VersionId": self.version_id,
        }


def build_triage_result(
    *,
    eligible: bool = True,
    instance_id: str = INSTANCE_ID,
) -> dict[str, Any]:
    """Build the exact contract returned by the triage Lambda."""

    return {
        "incident_id": "sample-guardduty-compute-hijacking",
        "finding": {
            "id": "sample-guardduty-compute-hijacking",
            "type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
            "severity": 8.0,
        },
        "resource": {
            "type": "Instance",
            "instance_id": instance_id,
        },
        "instance": {
            "instance_id": instance_id,
            "security_group_ids": [BASELINE_SG_ID],
        },
        "mitre_attack": {
            "technique_id": "T1496.001",
            "technique_name": "Compute Hijacking",
            "tactic": "Impact",
        },
        "decision": {
            "containment_eligible": eligible,
            "minimum_severity": 7.0,
            "reasons": [] if eligible else ["severity_below_threshold"],
        },
    }


def build_ec2_response(
    *,
    auto_containment: str = "true",
    security_group_id: str = BASELINE_SG_ID,
    state: str = "running",
    network_interface_count: int = 1,
) -> dict[str, Any]:
    """Build the live state re-read by the containment function."""

    return {
        "Reservations": [
            {
                "Instances": [
                    {
                        "Architecture": "x86_64",
                        "ImageId": "ami-0123456789abcdef0",
                        "InstanceId": INSTANCE_ID,
                        "InstanceType": "t3.micro",
                        "Placement": {
                            "AvailabilityZone": "us-east-1a",
                        },
                        "PrivateIpAddress": "10.0.1.10",
                        "RootDeviceName": "/dev/xvda",
                        "State": {"Name": state},
                        "SubnetId": "subnet-0123456789abcdef0",
                        "VpcId": "vpc-0123456789abcdef0",
                        "SecurityGroups": [
                            {
                                "GroupId": security_group_id,
                                "GroupName": "synthetic-security-group",
                            }
                        ],
                        "NetworkInterfaces": [
                            {
                                "NetworkInterfaceId": (
                                    f"eni-{index:017d}"
                                )
                            }
                            for index in range(network_interface_count)
                        ],
                        "Tags": [
                            {
                                "Key": "AutoContainment",
                                "Value": auto_containment,
                            },
                            {
                                "Key": "IncidentStatus",
                                "Value": "clean",
                            },
                            {
                                "Key": "DataClassification",
                                "Value": "synthetic",
                            },
                        ],
                    }
                ]
            }
        ]
    }


def configure_handler(
    monkeypatch: pytest.MonkeyPatch,
    *,
    ec2: FakeEC2Client,
    table: FakeIncidentTable,
    sns: FakeSNSClient,
    s3: FakeS3Client | None = None,
) -> None:
    """Inject deterministic clients and deployment settings."""

    monkeypatch.setattr(handler, "EC2_CLIENT", ec2)
    monkeypatch.setattr(handler, "SNS_CLIENT", sns)
    monkeypatch.setattr(handler, "S3_CLIENT", s3 or FakeS3Client())
    monkeypatch.setattr(
        handler,
        "DYNAMODB_RESOURCE",
        FakeDynamoDBResource(table),
    )
    monkeypatch.setattr(
        handler,
        "INCIDENTS_TABLE_NAME",
        "cloud-ir-lab-incidents",
    )
    monkeypatch.setattr(
        handler,
        "INCIDENT_TOPIC_ARN",
        "arn:aws:sns:us-east-1:111122223333:synthetic-topic",
    )
    monkeypatch.setattr(
        handler,
        "EVIDENCE_BUCKET_NAME",
        EVIDENCE_BUCKET,
    )
    monkeypatch.setattr(handler, "TARGET_INSTANCE_ID", INSTANCE_ID)
    monkeypatch.setattr(
        handler,
        "BASELINE_SECURITY_GROUP_ID",
        BASELINE_SG_ID,
    )
    monkeypatch.setattr(
        handler,
        "QUARANTINE_SECURITY_GROUP_ID",
        QUARANTINE_SG_ID,
    )


def test_eligible_finding_is_contained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An authorized target is moved from baseline to quarantine."""

    operations: list[str] = []
    ec2 = FakeEC2Client(build_ec2_response(), operations=operations)
    table = FakeIncidentTable()
    sns = FakeSNSClient()
    s3 = FakeS3Client(operations=operations)
    configure_handler(
        monkeypatch,
        ec2=ec2,
        table=table,
        sns=sns,
        s3=s3,
    )

    result = handler.lambda_handler(build_triage_result(), context=None)

    assert result["status"] == "contained"
    assert result["changed"] is True
    assert result["security_group_ids_before"] == [BASELINE_SG_ID]
    assert result["security_group_ids_after"] == [QUARANTINE_SG_ID]
    assert result["evidence"] == {
        "bucket": EVIDENCE_BUCKET,
        "key": (
            "incidents/sample-guardduty-compute-hijacking/"
            "pre-containment.json"
        ),
        "sha256": hashlib.sha256(s3.body or b"").hexdigest(),
        "checksum_sha256": s3.put_calls[0]["ChecksumSHA256"],
        "version_id": "synthetic-version-1",
        "status": "created",
    }
    assert operations[:3] == [
        "s3:PutObject",
        "s3:GetObject",
        "ec2:ModifyInstanceAttribute",
    ]
    assert s3.put_calls[0]["IfNoneMatch"] == "*"
    assert s3.put_calls[0]["ChecksumAlgorithm"] == "SHA256"
    assert s3.put_calls[0]["ServerSideEncryption"] == "AES256"
    evidence_document = json.loads((s3.body or b"").decode("utf-8"))
    assert evidence_document["evidence_type"] == "pre-containment"
    assert evidence_document["incident"]["id"] == result["incident_id"]
    assert evidence_document["instance"]["security_group_ids"] == [
        BASELINE_SG_ID
    ]
    assert evidence_document["instance"]["tags"][
        "IncidentStatus"
    ] == "clean"
    assert ec2.modify_calls == [
        {
            "InstanceId": INSTANCE_ID,
            "Groups": [QUARANTINE_SG_ID],
        }
    ]
    assert ec2.tag_calls == [
        {
            "Resources": [INSTANCE_ID],
            "Tags": [
                {
                    "Key": "IncidentStatus",
                    "Value": "contained",
                }
            ],
        }
    ]
    assert len(table.update_calls) == 3
    evidence_values = table.update_calls[1][
        "ExpressionAttributeValues"
    ]
    assert evidence_values[":evidence_key"] == result["evidence"]["key"]
    assert evidence_values[":evidence_sha256"] == result["evidence"][
        "sha256"
    ]
    assert len(sns.publish_calls) == 1


def test_ineligible_triage_result_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A denied triage result must not access AWS mutation clients."""

    ec2 = FakeEC2Client(build_ec2_response())
    table = FakeIncidentTable()
    sns = FakeSNSClient()
    configure_handler(
        monkeypatch,
        ec2=ec2,
        table=table,
        sns=sns,
    )

    result = handler.lambda_handler(
        build_triage_result(eligible=False),
        context=None,
    )

    assert result["status"] == "skipped"
    assert result["changed"] is False
    assert result["reasons"] == ["severity_below_threshold"]
    assert ec2.describe_calls == []
    assert ec2.modify_calls == []
    assert table.update_calls == []
    assert sns.publish_calls == []


def test_non_allowlisted_target_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An eligible event cannot redirect mutation to another instance."""

    ec2 = FakeEC2Client(build_ec2_response())
    table = FakeIncidentTable()
    sns = FakeSNSClient()
    configure_handler(
        monkeypatch,
        ec2=ec2,
        table=table,
        sns=sns,
    )

    with pytest.raises(
        handler.ContainmentBlockedError,
        match="target_instance_not_allowlisted",
    ):
        handler.lambda_handler(
            build_triage_result(instance_id="i-0aaaaaaaaaaaaaaaa"),
            context=None,
        )

    assert ec2.describe_calls == []
    assert ec2.modify_calls == []
    assert table.update_calls == []


def test_revoked_authorization_tag_blocks_containment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Authorization is re-read instead of trusting the triage snapshot."""

    ec2 = FakeEC2Client(
        build_ec2_response(auto_containment="false")
    )
    table = FakeIncidentTable()
    sns = FakeSNSClient()
    configure_handler(
        monkeypatch,
        ec2=ec2,
        table=table,
        sns=sns,
    )

    with pytest.raises(
        handler.ContainmentBlockedError,
        match="auto_containment_tag_not_authorized",
    ):
        handler.lambda_handler(build_triage_result(), context=None)

    assert ec2.modify_calls == []
    assert table.update_calls == []
    assert sns.publish_calls == []


def test_unexpected_security_group_blocks_containment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Containment refuses to overwrite an unknown network state."""

    ec2 = FakeEC2Client(
        build_ec2_response(
            security_group_id="sg-09999999999999999"
        )
    )
    table = FakeIncidentTable()
    sns = FakeSNSClient()
    configure_handler(
        monkeypatch,
        ec2=ec2,
        table=table,
        sns=sns,
    )

    with pytest.raises(
        handler.ContainmentBlockedError,
        match="unexpected_security_group_state",
    ):
        handler.lambda_handler(build_triage_result(), context=None)

    assert ec2.modify_calls == []
    assert table.update_calls == []


def test_completed_duplicate_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A completed duplicate does not mutate or notify again."""

    ec2 = FakeEC2Client(
        build_ec2_response(security_group_id=QUARANTINE_SG_ID)
    )
    table = FakeIncidentTable(
        existing_item={
            "incident_id": "sample-guardduty-compute-hijacking",
            "status": "contained",
        }
    )
    sns = FakeSNSClient()
    configure_handler(
        monkeypatch,
        ec2=ec2,
        table=table,
        sns=sns,
    )

    result = handler.lambda_handler(build_triage_result(), context=None)

    assert result["status"] == "already_contained"
    assert result["idempotent"] is True
    assert ec2.modify_calls == []
    assert ec2.tag_calls == []
    assert len(table.get_calls) == 1
    assert sns.publish_calls == []


def test_multiple_network_interfaces_block_containment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The chosen EC2 mutation API is limited to the single-ENI lab."""

    ec2 = FakeEC2Client(
        build_ec2_response(network_interface_count=2)
    )
    table = FakeIncidentTable()
    sns = FakeSNSClient()
    configure_handler(
        monkeypatch,
        ec2=ec2,
        table=table,
        sns=sns,
    )

    with pytest.raises(
        handler.ContainmentBlockedError,
        match="unsupported_network_interface_count",
    ):
        handler.lambda_handler(build_triage_result(), context=None)

    assert ec2.modify_calls == []
    assert table.update_calls == []


def test_notification_failure_marks_incident_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retryable downstream failure is recorded in the ledger."""

    ec2 = FakeEC2Client(build_ec2_response())
    table = FakeIncidentTable()
    sns = FakeSNSClient(fail=True)
    configure_handler(
        monkeypatch,
        ec2=ec2,
        table=table,
        sns=sns,
    )

    with pytest.raises(ClientError):
        handler.lambda_handler(build_triage_result(), context=None)

    assert len(ec2.modify_calls) == 1
    assert len(sns.publish_calls) == 1
    assert len(table.update_calls) == 3
    assert ":failed" in (
        table.update_calls[-1]["ExpressionAttributeValues"]
    )


def test_evidence_failure_blocks_ec2_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S3 evidence failure is fail-closed before any EC2 mutation."""

    ec2 = FakeEC2Client(build_ec2_response())
    table = FakeIncidentTable()
    sns = FakeSNSClient()
    s3 = FakeS3Client(fail_put=True)
    configure_handler(
        monkeypatch,
        ec2=ec2,
        table=table,
        sns=sns,
        s3=s3,
    )

    with pytest.raises(ClientError):
        handler.lambda_handler(build_triage_result(), context=None)

    assert len(s3.put_calls) == 1
    assert s3.get_calls == []
    assert ec2.modify_calls == []
    assert ec2.tag_calls == []
    assert sns.publish_calls == []
    assert len(table.update_calls) == 2
    assert table.update_calls[-1]["ExpressionAttributeValues"][
        ":failed"
    ] == "failed"


def test_failed_retry_reuses_verified_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed incident retry reads its exact S3 version without overwrite."""

    event = build_triage_result()
    ec2 = FakeEC2Client(build_ec2_response())
    snapshot = {
        "architecture": "x86_64",
        "availability_zone": "us-east-1a",
        "iam_instance_profile_arn": None,
        "image_id": "ami-0123456789abcdef0",
        "instance_id": INSTANCE_ID,
        "instance_type": "t3.micro",
        "launch_time": None,
        "state": "running",
        "private_ip_address": "10.0.1.10",
        "root_device_name": "/dev/xvda",
        "security_group_ids": [BASELINE_SG_ID],
        "subnet_id": "subnet-0123456789abcdef0",
        "network_interface_ids": ["eni-00000000000000000"],
        "tags": {
            "AutoContainment": "true",
            "IncidentStatus": "clean",
            "DataClassification": "synthetic",
        },
        "vpc_id": "vpc-0123456789abcdef0",
    }
    evidence_document = handler._build_precontainment_evidence(
        event=event,
        incident_id=event["incident_id"],
        instance=snapshot,
        collected_at="2026-09-15T00:00:00+00:00",
    )
    evidence_body = handler._canonical_json_bytes(evidence_document)
    evidence_sha256 = hashlib.sha256(evidence_body).hexdigest()
    evidence_key = (
        "incidents/sample-guardduty-compute-hijacking/"
        "pre-containment.json"
    )
    table = FakeIncidentTable(
        existing_item={
            "incident_id": event["incident_id"],
            "status": "failed",
            "evidence_bucket": EVIDENCE_BUCKET,
            "evidence_key": evidence_key,
            "evidence_sha256": evidence_sha256,
            "evidence_version_id": "synthetic-version-1",
        }
    )
    sns = FakeSNSClient()
    s3 = FakeS3Client(existing_body=evidence_body)
    configure_handler(
        monkeypatch,
        ec2=ec2,
        table=table,
        sns=sns,
        s3=s3,
    )

    result = handler.lambda_handler(event, context=None)

    assert result["status"] == "contained"
    assert result["evidence"]["status"] == "reused"
    assert result["evidence"]["version_id"] == "synthetic-version-1"
    assert s3.put_calls == []
    assert len(s3.get_calls) == 1
    assert s3.get_calls[0]["VersionId"] == "synthetic-version-1"
    assert len(ec2.modify_calls) == 1


def test_evidence_checksum_failure_blocks_ec2_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A checksum mismatch aborts before quarantine or notification."""

    ec2 = FakeEC2Client(build_ec2_response())
    table = FakeIncidentTable()
    sns = FakeSNSClient()
    s3 = FakeS3Client(corrupt_read=True)
    configure_handler(
        monkeypatch,
        ec2=ec2,
        table=table,
        sns=sns,
        s3=s3,
    )

    with pytest.raises(
        RuntimeError,
        match="Stored evidence SHA-256 verification failed",
    ):
        handler.lambda_handler(build_triage_result(), context=None)

    assert len(s3.put_calls) == 1
    assert len(s3.get_calls) == 1
    assert ec2.modify_calls == []
    assert ec2.tag_calls == []
    assert sns.publish_calls == []
    assert len(table.update_calls) == 2


def test_retry_recovers_evidence_written_before_ledger_update(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retry can bind a valid object left by a partial prior attempt."""

    event = build_triage_result()
    snapshot = {
        "instance_id": INSTANCE_ID,
        "state": "running",
        "security_group_ids": [BASELINE_SG_ID],
        "network_interface_ids": ["eni-00000000000000000"],
        "tags": {
            "AutoContainment": "true",
            "IncidentStatus": "clean",
            "DataClassification": "synthetic",
        },
    }
    document = handler._build_precontainment_evidence(
        event=event,
        incident_id=event["incident_id"],
        instance=snapshot,
        collected_at="2026-09-15T00:00:00+00:00",
    )
    s3 = FakeS3Client(
        existing_body=handler._canonical_json_bytes(document)
    )
    ec2 = FakeEC2Client(build_ec2_response())
    table = FakeIncidentTable(
        existing_item={
            "incident_id": event["incident_id"],
            "status": "failed",
        }
    )
    sns = FakeSNSClient()
    configure_handler(
        monkeypatch,
        ec2=ec2,
        table=table,
        sns=sns,
        s3=s3,
    )

    result = handler.lambda_handler(event, context=None)

    assert result["status"] == "contained"
    assert result["evidence"]["status"] == "reused"
    assert len(s3.put_calls) == 1
    assert len(s3.get_calls) == 1
    assert "VersionId" not in s3.get_calls[0]
    assert len(ec2.modify_calls) == 1
