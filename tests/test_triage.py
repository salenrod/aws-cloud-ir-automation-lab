"""Unit tests for the GuardDuty triage Lambda."""

from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest


os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")

from src.triage import handler  # noqa: E402


EVENT_PATH = (
    Path(__file__).resolve().parents[1]
    / "events"
    / "guardduty-crypto-ec2.json"
)


class FakeEC2Client:
    """Read-only fake for EC2 DescribeInstances."""

    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        self.requested_instance_ids: list[str] = []

    def describe_instances(
        self,
        *,
        InstanceIds: list[str],
    ) -> dict[str, Any]:
        self.requested_instance_ids = InstanceIds
        return deepcopy(self.response)


@pytest.fixture
def guardduty_event() -> dict[str, Any]:
    """Load a new synthetic EventBridge event for every test."""

    return json.loads(EVENT_PATH.read_text(encoding="utf-8"))


def build_ec2_response(
    *,
    auto_containment: str = "true",
    state: str = "running",
) -> dict[str, Any]:
    """Build a synthetic DescribeInstances response."""

    return {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-0123456789abcdef0",
                        "InstanceType": "t3.micro",
                        "State": {
                            "Name": state,
                        },
                        "PrivateIpAddress": "10.50.10.25",
                        "VpcId": "vpc-0123456789abcdef0",
                        "SubnetId": "subnet-0123456789abcdef0",
                        "SecurityGroups": [
                            {
                                "GroupId": "sg-0123456789abcdef0",
                                "GroupName": "cloud-ir-lab-baseline-sg",
                            }
                        ],
                        "BlockDeviceMappings": [
                            {
                                "DeviceName": "/dev/xvda",
                                "Ebs": {
                                    "VolumeId": "vol-0123456789abcdef0",
                                },
                            }
                        ],
                        "Tags": [
                            {
                                "Key": "Name",
                                "Value": "cloud-ir-lab-target",
                            },
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


def test_authorized_high_severity_finding_is_eligible(
    monkeypatch: pytest.MonkeyPatch,
    guardduty_event: dict[str, Any],
) -> None:
    """High severity plus authorization tag must permit containment."""

    fake_ec2 = FakeEC2Client(build_ec2_response())

    monkeypatch.setattr(
        handler,
        "EC2_CLIENT",
        fake_ec2,
    )

    result = handler.lambda_handler(
        guardduty_event,
        context=None,
    )

    assert result["incident_id"] == (
        "sample-guardduty-compute-hijacking"
    )
    assert result["finding"]["severity"] == 8.0
    assert result["resource"]["type"] == "Instance"
    assert result["instance"]["state"] == "running"
    assert result["instance"]["private_ip"] == "10.50.10.25"

    assert result["decision"]["containment_eligible"] is True
    assert result["decision"]["reasons"] == []

    assert result["mitre_attack"] == {
        "technique_id": "T1496.001",
        "technique_name": "Compute Hijacking",
        "tactic": "Impact",
    }

    assert fake_ec2.requested_instance_ids == [
        "i-0123456789abcdef0"
    ]


def test_low_severity_finding_is_not_eligible(
    monkeypatch: pytest.MonkeyPatch,
    guardduty_event: dict[str, Any],
) -> None:
    """Findings below the configured threshold must not contain."""

    guardduty_event["detail"]["severity"] = 4.0

    monkeypatch.setattr(
        handler,
        "EC2_CLIENT",
        FakeEC2Client(build_ec2_response()),
    )

    result = handler.lambda_handler(
        guardduty_event,
        context=None,
    )

    assert result["decision"]["containment_eligible"] is False
    assert "severity_below_threshold" in (
        result["decision"]["reasons"]
    )


def test_missing_authorization_tag_blocks_containment(
    monkeypatch: pytest.MonkeyPatch,
    guardduty_event: dict[str, Any],
) -> None:
    """A high-severity finding still requires explicit authorization."""

    monkeypatch.setattr(
        handler,
        "EC2_CLIENT",
        FakeEC2Client(
            build_ec2_response(auto_containment="false")
        ),
    )

    result = handler.lambda_handler(
        guardduty_event,
        context=None,
    )

    assert result["finding"]["severity"] == 8.0
    assert result["decision"]["containment_eligible"] is False
    assert "auto_containment_tag_not_authorized" in (
        result["decision"]["reasons"]
    )


def test_unsupported_instance_state_blocks_containment(
    monkeypatch: pytest.MonkeyPatch,
    guardduty_event: dict[str, Any],
) -> None:
    """Terminated instances must not enter containment actions."""

    monkeypatch.setattr(
        handler,
        "EC2_CLIENT",
        FakeEC2Client(build_ec2_response(state="terminated")),
    )

    result = handler.lambda_handler(
        guardduty_event,
        context=None,
    )

    assert result["decision"]["containment_eligible"] is False
    assert "unsupported_instance_state" in (
        result["decision"]["reasons"]
    )


def test_malformed_finding_is_rejected() -> None:
    """Invalid events must fail instead of silently continuing."""

    with pytest.raises(
        ValueError,
        match="missing required fields",
    ):
        handler.lambda_handler(
            {
                "detail": {
                    "id": "incomplete-finding",
                }
            },
            context=None,
        )