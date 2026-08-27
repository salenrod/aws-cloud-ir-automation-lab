"""GuardDuty finding triage and EC2 enrichment Lambda."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError


LOGGER = logging.getLogger()
LOGGER.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())

EC2_CLIENT = boto3.client("ec2")

MIN_SEVERITY = float(os.getenv("MIN_SEVERITY", "7.0"))
AUTO_CONTAINMENT_TAG = os.getenv(
    "AUTO_CONTAINMENT_TAG",
    "AutoContainment",
)
AUTO_CONTAINMENT_VALUE = os.getenv(
    "AUTO_CONTAINMENT_VALUE",
    "true",
).lower()

SUPPORTED_INSTANCE_STATES = {
    "running",
    "stopped",
}


def _log_event(event_name: str, **fields: Any) -> None:
    """Write a structured JSON log without dumping the raw finding."""

    payload = {
        "event": event_name,
        **fields,
    }

    LOGGER.info(json.dumps(payload, default=str, sort_keys=True))


def _extract_finding(event: dict[str, Any]) -> dict[str, Any]:
    """Accept an EventBridge event or a direct GuardDuty finding."""

    if not isinstance(event, dict):
        raise ValueError("Event must be a JSON object.")

    detail = event.get("detail", event)

    if not isinstance(detail, dict):
        raise ValueError("GuardDuty finding detail must be a JSON object.")

    required_fields = (
        "id",
        "type",
        "resource",
    )

    missing_fields = [
        field
        for field in required_fields
        if field not in detail
    ]

    if missing_fields:
        raise ValueError(
            "GuardDuty finding is missing required fields: "
            + ", ".join(missing_fields)
        )

    return detail


def _extract_instance_id(finding: dict[str, Any]) -> str | None:
    """Extract the affected EC2 instance ID from the finding."""

    resource = finding.get("resource", {})
    instance_details = resource.get("instanceDetails", {})

    instance_id = instance_details.get("instanceId")

    if not instance_id:
        return None

    return str(instance_id)


def _describe_instance(instance_id: str) -> dict[str, Any] | None:
    """Retrieve current EC2 state used by the containment guardrails."""

    try:
        response = EC2_CLIENT.describe_instances(
            InstanceIds=[instance_id],
        )
    except ClientError:
        _log_event(
            "ec2_enrichment_failed",
            instance_id=instance_id,
        )
        raise

    instances = [
        instance
        for reservation in response.get("Reservations", [])
        for instance in reservation.get("Instances", [])
    ]

    if len(instances) != 1:
        return None

    instance = instances[0]

    tags = {
        tag["Key"]: tag["Value"]
        for tag in instance.get("Tags", [])
        if "Key" in tag and "Value" in tag
    }

    selected_tag_names = (
        "Name",
        AUTO_CONTAINMENT_TAG,
        "IncidentStatus",
        "DataClassification",
    )

    selected_tags = {
        key: tags[key]
        for key in selected_tag_names
        if key in tags
    }

    security_group_ids = [
        security_group["GroupId"]
        for security_group in instance.get("SecurityGroups", [])
        if security_group.get("GroupId")
    ]

    volume_ids = [
        mapping["Ebs"]["VolumeId"]
        for mapping in instance.get("BlockDeviceMappings", [])
        if mapping.get("Ebs", {}).get("VolumeId")
    ]

    return {
        "instance_id": instance.get("InstanceId"),
        "instance_type": instance.get("InstanceType"),
        "state": instance.get("State", {}).get("Name"),
        "private_ip": instance.get("PrivateIpAddress"),
        "vpc_id": instance.get("VpcId"),
        "subnet_id": instance.get("SubnetId"),
        "security_group_ids": security_group_ids,
        "volume_ids": volume_ids,
        "tags": selected_tags,
    }


def _map_mitre(finding_type: str) -> dict[str, str | None]:
    """Map the laboratory cryptomining scenario to MITRE ATT&CK."""

    if finding_type.startswith("CryptoCurrency:EC2/"):
        return {
            "technique_id": "T1496.001",
            "technique_name": "Compute Hijacking",
            "tactic": "Impact",
        }

    return {
        "technique_id": None,
        "technique_name": "Unmapped",
        "tactic": None,
    }


def _evaluate_containment(
    *,
    severity: float,
    resource_type: str,
    instance: dict[str, Any] | None,
) -> tuple[bool, list[str]]:
    """Apply explicit containment guardrails."""

    reasons: list[str] = []

    if severity < MIN_SEVERITY:
        reasons.append("severity_below_threshold")

    if resource_type != "Instance":
        reasons.append("unsupported_resource_type")

    if instance is None:
        reasons.append("instance_not_found")
        return False, reasons

    instance_state = str(instance.get("state", ""))

    if instance_state not in SUPPORTED_INSTANCE_STATES:
        reasons.append("unsupported_instance_state")

    containment_tag_value = str(
        instance.get("tags", {}).get(AUTO_CONTAINMENT_TAG, "")
    ).lower()

    if containment_tag_value != AUTO_CONTAINMENT_VALUE:
        reasons.append("auto_containment_tag_not_authorized")

    return len(reasons) == 0, reasons


def lambda_handler(
    event: dict[str, Any],
    context: Any,
) -> dict[str, Any]:
    """Triage one GuardDuty finding and return normalized enrichment."""

    finding = _extract_finding(event)

    finding_id = str(finding["id"])
    finding_type = str(finding["type"])
    severity = float(finding.get("severity", 0.0))

    resource = finding.get("resource", {})
    resource_type = str(resource.get("resourceType", "Unknown"))
    instance_id = _extract_instance_id(finding)

    instance: dict[str, Any] | None = None

    if instance_id:
        instance = _describe_instance(instance_id)

    containment_eligible, decision_reasons = _evaluate_containment(
        severity=severity,
        resource_type=resource_type,
        instance=instance,
    )

    result = {
        "incident_id": finding_id,
        "finding": {
            "id": finding_id,
            "type": finding_type,
            "severity": severity,
            "title": finding.get("title", "Untitled GuardDuty finding"),
            "description": finding.get("description", ""),
            "account_id": finding.get("accountId"),
            "region": finding.get("region"),
            "created_at": finding.get("createdAt"),
            "updated_at": finding.get("updatedAt"),
        },
        "resource": {
            "type": resource_type,
            "instance_id": instance_id,
        },
        "instance": instance,
        "mitre_attack": _map_mitre(finding_type),
        "decision": {
            "containment_eligible": containment_eligible,
            "minimum_severity": MIN_SEVERITY,
            "reasons": decision_reasons,
        },
        "triaged_at": datetime.now(timezone.utc).isoformat(),
    }

    _log_event(
        "triage_complete",
        finding_id=finding_id,
        finding_type=finding_type,
        severity=severity,
        instance_id=instance_id,
        containment_eligible=containment_eligible,
        decision_reasons=decision_reasons,
    )

    return result