"""Controlled and idempotent EC2 containment Lambda."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import boto3
from botocore.exceptions import ClientError


LOGGER = logging.getLogger()
LOGGER.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())

EC2_CLIENT = boto3.client("ec2")
SNS_CLIENT = boto3.client("sns")
S3_CLIENT = boto3.client("s3")
DYNAMODB_RESOURCE = boto3.resource("dynamodb")

INCIDENTS_TABLE_NAME = os.getenv("INCIDENTS_TABLE_NAME", "")
INCIDENT_TOPIC_ARN = os.getenv("INCIDENT_TOPIC_ARN", "")
EVIDENCE_BUCKET_NAME = os.getenv("EVIDENCE_BUCKET_NAME", "")
TARGET_INSTANCE_ID = os.getenv("TARGET_INSTANCE_ID", "")
BASELINE_SECURITY_GROUP_ID = os.getenv("BASELINE_SECURITY_GROUP_ID", "")
QUARANTINE_SECURITY_GROUP_ID = os.getenv("QUARANTINE_SECURITY_GROUP_ID", "")
REQUIRED_DATA_CLASSIFICATION = os.getenv(
    "REQUIRED_DATA_CLASSIFICATION",
    "synthetic",
)

INCIDENT_RETENTION_SECONDS = int(
    os.getenv("INCIDENT_RETENTION_SECONDS", "604800")
)
PROCESSING_LEASE_SECONDS = int(
    os.getenv("PROCESSING_LEASE_SECONDS", "60")
)

SUPPORTED_INSTANCE_STATES = {
    "running",
    "stopped",
}


class ContainmentBlockedError(ValueError):
    """Raised when a containment safety precondition is not satisfied."""


def _log_event(event_name: str, **fields: Any) -> None:
    """Write a structured log without dumping the raw finding."""

    LOGGER.info(
        json.dumps(
            {
                "event": event_name,
                **fields,
            },
            default=str,
            sort_keys=True,
        )
    )


def _utc_now() -> str:
    """Return an RFC 3339-compatible UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


def _epoch_now() -> int:
    """Return the current epoch time in whole seconds."""

    return int(time.time())


def _execution_id(context: Any) -> str:
    """Return the Lambda request ID or a local fallback identifier."""

    request_id = getattr(context, "aws_request_id", None)
    return str(request_id or uuid.uuid4())


def _validate_configuration() -> None:
    """Fail closed when a required deployment setting is absent."""

    settings = {
        "INCIDENTS_TABLE_NAME": INCIDENTS_TABLE_NAME,
        "INCIDENT_TOPIC_ARN": INCIDENT_TOPIC_ARN,
        "EVIDENCE_BUCKET_NAME": EVIDENCE_BUCKET_NAME,
        "TARGET_INSTANCE_ID": TARGET_INSTANCE_ID,
        "BASELINE_SECURITY_GROUP_ID": BASELINE_SECURITY_GROUP_ID,
        "QUARANTINE_SECURITY_GROUP_ID": QUARANTINE_SECURITY_GROUP_ID,
    }

    missing = [
        name
        for name, value in settings.items()
        if not str(value).strip()
    ]

    if missing:
        raise RuntimeError(
            "Missing containment configuration: " + ", ".join(missing)
        )

    if BASELINE_SECURITY_GROUP_ID == QUARANTINE_SECURITY_GROUP_ID:
        raise RuntimeError(
            "Baseline and quarantine security groups must be different."
        )


def _extract_request(
    event: dict[str, Any],
) -> tuple[str, str | None, bool, list[str]]:
    """Extract the contract produced by the triage Lambda."""

    if not isinstance(event, dict):
        raise ValueError("Containment event must be a JSON object.")

    incident_id = str(event.get("incident_id", "")).strip()
    if not incident_id:
        raise ValueError("Containment event is missing incident_id.")

    decision = event.get("decision")
    if not isinstance(decision, dict):
        raise ValueError("Containment event is missing decision.")

    reasons_value = decision.get("reasons", [])
    reasons = (
        [str(reason) for reason in reasons_value]
        if isinstance(reasons_value, list)
        else []
    )

    eligible = decision.get("containment_eligible") is True

    resource = event.get("resource")
    if not isinstance(resource, dict):
        raise ValueError("Containment event is missing resource.")

    resource_type = str(resource.get("type", ""))
    instance_id_value = resource.get("instance_id")
    instance_id = (
        str(instance_id_value).strip()
        if instance_id_value is not None
        else None
    )

    if eligible and resource_type != "Instance":
        raise ContainmentBlockedError(
            "Containment blocked: unsupported_resource_type"
        )

    if eligible and not instance_id:
        raise ContainmentBlockedError(
            "Containment blocked: missing_instance_id"
        )

    return incident_id, instance_id, eligible, reasons


def _describe_instance(instance_id: str) -> dict[str, Any]:
    """Read the current instance state immediately before containment."""

    response = EC2_CLIENT.describe_instances(
        InstanceIds=[instance_id],
    )

    instances = [
        instance
        for reservation in response.get("Reservations", [])
        for instance in reservation.get("Instances", [])
    ]

    if len(instances) != 1:
        raise ContainmentBlockedError(
            "Containment blocked: instance_not_found"
        )

    instance = instances[0]
    tags = {
        tag["Key"]: tag["Value"]
        for tag in instance.get("Tags", [])
        if "Key" in tag and "Value" in tag
    }
    security_group_ids = sorted(
        group["GroupId"]
        for group in instance.get("SecurityGroups", [])
        if group.get("GroupId")
    )
    network_interface_ids = [
        interface["NetworkInterfaceId"]
        for interface in instance.get("NetworkInterfaces", [])
        if interface.get("NetworkInterfaceId")
    ]

    launch_time = instance.get("LaunchTime")
    if hasattr(launch_time, "isoformat"):
        launch_time = launch_time.isoformat()

    placement = instance.get("Placement", {})
    iam_instance_profile = instance.get("IamInstanceProfile", {})

    return {
        "architecture": instance.get("Architecture"),
        "availability_zone": placement.get("AvailabilityZone"),
        "iam_instance_profile_arn": iam_instance_profile.get("Arn"),
        "image_id": instance.get("ImageId"),
        "instance_id": instance.get("InstanceId"),
        "instance_type": instance.get("InstanceType"),
        "launch_time": launch_time,
        "state": instance.get("State", {}).get("Name"),
        "private_ip_address": instance.get("PrivateIpAddress"),
        "root_device_name": instance.get("RootDeviceName"),
        "security_group_ids": security_group_ids,
        "subnet_id": instance.get("SubnetId"),
        "network_interface_ids": network_interface_ids,
        "tags": tags,
        "vpc_id": instance.get("VpcId"),
    }


def _evidence_key(incident_id: str) -> str:
    """Return a deterministic S3 key without accepting path separators."""

    encoded_incident_id = quote(incident_id, safe="-_.")
    if len(encoded_incident_id) > 180:
        suffix = hashlib.sha256(incident_id.encode("utf-8")).hexdigest()
        encoded_incident_id = f"{encoded_incident_id[:120]}-{suffix[:32]}"

    return f"incidents/{encoded_incident_id}/pre-containment.json"


def _build_precontainment_evidence(
    *,
    event: dict[str, Any],
    incident_id: str,
    instance: dict[str, Any],
    collected_at: str,
) -> dict[str, Any]:
    """Build the minimal incident record captured before EC2 mutation."""

    finding = event.get("finding", {})
    resource = event.get("resource", {})
    decision = event.get("decision", {})
    mitre_attack = event.get("mitre_attack", {})

    return {
        "schema_version": "1.0",
        "evidence_type": "pre-containment",
        "collected_at": collected_at,
        "incident": {
            "id": incident_id,
        },
        "finding": {
            "account_id": finding.get("account_id"),
            "created_at": finding.get("created_at"),
            "description": finding.get("description"),
            "id": finding.get("id"),
            "region": finding.get("region"),
            "title": finding.get("title"),
            "type": finding.get("type"),
            "severity": finding.get("severity"),
            "updated_at": finding.get("updated_at"),
        },
        "decision": {
            "containment_eligible": (
                decision.get("containment_eligible") is True
            ),
            "minimum_severity": decision.get("minimum_severity"),
            "reasons": decision.get("reasons", []),
        },
        "mitre_attack": {
            "technique_id": mitre_attack.get("technique_id"),
            "technique_name": mitre_attack.get("technique_name"),
            "tactic": mitre_attack.get("tactic"),
        },
        "resource": {
            "type": resource.get("type"),
            "instance_id": resource.get("instance_id"),
        },
        "instance": instance,
    }


def _canonical_json_bytes(document: dict[str, Any]) -> bytes:
    """Serialize evidence deterministically for checksum verification."""

    return json.dumps(
        document,
        default=str,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _read_and_verify_evidence(
    *,
    bucket: str,
    key: str,
    expected_sha256: str,
    version_id: str | None,
    status: str,
) -> dict[str, str]:
    """Read one exact evidence version and verify both checksums."""

    arguments: dict[str, Any] = {
        "Bucket": bucket,
        "Key": key,
        "ChecksumMode": "ENABLED",
    }
    if version_id:
        arguments["VersionId"] = version_id

    response = S3_CLIENT.get_object(**arguments)
    body = response["Body"].read()
    actual_sha256 = hashlib.sha256(body).hexdigest()
    expected_checksum = base64.b64encode(
        bytes.fromhex(expected_sha256)
    ).decode("ascii")
    returned_checksum = str(response.get("ChecksumSHA256", ""))
    returned_version_id = str(response.get("VersionId", "")).strip()

    if actual_sha256 != expected_sha256:
        raise RuntimeError("Stored evidence SHA-256 verification failed.")

    if returned_checksum != expected_checksum:
        raise RuntimeError("S3 evidence checksum verification failed.")

    if version_id and returned_version_id != version_id:
        raise RuntimeError("S3 evidence version verification failed.")

    if not returned_version_id:
        raise RuntimeError("S3 evidence version identifier is missing.")

    return {
        "bucket": bucket,
        "key": key,
        "sha256": expected_sha256,
        "checksum_sha256": expected_checksum,
        "version_id": returned_version_id,
        "status": status,
    }


def _previous_evidence_reference(
    item: dict[str, Any] | None,
) -> dict[str, str] | None:
    """Extract a complete evidence reference from a ledger item."""

    if not isinstance(item, dict):
        return None

    reference = {
        "bucket": str(item.get("evidence_bucket", "")).strip(),
        "key": str(item.get("evidence_key", "")).strip(),
        "sha256": str(item.get("evidence_sha256", "")).strip(),
        "version_id": str(item.get("evidence_version_id", "")).strip(),
    }

    if not all(reference.values()):
        return None

    return reference


def _recover_unrecorded_evidence(
    *,
    bucket: str,
    key: str,
    incident_id: str,
    instance_id: str,
) -> dict[str, str]:
    """Verify an object created before its ledger update completed."""

    response = S3_CLIENT.get_object(
        Bucket=bucket,
        Key=key,
        ChecksumMode="ENABLED",
    )
    body = response["Body"].read()
    sha256 = hashlib.sha256(body).hexdigest()
    checksum_sha256 = base64.b64encode(
        bytes.fromhex(sha256)
    ).decode("ascii")
    returned_checksum = str(response.get("ChecksumSHA256", ""))
    version_id = str(response.get("VersionId", "")).strip()

    if returned_checksum != checksum_sha256:
        raise RuntimeError("Unrecorded S3 evidence checksum is invalid.")

    if not version_id:
        raise RuntimeError("Unrecorded S3 evidence version is missing.")

    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("Unrecorded S3 evidence is not valid JSON.") from error

    if (
        not isinstance(document, dict)
        or document.get("schema_version") != "1.0"
        or document.get("evidence_type") != "pre-containment"
        or document.get("incident", {}).get("id") != incident_id
        or document.get("resource", {}).get("instance_id") != instance_id
    ):
        raise RuntimeError("Unrecorded S3 evidence contract is invalid.")

    return {
        "bucket": bucket,
        "key": key,
        "sha256": sha256,
        "checksum_sha256": checksum_sha256,
        "version_id": version_id,
        "status": "reused",
    }


def _preserve_precontainment_evidence(
    *,
    event: dict[str, Any],
    incident_id: str,
    instance: dict[str, Any],
    previous_item: dict[str, Any] | None,
) -> dict[str, str]:
    """Create immutable pre-containment evidence or verify a retry."""

    previous_reference = _previous_evidence_reference(previous_item)
    if previous_reference is not None:
        if previous_reference["bucket"] != EVIDENCE_BUCKET_NAME:
            raise RuntimeError("Previous evidence bucket is unexpected.")

        if previous_reference["key"] != _evidence_key(incident_id):
            raise RuntimeError("Previous evidence key is unexpected.")

        return _read_and_verify_evidence(
            bucket=previous_reference["bucket"],
            key=previous_reference["key"],
            expected_sha256=previous_reference["sha256"],
            version_id=previous_reference["version_id"],
            status="reused",
        )

    document = _build_precontainment_evidence(
        event=event,
        incident_id=incident_id,
        instance=instance,
        collected_at=str(
            event.get("finding", {}).get("updated_at")
            or event.get("finding", {}).get("created_at")
            or _utc_now()
        ),
    )
    body = _canonical_json_bytes(document)
    sha256 = hashlib.sha256(body).hexdigest()
    checksum_sha256 = base64.b64encode(
        bytes.fromhex(sha256)
    ).decode("ascii")
    key = _evidence_key(incident_id)

    try:
        response = S3_CLIENT.put_object(
            Bucket=EVIDENCE_BUCKET_NAME,
            Key=key,
            Body=body,
            ChecksumAlgorithm="SHA256",
            ChecksumSHA256=checksum_sha256,
            ContentType="application/json",
            IfNoneMatch="*",
            Metadata={
                "evidence-type": "pre-containment",
                "sha256": sha256,
            },
            ServerSideEncryption="AES256",
        )
        if response.get("ChecksumSHA256") != checksum_sha256:
            raise RuntimeError("S3 put evidence checksum verification failed.")

        version_id = str(response.get("VersionId", "")).strip()
        if not version_id:
            raise RuntimeError("S3 put evidence version identifier is missing.")

        status = "created"
    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code")
        if error_code not in {
            "ConditionalRequestConflict",
            "PreconditionFailed",
        }:
            raise
        return _recover_unrecorded_evidence(
            bucket=EVIDENCE_BUCKET_NAME,
            key=key,
            incident_id=incident_id,
            instance_id=str(instance.get("instance_id", "")),
        )

    return _read_and_verify_evidence(
        bucket=EVIDENCE_BUCKET_NAME,
        key=key,
        expected_sha256=sha256,
        version_id=version_id,
        status=status,
    )


def _validate_instance(
    instance: dict[str, Any],
    instance_id: str,
) -> bool:
    """Revalidate all mutation guardrails and return quarantine state."""

    reasons: list[str] = []

    if instance_id != TARGET_INSTANCE_ID:
        reasons.append("target_instance_not_allowlisted")

    if instance.get("instance_id") != TARGET_INSTANCE_ID:
        reasons.append("described_instance_does_not_match_target")

    if instance.get("state") not in SUPPORTED_INSTANCE_STATES:
        reasons.append("unsupported_instance_state")

    tags = instance.get("tags", {})
    if str(tags.get("AutoContainment", "")).lower() != "true":
        reasons.append("auto_containment_tag_not_authorized")

    if tags.get("DataClassification") != REQUIRED_DATA_CLASSIFICATION:
        reasons.append("unexpected_data_classification")

    network_interface_ids = instance.get("network_interface_ids", [])
    if len(network_interface_ids) != 1:
        reasons.append("unsupported_network_interface_count")

    security_group_ids = instance.get("security_group_ids", [])
    baseline_groups = [BASELINE_SECURITY_GROUP_ID]
    quarantine_groups = [QUARANTINE_SECURITY_GROUP_ID]

    already_quarantined = security_group_ids == quarantine_groups
    has_expected_baseline = security_group_ids == baseline_groups

    if not already_quarantined and not has_expected_baseline:
        reasons.append("unexpected_security_group_state")

    if reasons:
        raise ContainmentBlockedError(
            "Containment blocked: " + ", ".join(reasons)
        )

    return already_quarantined


def _claim_incident(
    *,
    table: Any,
    event: dict[str, Any],
    incident_id: str,
    instance_id: str,
    owner_token: str,
) -> tuple[bool, dict[str, Any] | None]:
    """Acquire a processing lease or return the existing incident."""

    now_epoch = _epoch_now()
    now_text = _utc_now()
    finding = event.get("finding", {})
    mitre_attack = event.get("mitre_attack", {})

    try:
        response = table.update_item(
            Key={"incident_id": incident_id},
            UpdateExpression=(
                "SET #status = :processing, "
                "owner_token = :owner_token, "
                "lease_until = :lease_until, "
                "updated_at = :updated_at, "
                "created_at = if_not_exists(created_at, :created_at), "
                "expires_at = :expires_at, "
                "instance_id = :instance_id, "
                "finding_type = :finding_type, "
                "severity = :severity, "
                "mitre_technique = :mitre_technique"
            ),
            ConditionExpression=(
                "attribute_not_exists(incident_id) "
                "OR #status = :failed "
                "OR (#status = :processing AND lease_until < :now)"
            ),
            ExpressionAttributeNames={
                "#status": "status",
            },
            ExpressionAttributeValues={
                ":processing": "processing",
                ":failed": "failed",
                ":owner_token": owner_token,
                ":lease_until": now_epoch + PROCESSING_LEASE_SECONDS,
                ":now": now_epoch,
                ":updated_at": now_text,
                ":created_at": now_text,
                ":expires_at": now_epoch + INCIDENT_RETENTION_SECONDS,
                ":instance_id": instance_id,
                ":finding_type": str(finding.get("type", "Unknown")),
                ":severity": str(finding.get("severity", "0")),
                ":mitre_technique": str(
                    mitre_attack.get("technique_id") or "Unmapped"
                ),
            },
            ReturnValues="ALL_OLD",
        )
        previous_item = response.get("Attributes")
        return (
            True,
            previous_item if isinstance(previous_item, dict) else None,
        )
    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code")
        if error_code != "ConditionalCheckFailedException":
            raise

    response = table.get_item(
        Key={"incident_id": incident_id},
        ConsistentRead=True,
    )
    existing_item = response.get("Item")

    if not isinstance(existing_item, dict):
        raise RuntimeError(
            "Incident lease was rejected but no existing item was found."
        )

    return False, existing_item


def _record_evidence_reference(
    *,
    table: Any,
    incident_id: str,
    owner_token: str,
    evidence: dict[str, str],
) -> None:
    """Attach the verified S3 evidence reference to the incident ledger."""

    table.update_item(
        Key={"incident_id": incident_id},
        UpdateExpression=(
            "SET updated_at = :updated_at, "
            "evidence_bucket = :evidence_bucket, "
            "evidence_key = :evidence_key, "
            "evidence_sha256 = :evidence_sha256, "
            "evidence_checksum_sha256 = :evidence_checksum_sha256, "
            "evidence_version_id = :evidence_version_id, "
            "evidence_status = :evidence_status"
        ),
        ConditionExpression=(
            "owner_token = :owner_token AND #status = :processing"
        ),
        ExpressionAttributeNames={
            "#status": "status",
        },
        ExpressionAttributeValues={
            ":updated_at": _utc_now(),
            ":evidence_bucket": evidence["bucket"],
            ":evidence_key": evidence["key"],
            ":evidence_sha256": evidence["sha256"],
            ":evidence_checksum_sha256": evidence[
                "checksum_sha256"
            ],
            ":evidence_version_id": evidence["version_id"],
            ":evidence_status": evidence["status"],
            ":owner_token": owner_token,
            ":processing": "processing",
        },
    )


def _mark_failed(
    *,
    table: Any,
    incident_id: str,
    owner_token: str,
    error: Exception,
) -> None:
    """Record a recoverable failed state without hiding the root error."""

    try:
        table.update_item(
            Key={"incident_id": incident_id},
            UpdateExpression=(
                "SET #status = :failed, "
                "updated_at = :updated_at, "
                "failure_type = :failure_type REMOVE lease_until"
            ),
            ConditionExpression="owner_token = :owner_token",
            ExpressionAttributeNames={
                "#status": "status",
            },
            ExpressionAttributeValues={
                ":failed": "failed",
                ":updated_at": _utc_now(),
                ":failure_type": type(error).__name__,
                ":owner_token": owner_token,
            },
        )
    except ClientError:
        _log_event(
            "incident_failure_record_failed",
            incident_id=incident_id,
        )


def _finalize_incident(
    *,
    table: Any,
    incident_id: str,
    owner_token: str,
    changed: bool,
    security_group_ids_before: list[str],
) -> str:
    """Commit the completed containment state to the incident ledger."""

    completed_at = _utc_now()

    table.update_item(
        Key={"incident_id": incident_id},
        UpdateExpression=(
            "SET #status = :contained, "
            "updated_at = :updated_at, "
            "contained_at = :contained_at, "
            "containment_changed_resource = :changed, "
            "security_group_ids_before = :security_group_ids_before, "
            "security_group_ids_after = :security_group_ids_after "
            "REMOVE lease_until"
        ),
        ConditionExpression=(
            "owner_token = :owner_token AND #status = :processing"
        ),
        ExpressionAttributeNames={
            "#status": "status",
        },
        ExpressionAttributeValues={
            ":contained": "contained",
            ":processing": "processing",
            ":updated_at": completed_at,
            ":contained_at": completed_at,
            ":changed": changed,
            ":security_group_ids_before": security_group_ids_before,
            ":security_group_ids_after": [
                QUARANTINE_SECURITY_GROUP_ID
            ],
            ":owner_token": owner_token,
        },
    )

    return completed_at


def _publish_notification(
    *,
    event: dict[str, Any],
    incident_id: str,
    instance_id: str,
    changed: bool,
    evidence: dict[str, str],
) -> None:
    """Publish a compact notification without raw finding contents."""

    finding = event.get("finding", {})
    mitre_attack = event.get("mitre_attack", {})

    message = {
        "event": "containment_complete",
        "incident_id": incident_id,
        "instance_id": instance_id,
        "finding_type": finding.get("type"),
        "severity": finding.get("severity"),
        "mitre_technique": mitre_attack.get("technique_id"),
        "containment_changed_resource": changed,
        "security_group_state": "quarantine",
        "evidence": {
            "bucket": evidence["bucket"],
            "key": evidence["key"],
            "sha256": evidence["sha256"],
            "version_id": evidence["version_id"],
        },
    }

    SNS_CLIENT.publish(
        TopicArn=INCIDENT_TOPIC_ARN,
        Subject="Cloud IR Lab containment completed",
        Message=json.dumps(message, default=str, sort_keys=True),
    )


def lambda_handler(
    event: dict[str, Any],
    context: Any,
) -> dict[str, Any]:
    """Contain one explicitly authorized EC2 target."""

    incident_id, instance_id, eligible, decision_reasons = (
        _extract_request(event)
    )

    if not eligible:
        result = {
            "incident_id": incident_id,
            "instance_id": instance_id,
            "status": "skipped",
            "changed": False,
            "idempotent": True,
            "reasons": decision_reasons or ["triage_not_eligible"],
        }
        _log_event("containment_skipped", **result)
        return result

    _validate_configuration()
    assert instance_id is not None

    if instance_id != TARGET_INSTANCE_ID:
        raise ContainmentBlockedError(
            "Containment blocked: target_instance_not_allowlisted"
        )

    current_instance = _describe_instance(instance_id)
    already_quarantined = _validate_instance(
        current_instance,
        instance_id,
    )

    table = DYNAMODB_RESOURCE.Table(INCIDENTS_TABLE_NAME)
    owner_token = _execution_id(context)
    claimed, existing_item = _claim_incident(
        table=table,
        event=event,
        incident_id=incident_id,
        instance_id=instance_id,
        owner_token=owner_token,
    )

    if not claimed:
        existing_status = str(existing_item.get("status", ""))

        if existing_status == "contained" and already_quarantined:
            result = {
                "incident_id": incident_id,
                "instance_id": instance_id,
                "status": "already_contained",
                "changed": False,
                "idempotent": True,
                "security_group_ids": [
                    QUARANTINE_SECURITY_GROUP_ID
                ],
            }
            existing_evidence = _previous_evidence_reference(existing_item)
            if existing_evidence is not None:
                result["evidence"] = {
                    **existing_evidence,
                    "checksum_sha256": str(
                        existing_item.get(
                            "evidence_checksum_sha256",
                            "",
                        )
                    ),
                    "status": str(
                        existing_item.get("evidence_status", "preserved")
                    ),
                }
            _log_event("containment_idempotent", **result)
            return result

        if existing_status == "processing":
            result = {
                "incident_id": incident_id,
                "instance_id": instance_id,
                "status": "in_progress",
                "changed": False,
                "idempotent": True,
            }
            _log_event("containment_in_progress", **result)
            return result

        raise RuntimeError(
            "Existing incident state is inconsistent with the EC2 state."
        )

    security_group_ids_before = list(
        current_instance["security_group_ids"]
    )
    changed = not already_quarantined

    try:
        evidence = _preserve_precontainment_evidence(
            event=event,
            incident_id=incident_id,
            instance=current_instance,
            previous_item=existing_item,
        )
        _record_evidence_reference(
            table=table,
            incident_id=incident_id,
            owner_token=owner_token,
            evidence=evidence,
        )

        if changed:
            EC2_CLIENT.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[QUARANTINE_SECURITY_GROUP_ID],
            )

        verified_instance = _describe_instance(instance_id)
        if verified_instance["security_group_ids"] != [
            QUARANTINE_SECURITY_GROUP_ID
        ]:
            raise RuntimeError(
                "Quarantine security group verification failed."
            )

        EC2_CLIENT.create_tags(
            Resources=[instance_id],
            Tags=[
                {
                    "Key": "IncidentStatus",
                    "Value": "contained",
                }
            ],
        )

        _publish_notification(
            event=event,
            incident_id=incident_id,
            instance_id=instance_id,
            changed=changed,
            evidence=evidence,
        )

        contained_at = _finalize_incident(
            table=table,
            incident_id=incident_id,
            owner_token=owner_token,
            changed=changed,
            security_group_ids_before=security_group_ids_before,
        )
    except Exception as error:
        _mark_failed(
            table=table,
            incident_id=incident_id,
            owner_token=owner_token,
            error=error,
        )
        _log_event(
            "containment_failed",
            incident_id=incident_id,
            instance_id=instance_id,
            failure_type=type(error).__name__,
        )
        raise

    result = {
        "incident_id": incident_id,
        "instance_id": instance_id,
        "status": "contained",
        "changed": changed,
        "idempotent": False,
        "security_group_ids_before": security_group_ids_before,
        "security_group_ids_after": [
            QUARANTINE_SECURITY_GROUP_ID
        ],
        "notification_status": "published",
        "contained_at": contained_at,
        "evidence": evidence,
    }

    _log_event("containment_complete", **result)
    return result
