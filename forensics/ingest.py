from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction

from .models import DumpUpload, ForensicsMessage, ForensicsSnapshot, Incident, UploadToken

FORENSICS_SCHEMA_VERSION = "marmot-forensics/v1"


@dataclass(frozen=True)
class IngestionResult:
    upload: DumpUpload
    created: bool


def ingest_dump_bytes(
    *,
    incident: Incident,
    dump_bytes: bytes,
    upload_token: UploadToken | None = None,
    uploaded_by=None,
    source_ip: str | None = None,
    user_agent: str = "",
) -> IngestionResult:
    try:
        raw_text = dump_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError("Dump must be UTF-8 JSON.") from exc

    try:
        bundle = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"Dump must be valid JSON: {exc.msg}") from exc

    if not isinstance(bundle, dict):
        raise ValidationError("Dump root must be a JSON object.")

    normalized = normalize_bundle(bundle)
    raw_sha256 = hashlib.sha256(dump_bytes).hexdigest()

    try:
        with transaction.atomic():
            upload = DumpUpload.objects.create(
                incident=incident,
                upload_token=upload_token,
                uploaded_by=uploaded_by,
                raw_sha256=raw_sha256,
                raw_text=raw_text,
                raw_json=bundle,
                source_ip=source_ip,
                user_agent=user_agent[:5000],
                **normalized["upload"],
            )
            ForensicsMessage.objects.bulk_create(
                ForensicsMessage(dump=upload, **message)
                for message in normalized["messages"]
            )
            ForensicsSnapshot.objects.bulk_create(
                ForensicsSnapshot(dump=upload, **snapshot)
                for snapshot in normalized["snapshots"]
            )
            return IngestionResult(upload=upload, created=True)
    except IntegrityError:
        upload = DumpUpload.objects.get(incident=incident, raw_sha256=raw_sha256)
        return IngestionResult(upload=upload, created=False)


def normalize_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    schema_version = require_str(bundle, "schema_version")
    if schema_version != FORENSICS_SCHEMA_VERSION:
        raise ValidationError(
            f"Unsupported forensics schema {schema_version!r}; expected {FORENSICS_SCHEMA_VERSION}."
        )

    mode = require_str(bundle, "mode")
    if mode not in {DumpUpload.MODE_PUBLIC, DumpUpload.MODE_SENSITIVE}:
        raise ValidationError("Dump mode must be 'public' or 'sensitive'.")

    producer = require_object(bundle, "producer")
    account = require_object(bundle, "account")
    group = require_object(bundle, "group")
    messages = require_list(bundle, "messages")
    snapshots = require_list(bundle, "snapshots")

    upload = {
        "schema_version": schema_version,
        "mode": mode,
        "redaction_salt_id": optional_str(bundle, "redaction_salt_id"),
        "exported_at_ms": require_int(bundle, "exported_at_ms"),
        "producer_name": require_str(producer, "name"),
        "producer_version": require_str(producer, "version"),
        "account_ref": require_str(account, "account_ref"),
        "account_id": require_str(account, "account_id"),
        "group_id": require_str(group, "group_id"),
        "epoch": require_int(group, "epoch"),
        "member_count": require_int(group, "member_count"),
        "required_app_components": optional_list(group, "required_app_components"),
        "admins": optional_list(group, "admins"),
        "relays": optional_list(group, "relays"),
        "nostr_group_id": optional_str(group, "nostr_group_id"),
        "warnings": optional_list(bundle, "warnings"),
    }

    return {
        "upload": upload,
        "messages": [normalize_message(message, idx) for idx, message in enumerate(messages)],
        "snapshots": [normalize_snapshot(snapshot, idx) for idx, snapshot in enumerate(snapshots)],
    }


def normalize_message(message: Any, idx: int) -> dict[str, Any]:
    if not isinstance(message, dict):
        raise ValidationError(f"messages[{idx}] must be an object.")
    openmls = message.get("openmls")
    if openmls is not None and not isinstance(openmls, dict):
        raise ValidationError(f"messages[{idx}].openmls must be an object when present.")

    return {
        "message_id": require_str(message, "message_id", prefix=f"messages[{idx}]"),
        "group_id": require_str(message, "group_id", prefix=f"messages[{idx}]"),
        "epoch": require_int(message, "epoch", prefix=f"messages[{idx}]"),
        "state": require_str(message, "state", prefix=f"messages[{idx}]"),
        "payload_kind": require_str(message, "payload_kind", prefix=f"messages[{idx}]"),
        "envelope_kind": require_str(message, "envelope_kind", prefix=f"messages[{idx}]"),
        "timestamp": require_int(message, "timestamp", prefix=f"messages[{idx}]"),
        "payload_len": require_int(message, "payload_len", prefix=f"messages[{idx}]"),
        "payload_digest": require_str(message, "payload_digest", prefix=f"messages[{idx}]"),
        "has_payload_hex": isinstance(message.get("payload_hex"), str),
        "openmls_content_kind": optional_str(openmls or {}, "content_kind"),
        "openmls_source_epoch": optional_int(openmls or {}, "source_epoch"),
        "openmls_message_digest": optional_str(openmls or {}, "message_digest"),
    }


def normalize_snapshot(snapshot: Any, idx: int) -> dict[str, Any]:
    if not isinstance(snapshot, dict):
        raise ValidationError(f"snapshots[{idx}] must be an object.")
    return {"name": require_str(snapshot, "name", prefix=f"snapshots[{idx}]")}


def require_object(obj: dict[str, Any], key: str) -> dict[str, Any]:
    value = obj.get(key)
    if not isinstance(value, dict):
        raise ValidationError(f"{key} must be an object.")
    return value


def require_list(obj: dict[str, Any], key: str) -> list[Any]:
    value = obj.get(key)
    if not isinstance(value, list):
        raise ValidationError(f"{key} must be a list.")
    return value


def optional_list(obj: dict[str, Any], key: str) -> list[Any]:
    value = obj.get(key, [])
    if not isinstance(value, list):
        raise ValidationError(f"{key} must be a list when present.")
    return value


def require_str(obj: dict[str, Any], key: str, *, prefix: str | None = None) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        name = f"{prefix}.{key}" if prefix else key
        raise ValidationError(f"{name} must be a non-empty string.")
    return value


def optional_str(obj: dict[str, Any], key: str) -> str:
    value = obj.get(key)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValidationError(f"{key} must be a string when present.")
    return value


def require_int(obj: dict[str, Any], key: str, *, prefix: str | None = None) -> int:
    value = obj.get(key)
    if not isinstance(value, int) or value < 0:
        name = f"{prefix}.{key}" if prefix else key
        raise ValidationError(f"{name} must be a non-negative integer.")
    return value


def optional_int(obj: dict[str, Any], key: str) -> int | None:
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, int) or value < 0:
        raise ValidationError(f"{key} must be a non-negative integer when present.")
    return value
