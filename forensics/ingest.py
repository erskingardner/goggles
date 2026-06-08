from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from django.db import IntegrityError, transaction
from django.template.defaultfilters import slugify
from django.utils import timezone

from .models import AuditEvent, AuditFile, AuditGroup, UploadToken

AUDIT_SCHEMA_VERSION = "marmot-forensics-audit/v1"
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


@dataclass(frozen=True)
class IngestionResult:
    audit_file: AuditFile
    created: bool


@dataclass
class ParsedLine:
    line_number: int
    raw_line: str
    line_hash: str
    data: dict[str, Any] | None
    normalized: dict[str, Any]
    errors: list[str]


def first_group_ref_from_audit_log_bytes(dump_bytes: bytes) -> str | None:
    try:
        raw_text = dump_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None

    for raw_line in raw_text.splitlines():
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            loaded = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        if not isinstance(loaded, dict):
            continue
        group_ref = loaded.get("group_ref")
        if is_hex(group_ref, even=True):
            return group_ref
    return None


def ingest_audit_log_bytes(
    *,
    dump_bytes: bytes,
    fallback_group_slug: str | None = None,
    fallback_group_name: str = "",
    upload_token: UploadToken | None = None,
    uploaded_by=None,
    source_ip: str | None = None,
    user_agent: str = "",
    source_name: str = "",
    source_account_label: str = "",
    source_device_label: str = "",
    source_platform: str = "",
    source_app_version: str = "",
    content_type: str = "",
) -> IngestionResult:
    try:
        raw_text = dump_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raw_text = dump_bytes.decode("utf-8", errors="replace")
        return save_invalid_upload(
            fallback_group_slug=fallback_group_slug,
            fallback_group_name=fallback_group_name,
            upload_token=upload_token,
            uploaded_by=uploaded_by,
            source_ip=source_ip,
            user_agent=user_agent,
            source_name=source_name,
            source_account_label=source_account_label,
            source_device_label=source_device_label,
            source_platform=source_platform,
            source_app_version=source_app_version,
            content_type=content_type,
            dump_bytes=dump_bytes,
            raw_text=raw_text,
            error=f"Audit log must be UTF-8 JSONL: {exc}.",
        )

    file_sha256 = hashlib.sha256(dump_bytes).hexdigest()
    existing = AuditFile.objects.filter(file_sha256=file_sha256).first()
    if existing is not None:
        return IngestionResult(audit_file=existing, created=False)

    parsed_lines = parse_jsonl(raw_text)
    metadata = file_metadata(parsed_lines)
    validation_errors = [
        f"line {line.line_number}: {'; '.join(line.errors)}"
        for line in parsed_lines
        if line.errors
    ]
    if not parsed_lines:
        validation_errors = ["audit log has no non-empty JSONL lines"]
    else:
        validation_errors.extend(file_validation_errors(parsed_lines))

    validation_status = (
        AuditFile.STATUS_INVALID if validation_errors else AuditFile.STATUS_VALID
    )
    validation_error = "\n".join(validation_errors)

    try:
        with transaction.atomic():
            audit_file = AuditFile.objects.create(
                upload_token=upload_token,
                uploaded_by=uploaded_by,
                source_name=source_name[:255],
                source_account_label=source_account_label[:255],
                source_device_label=source_device_label[:255],
                source_platform=source_platform[:120],
                source_app_version=source_app_version[:120],
                content_type=content_type[:120],
                file_sha256=file_sha256,
                byte_size=len(dump_bytes),
                raw_text=raw_text,
                validation_status=validation_status,
                validation_error=validation_error,
                source_ip=source_ip,
                user_agent=user_agent[:5000],
                **metadata,
            )
            duplicate_count, group_ids = create_events(
                audit_file,
                parsed_lines,
                fallback_group_slug=fallback_group_slug,
                fallback_group_name=fallback_group_name,
            )
            if duplicate_count:
                audit_file.duplicate_event_count = duplicate_count
                audit_file.save(update_fields=["duplicate_event_count"])
            for group_id in group_ids:
                AuditGroup.objects.filter(id=group_id).update(updated_at=timezone.now())
            return IngestionResult(audit_file=audit_file, created=True)
    except IntegrityError:
        audit_file = AuditFile.objects.get(file_sha256=file_sha256)
        return IngestionResult(audit_file=audit_file, created=False)


def save_invalid_upload(
    *,
    fallback_group_slug: str | None,
    fallback_group_name: str,
    upload_token: UploadToken | None,
    uploaded_by,
    source_ip: str | None,
    user_agent: str,
    source_name: str,
    source_account_label: str,
    source_device_label: str,
    source_platform: str,
    source_app_version: str,
    content_type: str,
    dump_bytes: bytes,
    raw_text: str,
    error: str,
) -> IngestionResult:
    file_sha256 = hashlib.sha256(dump_bytes).hexdigest()
    existing = AuditFile.objects.filter(file_sha256=file_sha256).first()
    if existing is not None:
        return IngestionResult(audit_file=existing, created=False)
    fallback_group = group_for_slug(fallback_group_slug, fallback_group_name)
    with transaction.atomic():
        audit_file = AuditFile.objects.create(
            upload_token=upload_token,
            uploaded_by=uploaded_by,
            source_name=source_name[:255],
            source_account_label=source_account_label[:255],
            source_device_label=source_device_label[:255],
            source_platform=source_platform[:120],
            source_app_version=source_app_version[:120],
            content_type=content_type[:120],
            file_sha256=file_sha256,
            byte_size=len(dump_bytes),
            raw_text=raw_text,
            validation_status=AuditFile.STATUS_INVALID,
            validation_error=error,
            total_line_count=1,
            invalid_event_count=1,
            source_ip=source_ip,
            user_agent=user_agent[:5000],
        )
        AuditEvent.objects.create(
            group=fallback_group,
            audit_file=audit_file,
            line_number=1,
            line_hash=hashlib.sha256(raw_text.encode("utf-8", errors="replace")).hexdigest(),
            raw_line=raw_text,
            parse_status=AuditEvent.STATUS_INVALID,
            validation_error=error,
        )
        if fallback_group is not None:
            AuditGroup.objects.filter(id=fallback_group.id).update(updated_at=timezone.now())
    return IngestionResult(audit_file=audit_file, created=True)


def parse_jsonl(raw_text: str) -> list[ParsedLine]:
    parsed_lines = []
    for line_number, raw_line in enumerate(raw_text.splitlines(), start=1):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        data = None
        errors = []
        try:
            loaded = json.loads(raw_line)
            if not isinstance(loaded, dict):
                errors.append("line must be a JSON object")
            else:
                data = loaded
        except json.JSONDecodeError as exc:
            errors.append(f"invalid JSON: {exc.msg}")

        normalized: dict[str, Any] = {}
        if data is not None:
            normalized, validation_errors = normalize_event(data)
            errors.extend(validation_errors)

        parsed_lines.append(
            ParsedLine(
                line_number=line_number,
                raw_line=raw_line,
                line_hash=hashlib.sha256(raw_line.encode("utf-8")).hexdigest(),
                data=data,
                normalized=normalized,
                errors=errors,
            )
        )
    return parsed_lines


def normalize_event(data: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    normalized: dict[str, Any] = {
        "schema_version": value_if_str(data.get("schema_version")),
        "seq": value_if_int(data.get("seq")),
        "wall_time_ms": value_if_int(data.get("wall_time_ms")),
        "account_ref": (
            value_if_str(data.get("account_ref"))
            if data.get("account_ref") is not None
            else ""
        ),
        "engine_id": value_if_str(data.get("engine_id")),
        "group_ref": (
            value_if_str(data.get("group_ref"))
            if data.get("group_ref") is not None
            else ""
        ),
    }

    if normalized["schema_version"] != AUDIT_SCHEMA_VERSION:
        errors.append(
            "unsupported schema_version "
            f"{data.get('schema_version')!r}; expected {AUDIT_SCHEMA_VERSION}"
        )
    if normalized["seq"] is None:
        errors.append("seq must be a non-negative integer")
    if normalized["wall_time_ms"] is None:
        errors.append("wall_time_ms must be a non-negative integer")
    if normalized["account_ref"] and not is_hex(
        normalized["account_ref"], exact_len=32
    ):
        errors.append("account_ref must be 32 hex characters when present")
    if not is_hex(normalized["engine_id"], exact_len=32):
        errors.append("engine_id must be 32 hex characters")
    if normalized["group_ref"] and not is_hex(normalized["group_ref"], even=True):
        errors.append("group_ref must be even-length hex when present")

    kind = data.get("kind")
    if not isinstance(kind, dict):
        errors.append("kind must be an object")
        return normalized, errors

    event_type = value_if_str(kind.get("type"))
    normalized["raw_kind"] = kind
    normalized["event_type"] = event_type
    if not event_type:
        errors.append("kind.type must be a non-empty string")
        return normalized, errors

    variant_errors = normalize_kind(event_type, kind, normalized)
    errors.extend(variant_errors)
    return normalized, errors


def normalize_kind(event_type: str, kind: dict[str, Any], normalized: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    match event_type:
        case "ingest_entry":
            copy_msg_id(kind, normalized, errors)
            copy_str(kind, normalized, errors, "envelope_kind")
            copy_int(kind, normalized, errors, "payload_len")
            copy_digest(kind, normalized, errors, "payload_digest")
        case "ingest_outcome":
            copy_msg_id(kind, normalized, errors)
            copy_str(kind, normalized, errors, "outcome_kind")
            copy_optional_str(kind, normalized, errors, "stale_reason")
            copy_optional_int(kind, normalized, errors, "epoch")
        case "send_entry":
            copy_str(kind, normalized, errors, "intent_kind")
        case "send_outcome":
            copy_str(kind, normalized, errors, "intent_kind")
            copy_str(kind, normalized, errors, "result_kind")
            copy_optional_msg_id(kind, normalized, errors, "outbound_msg_id")
            welcome_ids = kind.get("outbound_welcome_msg_ids", [])
            if not isinstance(welcome_ids, list) or any(
                not is_hex(item, even=True) for item in welcome_ids
            ):
                errors.append("outbound_welcome_msg_ids must be a list of hex strings")
            else:
                normalized["outbound_welcome_msg_ids"] = welcome_ids
        case "epoch_confirmed":
            copy_int(kind, normalized, errors, "from_epoch")
            copy_int(kind, normalized, errors, "to_epoch")
            copy_str(kind, normalized, errors, "pending_kind")
        case "epoch_rolled_back":
            copy_int(kind, normalized, errors, "pending_epoch")
            copy_int(kind, normalized, errors, "restored_epoch")
            copy_str(kind, normalized, errors, "pending_kind")
        case "snapshot_created":
            copy_str(kind, normalized, errors, "snapshot_name")
            copy_int(kind, normalized, errors, "source_epoch")
            copy_str(kind, normalized, errors, "reason")
        case "fork_resolution":
            copy_int(kind, normalized, errors, "source_epoch")
            copy_digest(kind, normalized, errors, "candidate_digest")
            copy_optional_digest(kind, normalized, errors, "incumbent_digest")
            copy_str(kind, normalized, errors, "winner")
            if normalized.get("winner") not in {"candidate", "incumbent", "missing_snapshot"}:
                errors.append("winner must be candidate, incumbent, or missing_snapshot")
            copy_optional_msg_id(kind, normalized, errors, "invalidated_msg_id")
        case "convergence_decision":
            copy_int(kind, normalized, errors, "current_tip_epoch")
            copy_int(kind, normalized, errors, "candidate_count")
            copy_int(kind, normalized, errors, "eligible_count")
            copy_int(kind, normalized, errors, "max_rewind_commits")
            copy_optional_str(kind, normalized, errors, "selected_branch_id")
            copy_optional_int(kind, normalized, errors, "selected_fork_epoch")
            copy_optional_int(kind, normalized, errors, "selected_tip_epoch")
        case "peeler_outcome":
            copy_msg_id(kind, normalized, errors)
            copy_str(kind, normalized, errors, "outcome")
            if normalized.get("outcome") not in {
                "success",
                "decrypt_failed",
                "stale_epoch",
                "malformed",
                "other",
            }:
                errors.append("outcome must be a known peeler outcome")
            fallback = kind.get("fallback_snapshot_used")
            if not isinstance(fallback, bool):
                errors.append("fallback_snapshot_used must be a boolean")
            else:
                normalized["fallback_snapshot_used"] = fallback
            copy_optional_str(kind, normalized, errors, "detail")
        case "auto_commit_decision":
            copy_str(kind, normalized, errors, "proposal_kind")
            copy_str(kind, normalized, errors, "decision")
            copy_optional_str(kind, normalized, errors, "reason")
        case "message_state_changed":
            copy_msg_id(kind, normalized, errors)
            copy_str(kind, normalized, errors, "new_state")
            copy_str(kind, normalized, errors, "reason")
        case "rejection":
            copy_msg_id(kind, normalized, errors)
            copy_str(kind, normalized, errors, "reason")
        case _:
            errors.append(f"unknown kind.type {event_type!r}")
    return errors


def create_events(
    audit_file: AuditFile,
    parsed_lines: list[ParsedLine],
    *,
    fallback_group_slug: str | None,
    fallback_group_name: str,
) -> tuple[int, set[int]]:
    duplicate_count = 0
    group_ids: set[int] = set()
    for parsed in parsed_lines:
        group = group_for_parsed_line(
            parsed,
            fallback_group_slug=fallback_group_slug,
            fallback_group_name=fallback_group_name,
        )
        if group is not None:
            group_ids.add(group.id)
        if duplicate_event_exists(
            parsed,
            ignore_invalid_files=audit_file.validation_status == AuditFile.STATUS_VALID,
        ):
            duplicate_count += 1
            continue
        values = event_values(audit_file, parsed, group)
        AuditEvent.objects.create(**values)
    return duplicate_count, group_ids


def duplicate_event_exists(parsed: ParsedLine, *, ignore_invalid_files: bool) -> bool:
    filters = {"line_hash": parsed.line_hash}
    engine_id = parsed.normalized.get("engine_id")
    if engine_id:
        filters["engine_id"] = engine_id
    if ignore_invalid_files:
        filters["audit_file__validation_status"] = AuditFile.STATUS_VALID
    return AuditEvent.objects.filter(**filters).exists()


def group_for_parsed_line(
    parsed: ParsedLine,
    *,
    fallback_group_slug: str | None,
    fallback_group_name: str,
) -> AuditGroup | None:
    group_ref = parsed.normalized.get("group_ref") or ""
    if is_hex(group_ref, even=True):
        return group_for_ref(group_ref)
    return group_for_slug(fallback_group_slug, fallback_group_name)


def group_for_ref(group_ref: str) -> AuditGroup:
    slug = slugify(group_ref)[:160] or "incoming"
    group, created = AuditGroup.objects.get_or_create(
        slug=slug,
        defaults={
            "name": f"Group {group_ref[:12]}",
            "group_ref": group_ref,
        },
    )
    if group_ref and not group.group_ref:
        group.group_ref = group_ref
        group.save(update_fields=["group_ref"])
    elif created:
        group.save(update_fields=["updated_at"])
    return group


def group_for_slug(slug: str | None, name: str = "") -> AuditGroup | None:
    if not slug:
        return None
    group, _created = AuditGroup.objects.get_or_create(
        slug=slug,
        defaults={"name": name or group_name_from_slug(slug), "group_ref": ""},
    )
    return group


def group_name_from_slug(slug: str) -> str:
    return slug.replace("-", " ").strip().title() or "Incoming"


def event_values(
    audit_file: AuditFile,
    parsed: ParsedLine,
    group: AuditGroup | None,
) -> dict[str, Any]:
    values = {
        "group": group,
        "audit_file": audit_file,
        "line_number": parsed.line_number,
        "line_hash": parsed.line_hash,
        "raw_line": parsed.raw_line,
        "raw_event": parsed.data,
        "parse_status": AuditEvent.STATUS_INVALID if parsed.errors else AuditEvent.STATUS_VALID,
        "validation_error": "; ".join(parsed.errors),
    }
    if parsed.data is not None:
        values.update(
            {
                "raw_kind": parsed.normalized.get("raw_kind") or {},
                "schema_version": parsed.normalized.get("schema_version") or "",
                "seq": parsed.normalized.get("seq"),
                "wall_time_ms": parsed.normalized.get("wall_time_ms"),
                "account_ref": parsed.normalized.get("account_ref") or "",
                "engine_id": parsed.normalized.get("engine_id") or "",
                "group_ref": parsed.normalized.get("group_ref") or "",
                "event_type": parsed.normalized.get("event_type") or "",
            }
        )
        for field in normalized_fields():
            if field in parsed.normalized:
                values[field] = parsed.normalized[field]
    return values


def file_metadata(parsed_lines: list[ParsedLine]) -> dict[str, Any]:
    valid_lines = [line for line in parsed_lines if not line.errors]
    all_line_numbers = [line.line_number for line in parsed_lines]
    seqs = [
        line.normalized.get("seq")
        for line in valid_lines
        if line.normalized.get("seq") is not None
    ]
    wall_times = [
        line.normalized.get("wall_time_ms")
        for line in valid_lines
        if line.normalized.get("wall_time_ms") is not None
    ]
    engine_ids = sorted(
        {
            line.normalized.get("engine_id")
            for line in valid_lines
            if line.normalized.get("engine_id")
        }
    )
    account_refs = sorted(
        {
            line.normalized.get("account_ref")
            for line in valid_lines
            if line.normalized.get("account_ref")
        }
    )
    group_refs = sorted(
        {
            line.normalized.get("group_ref")
            for line in valid_lines
            if line.normalized.get("group_ref")
        }
    )
    schema_versions = sorted(
        {
            line.normalized.get("schema_version")
            for line in parsed_lines
            if line.normalized.get("schema_version")
        }
    )
    return {
        "total_line_count": len(parsed_lines),
        "valid_event_count": len(valid_lines),
        "invalid_event_count": len(parsed_lines) - len(valid_lines),
        "first_line_number": min(all_line_numbers) if all_line_numbers else None,
        "last_line_number": max(all_line_numbers) if all_line_numbers else None,
        "first_seq": min(seqs) if seqs else None,
        "last_seq": max(seqs) if seqs else None,
        "first_wall_time_ms": min(wall_times) if wall_times else None,
        "last_wall_time_ms": max(wall_times) if wall_times else None,
        "account_refs": account_refs,
        "engine_ids": engine_ids,
        "group_refs": group_refs,
        "schema_versions": schema_versions,
    }


def file_validation_errors(parsed_lines: list[ParsedLine]) -> list[str]:
    errors = []
    engine_ids = sorted(
        {
            line.normalized.get("engine_id")
            for line in parsed_lines
            if is_hex(line.normalized.get("engine_id"), exact_len=32)
        }
    )
    if len(engine_ids) > 1:
        errors.append(
            "audit log contains multiple engine_ids; expected one engine per file: "
            + ", ".join(engine_ids)
        )
    account_refs = sorted(
        {
            line.normalized.get("account_ref")
            for line in parsed_lines
            if is_hex(line.normalized.get("account_ref"), exact_len=32)
        }
    )
    if len(account_refs) > 1:
        errors.append(
            "audit log contains multiple account_refs; expected one account per file: "
            + ", ".join(account_refs)
        )
    return errors


def normalized_fields() -> tuple[str, ...]:
    return (
        "msg_id",
        "outbound_msg_id",
        "outbound_welcome_msg_ids",
        "epoch",
        "source_epoch",
        "from_epoch",
        "to_epoch",
        "pending_epoch",
        "restored_epoch",
        "current_tip_epoch",
        "selected_fork_epoch",
        "selected_tip_epoch",
        "payload_len",
        "payload_digest",
        "candidate_digest",
        "incumbent_digest",
        "envelope_kind",
        "outcome",
        "outcome_kind",
        "stale_reason",
        "decision",
        "reason",
        "winner",
        "new_state",
        "pending_kind",
        "intent_kind",
        "result_kind",
        "proposal_kind",
        "snapshot_name",
        "selected_branch_id",
        "detail",
        "fallback_snapshot_used",
        "invalidated_msg_id",
        "max_rewind_commits",
        "candidate_count",
        "eligible_count",
    )


def copy_msg_id(kind: dict[str, Any], normalized: dict[str, Any], errors: list[str]) -> None:
    copy_msg_field(kind, normalized, errors, "msg_id", required=True)


def copy_optional_msg_id(
    kind: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
    field: str,
) -> None:
    copy_msg_field(kind, normalized, errors, field, required=False)


def copy_msg_field(
    kind: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
    field: str,
    *,
    required: bool,
) -> None:
    value = kind.get(field)
    if value is None:
        if required:
            errors.append(f"{field} is required")
        return
    if not is_hex(value, even=True):
        errors.append(f"{field} must be even-length hex")
        return
    normalized[field] = value


def copy_digest(
    kind: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
    field: str,
) -> None:
    value = kind.get(field)
    if not is_hex(value, exact_len=64):
        errors.append(f"{field} must be 64 hex characters")
        return
    normalized[field] = value


def copy_optional_digest(
    kind: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
    field: str,
) -> None:
    value = kind.get(field)
    if value is None:
        return
    if not is_hex(value, exact_len=64):
        errors.append(f"{field} must be 64 hex characters")
        return
    normalized[field] = value


def copy_str(
    kind: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
    field: str,
) -> None:
    value = value_if_str(kind.get(field))
    if not value:
        errors.append(f"{field} must be a non-empty string")
        return
    normalized[field] = value


def copy_optional_str(
    kind: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
    field: str,
) -> None:
    value = kind.get(field)
    if value is None:
        return
    if not isinstance(value, str):
        errors.append(f"{field} must be a string when present")
        return
    normalized[field] = value


def copy_int(
    kind: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
    field: str,
) -> None:
    value = value_if_int(kind.get(field))
    if value is None:
        errors.append(f"{field} must be a non-negative integer")
        return
    normalized[field] = value


def copy_optional_int(
    kind: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
    field: str,
) -> None:
    if kind.get(field) is None:
        return
    value = value_if_int(kind.get(field))
    if value is None:
        errors.append(f"{field} must be a non-negative integer when present")
        return
    normalized[field] = value


def value_if_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def value_if_int(value: Any) -> int | None:
    return value if isinstance(value, int) and value >= 0 else None


def is_hex(value: Any, *, exact_len: int | None = None, even: bool = False) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if exact_len is not None and len(value) != exact_len:
        return False
    if even and len(value) % 2:
        return False
    return HEX_RE.fullmatch(value) is not None
