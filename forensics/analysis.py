from __future__ import annotations

from collections import defaultdict

from .models import AuditEvent, AuditFile


def audit_files_for_group(group):
    return (
        AuditFile.objects.filter(events__group=group)
        .prefetch_related("events__group")
        .distinct()
        .order_by("-created_at", "-id")
    )


def valid_events_for_group(group):
    return (
        AuditEvent.objects.filter(
            group=group,
            audit_file__validation_status=AuditFile.STATUS_VALID,
            parse_status=AuditEvent.STATUS_VALID,
        )
        .select_related("audit_file")
        .order_by(
            "wall_time_ms",
            "engine_id",
            "line_number",
            "id",
        )
    )


def group_summary(group, audit_files):
    events = list(valid_events_for_group(group))
    engine_ids = {event.engine_id for event in events if event.engine_id}
    group_refs = {event.group_ref for event in events if event.group_ref}
    msg_ids = message_ids_from_events(events)
    invalid_count = AuditEvent.objects.filter(
        group=group,
        parse_status=AuditEvent.STATUS_INVALID,
    ).count()
    return {
        "file_count": len(audit_files),
        "event_count": len(events),
        "invalid_event_count": invalid_count,
        "engine_count": len(engine_ids),
        "group_count": len(group_refs),
        "message_count": len(msg_ids),
    }


def file_rows_for_group(audit_files, group):
    return [
        {
            "id": audit_file.id,
            "source_name": audit_file.source_name or f"audit-file-{audit_file.id}",
            "source_label": source_label_for_file(audit_file),
            "source_account_label": audit_file.source_account_label,
            "source_device_label": audit_file.source_device_label,
            "source_platform": audit_file.source_platform,
            "validation_status": audit_file.validation_status,
            "total_line_count": audit_file.total_line_count,
            "valid_event_count": audit_file.valid_event_count,
            "invalid_event_count": audit_file.invalid_event_count,
            "duplicate_event_count": audit_file.duplicate_event_count,
            "group_event_count": audit_file.events.filter(group=group).count(),
            "account_refs": audit_file.account_refs,
            "engine_ids": audit_file.engine_ids,
            "group_refs": audit_file.group_refs,
            "created_at": audit_file.created_at,
        }
        for audit_file in audit_files
    ]


def timeline_by_engine(group):
    grouped = defaultdict(list)
    for event in valid_events_for_group(group):
        grouped[event.engine_id or "<missing engine>"].append(timeline_event(event))
    return [
        {
            "engine_id": engine_id,
            "account_ref": events[0].get("account_ref", "") if events else "",
            "source_label": events[0].get("source_label", "") if events else "",
            "events": events,
            "event_count": len(events),
        }
        for engine_id, events in sorted(grouped.items())
    ]


def timeline_event(event: AuditEvent):
    related_key = (
        event.msg_id or event.outbound_msg_id or event.candidate_digest or event.payload_digest
    )
    tone = "send" if event.event_type.startswith("send_") else "receive"
    if event.event_type in {"fork_resolution", "convergence_decision"}:
        tone = "fork"
    if event.event_type in {"peeler_outcome", "rejection"}:
        tone = "error"
    if event.event_type == "message_state_changed" and event.new_state in {
        "failed",
        "epoch_invalidated",
        "peel_deferred",
    }:
        tone = "error"
    return {
        "id": event.id,
        "line_number": event.line_number,
        "wall_time_ms": event.wall_time_ms,
        "seq": event.seq,
        "account_ref": event.account_ref,
        "engine_id": event.engine_id,
        "source_label": source_label_for_file(event.audit_file),
        "event_type": event.event_type,
        "group_ref": event.group_ref,
        "msg_id": event.msg_id or event.outbound_msg_id,
        "related_key": related_key,
        "tone": tone,
        "epoch": event_epoch(event),
        "summary": event_summary(event),
        "raw_kind": event.raw_kind,
    }


def message_traces_for_group(group):
    all_engines = engine_ids_for_group(group)
    by_msg = defaultdict(list)
    for event in valid_events_for_group(group):
        for msg_id in event_message_ids(event):
            by_msg[msg_id].append(event)

    traces = []
    for msg_id, events in sorted(by_msg.items()):
        engines = sorted({event.engine_id for event in events if event.engine_id})
        event_types = sorted({event.event_type for event in events if event.event_type})
        states = sorted(
            {
                value
                for event in events
                for value in (event.new_state, event.outcome, event.outcome_kind, event.reason)
                if value
            }
        )
        traces.append(
            {
                "msg_id": msg_id,
                "engines": engines,
                "missing_engines": sorted(all_engines - set(engines)),
                "event_types": event_types,
                "states": states,
                "first_wall_time_ms": min(
                    event.wall_time_ms for event in events if event.wall_time_ms is not None
                ),
                "last_wall_time_ms": max(
                    event.wall_time_ms for event in events if event.wall_time_ms is not None
                ),
                "event_count": len(events),
            }
        )
    return traces


def source_label_for_file(audit_file: AuditFile) -> str:
    parts = [
        audit_file.source_account_label,
        audit_file.source_device_label,
        audit_file.source_platform,
    ]
    return " / ".join(part for part in parts if part)


def missing_observations_for_group(group):
    return [
        trace
        for trace in message_traces_for_group(group)
        if trace["missing_engines"] and trace["engines"]
    ]


def fork_and_convergence_events(group):
    return [
        event_row(event)
        for event in valid_events_for_group(group).filter(
            event_type__in=[
                "fork_resolution",
                "convergence_decision",
                "epoch_confirmed",
                "epoch_rolled_back",
            ]
        )
    ]


def peeler_and_rejection_events(group):
    rows = []
    for event in valid_events_for_group(group).filter(
        event_type__in=["peeler_outcome", "rejection", "message_state_changed"]
    ):
        if event.event_type == "peeler_outcome" and (
            event.outcome != "success" or event.fallback_snapshot_used
        ):
            rows.append(event_row(event))
        elif event.event_type == "rejection":
            rows.append(event_row(event))
        elif event.event_type == "message_state_changed" and event.new_state in {
            "failed",
            "epoch_invalidated",
            "peel_deferred",
        }:
            rows.append(event_row(event))
    return rows


def event_row(event: AuditEvent):
    return {
        "id": event.id,
        "engine_id": event.engine_id,
        "account_ref": event.account_ref,
        "event_type": event.event_type,
        "wall_time_ms": event.wall_time_ms,
        "seq": event.seq,
        "group_ref": event.group_ref,
        "msg_id": event.msg_id or event.outbound_msg_id or event.invalidated_msg_id,
        "epoch": event_epoch(event),
        "digest": event.candidate_digest or event.payload_digest or event.incumbent_digest,
        "outcome": (
            event.outcome or event.outcome_kind or event.decision or event.winner or event.new_state
        ),
        "reason": event.reason or event.stale_reason or event.detail or event.pending_kind,
        "summary": event_summary(event),
    }


def event_summary(event: AuditEvent) -> str:
    if event.event_type == "fork_resolution":
        return f"{event.winner} at source epoch {event.source_epoch}"
    if event.event_type == "convergence_decision":
        return f"tip {event.current_tip_epoch} -> {event.selected_tip_epoch or '-'}"
    if event.event_type == "epoch_confirmed":
        return f"epoch {event.from_epoch} -> {event.to_epoch}"
    if event.event_type == "epoch_rolled_back":
        return f"rollback {event.pending_epoch} -> {event.restored_epoch}"
    if event.event_type == "peeler_outcome":
        fallback = " with snapshot fallback" if event.fallback_snapshot_used else ""
        return f"{event.outcome}{fallback}"
    if event.event_type == "message_state_changed":
        return f"{event.msg_id} -> {event.new_state}"
    if event.event_type == "ingest_outcome":
        return f"{event.outcome_kind} epoch {event.epoch or '-'}"
    if event.event_type == "send_outcome":
        return f"{event.intent_kind} -> {event.result_kind}"
    return event.event_type


def event_epoch(event: AuditEvent):
    return (
        event.epoch
        or event.source_epoch
        or event.to_epoch
        or event.pending_epoch
        or event.current_tip_epoch
        or event.selected_tip_epoch
    )


def event_message_ids(event: AuditEvent):
    ids = []
    for value in (event.msg_id, event.outbound_msg_id, event.invalidated_msg_id):
        if value:
            ids.append(value)
    ids.extend(event.outbound_welcome_msg_ids or [])
    return ids


def message_ids_from_events(events):
    ids = set()
    for event in events:
        ids.update(event_message_ids(event))
    return ids


def engine_ids_for_group(group):
    return {
        engine_id
        for engine_id in AuditEvent.objects.filter(
            group=group,
            audit_file__validation_status=AuditFile.STATUS_VALID,
            parse_status=AuditEvent.STATUS_VALID,
        )
        .exclude(engine_id="")
        .values_list("engine_id", flat=True)
        .distinct()
    }
