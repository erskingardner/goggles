from __future__ import annotations

from collections import defaultdict

from .models import DumpUpload, ForensicsMessage


def incident_summary(uploads):
    uploads = list(uploads)
    return {
        "upload_count": len(uploads),
        "group_count": len({upload.group_id for upload in uploads}),
        "account_count": len({upload.account_id for upload in uploads}),
        "message_count": sum(getattr(upload, "message_count", 0) for upload in uploads),
    }


def branch_conflicts_for_incident(incident):
    rows = (
        ForensicsMessage.objects.filter(
            dump__incident=incident,
            openmls_content_kind="commit",
            openmls_source_epoch__isnull=False,
        )
        .select_related("dump")
        .order_by("group_id", "openmls_source_epoch", "openmls_message_digest")
    )
    grouped = defaultdict(lambda: defaultdict(set))
    for row in rows:
        key = (row.group_id, row.openmls_source_epoch)
        grouped[key][row.openmls_message_digest].add(row.dump.account_id)

    conflicts = []
    for (group_id, source_epoch), digest_map in grouped.items():
        if len(digest_map) < 2:
            continue
        conflicts.append(
            {
                "group_id": group_id,
                "source_epoch": source_epoch,
                "digests": [
                    {"digest": digest, "observed_by": sorted(observed_by)}
                    for digest, observed_by in sorted(digest_map.items())
                ],
            }
        )
    return conflicts


def commit_observations_for_incident(incident):
    rows = (
        ForensicsMessage.objects.filter(
            dump__incident=incident,
            openmls_content_kind="commit",
            openmls_source_epoch__isnull=False,
        )
        .select_related("dump")
        .order_by("group_id", "openmls_source_epoch", "openmls_message_digest", "dump__account_id")
    )
    return [
        {
            "group_id": row.group_id,
            "source_epoch": row.openmls_source_epoch,
            "digest": row.openmls_message_digest,
            "account_id": row.dump.account_id,
            "dump_id": row.dump_id,
        }
        for row in rows
    ]


def uploads_for_incident(incident):
    return (
        DumpUpload.objects.filter(incident=incident)
        .prefetch_related("messages", "snapshots")
        .order_by("group_id", "account_id", "epoch")
    )
