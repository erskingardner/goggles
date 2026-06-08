from __future__ import annotations

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.http import HttpRequest, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.template.defaultfilters import slugify
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .analysis import (
    audit_files_for_group,
    file_rows_for_group,
    fork_and_convergence_events,
    group_summary,
    message_traces_for_group,
    missing_observations_for_group,
    peeler_and_rejection_events,
    timeline_by_engine,
)
from .ingest import ingest_audit_log_bytes
from .models import AuditFile, AuditGroup, UploadToken


@login_required
def group_list(request: HttpRequest):
    groups = AuditGroup.objects.annotate(
        audit_file_count=Count("audit_events__audit_file", distinct=True),
        event_count=Count("audit_events", distinct=True),
    )
    return render(request, "forensics/group_list.html", {"groups": groups})


@login_required
def group_detail(request: HttpRequest, slug: str):
    group = get_object_or_404(AuditGroup, slug=slug)
    audit_files = list(audit_files_for_group(group))
    return render(
        request,
        "forensics/group_detail.html",
        {
            "group": group,
            "summary": group_summary(group, audit_files),
            "audit_files": file_rows_for_group(audit_files, group),
            "timeline_lanes": timeline_by_engine(group),
            "message_traces": message_traces_for_group(group),
            "missing_observations": missing_observations_for_group(group),
            "fork_events": fork_and_convergence_events(group),
            "peeler_events": peeler_and_rejection_events(group),
        },
    )


@login_required
def audit_file_detail(request: HttpRequest, pk: int):
    audit_file = get_object_or_404(
        AuditFile.objects.prefetch_related("events__group"),
        pk=pk,
    )
    return render(
        request,
        "forensics/audit_file_detail.html",
        {
            "audit_file": audit_file,
            "groups": groups_for_audit_file(audit_file),
        },
    )


@csrf_exempt
@require_POST
def api_audit_log_upload(request: HttpRequest, group_slug: str | None = None):
    token = authenticate_request(request)
    if token is None:
        return JsonResponse({"error": "missing or invalid bearer token"}, status=401)

    audit_bytes, source_name, content_type = audit_bytes_from_request(request)
    if len(audit_bytes) > settings.GOGGLES_MAX_DUMP_BYTES:
        return JsonResponse({"error": "audit log exceeds maximum upload size"}, status=413)

    fallback_slug, fallback_name = fallback_group_from_request(request, group_slug)
    source_metadata = source_metadata_from_request(request)
    result = ingest_audit_log_bytes(
        dump_bytes=audit_bytes,
        fallback_group_slug=fallback_slug,
        fallback_group_name=fallback_name,
        upload_token=token,
        source_ip=client_ip(request),
        user_agent=request.headers.get("User-Agent", ""),
        source_name=source_name,
        **source_metadata,
        content_type=content_type or request.content_type or "",
    )

    token.mark_used()
    audit_file = result.audit_file
    groups = groups_for_audit_file(audit_file)
    group_slugs = [group.slug for group in groups]
    response_status = 201 if result.created else 200
    if audit_file.validation_status == AuditFile.STATUS_INVALID:
        response_status = 400

    body = {
        "id": audit_file.id,
        "created": result.created,
        "group": group_slugs[0] if len(group_slugs) == 1 else None,
        "groups": group_slugs,
        "artifact_type": "audit_log",
        "source": source_response(audit_file),
        "account_refs": audit_file.account_refs,
        "group_refs": audit_file.group_refs,
        "schema_versions": audit_file.schema_versions,
        "validation_status": audit_file.validation_status,
        "event_count": audit_file.valid_event_count,
        "invalid_event_count": audit_file.invalid_event_count,
        "duplicate_event_count": audit_file.duplicate_event_count,
        "engine_ids": audit_file.engine_ids,
    }
    if audit_file.validation_status == AuditFile.STATUS_INVALID:
        body["error"] = audit_file.validation_error
    return JsonResponse(body, status=response_status)


def authenticate_request(request: HttpRequest) -> UploadToken | None:
    authorization = request.headers.get("Authorization", "")
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer" or not value:
        return None
    return UploadToken.authenticate(value.strip())


def audit_bytes_from_request(request: HttpRequest) -> tuple[bytes, str, str]:
    if request.FILES:
        upload = (
            request.FILES.get("audit_log")
            or request.FILES.get("dump")
            or next(iter(request.FILES.values()))
        )
        return upload.read(), upload.name, getattr(upload, "content_type", "")
    if request.body:
        return request.body, "", request.content_type or ""
    return b"", "", ""


def source_metadata_from_request(request: HttpRequest) -> dict[str, str]:
    return {
        "source_account_label": request.POST.get("account_label")
        or request.headers.get("X-Goggles-Account-Label", ""),
        "source_device_label": request.POST.get("device_label")
        or request.headers.get("X-Goggles-Device-Label", ""),
        "source_platform": request.POST.get("platform")
        or request.headers.get("X-Goggles-Platform", ""),
        "source_app_version": request.POST.get("app_version")
        or request.headers.get("X-Goggles-App-Version", ""),
    }


def source_response(audit_file: AuditFile) -> dict[str, str]:
    return {
        "account_label": audit_file.source_account_label,
        "device_label": audit_file.source_device_label,
        "platform": audit_file.source_platform,
        "app_version": audit_file.source_app_version,
    }


def fallback_group_from_request(
    request: HttpRequest,
    group_slug: str | None,
) -> tuple[str | None, str]:
    candidate = (
        group_slug
        or request.POST.get("group")
        or request.GET.get("group")
        or request.headers.get("X-Goggles-Group")
    )
    if not candidate:
        return None, ""
    slug = slugify(candidate)[:160] or "incoming"
    return slug, group_name(candidate)


def group_name(candidate: str) -> str:
    return candidate.replace("-", " ").strip().title() or "Incoming"


def groups_for_audit_file(audit_file: AuditFile):
    return list(
        AuditGroup.objects.filter(audit_events__audit_file=audit_file)
        .distinct()
        .order_by("slug")
    )


def client_ip(request: HttpRequest) -> str | None:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.META.get("REMOTE_ADDR")
