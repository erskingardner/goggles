from __future__ import annotations

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.db.models import Count
from django.http import HttpRequest, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.template.defaultfilters import slugify
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .analysis import (
    branch_conflicts_for_incident,
    commit_observations_for_incident,
    incident_summary,
    uploads_for_incident,
)
from .ingest import ingest_dump_bytes
from .models import DumpUpload, Incident, UploadToken


@login_required
def incident_list(request: HttpRequest):
    incidents = Incident.objects.annotate(
        upload_count=Count("uploads", distinct=True),
        message_count=Count("uploads__messages", distinct=True),
    )
    return render(request, "forensics/incident_list.html", {"incidents": incidents})


@login_required
def incident_detail(request: HttpRequest, slug: str):
    incident = get_object_or_404(Incident, slug=slug)
    uploads = list(
        uploads_for_incident(incident).annotate(
            message_count=Count("messages", distinct=True),
            snapshot_count=Count("snapshots", distinct=True),
        )
    )
    return render(
        request,
        "forensics/incident_detail.html",
        {
            "incident": incident,
            "uploads": uploads,
            "summary": incident_summary(uploads),
            "branch_conflicts": branch_conflicts_for_incident(incident),
            "commit_observations": commit_observations_for_incident(incident),
        },
    )


@login_required
def dump_detail(request: HttpRequest, pk: int):
    upload = get_object_or_404(
        DumpUpload.objects.select_related("incident").prefetch_related("messages", "snapshots"),
        pk=pk,
    )
    return render(request, "forensics/dump_detail.html", {"upload": upload})


@csrf_exempt
@require_POST
def api_dump_upload(request: HttpRequest, incident_slug: str | None = None):
    token = authenticate_request(request)
    if token is None:
        return JsonResponse({"error": "missing or invalid bearer token"}, status=401)

    try:
        dump_bytes = dump_bytes_from_request(request)
        if len(dump_bytes) > settings.GOGGLES_MAX_DUMP_BYTES:
            return JsonResponse({"error": "dump exceeds maximum upload size"}, status=413)

        incident = incident_from_request(request, incident_slug)
        result = ingest_dump_bytes(
            incident=incident,
            dump_bytes=dump_bytes,
            upload_token=token,
            source_ip=client_ip(request),
            user_agent=request.headers.get("User-Agent", ""),
        )
    except ValidationError as exc:
        return JsonResponse({"error": "; ".join(exc.messages)}, status=400)

    token.mark_used()
    status = 201 if result.created else 200
    upload = result.upload
    return JsonResponse(
        {
            "id": upload.id,
            "created": result.created,
            "incident": upload.incident.slug,
            "schema_version": upload.schema_version,
            "mode": upload.mode,
            "account_id": upload.account_id,
            "group_id": upload.group_id,
            "epoch": upload.epoch,
            "message_count": upload.messages.count(),
            "snapshot_count": upload.snapshots.count(),
        },
        status=status,
    )


def authenticate_request(request: HttpRequest) -> UploadToken | None:
    authorization = request.headers.get("Authorization", "")
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer" or not value:
        return None
    return UploadToken.authenticate(value.strip())


def dump_bytes_from_request(request: HttpRequest) -> bytes:
    if request.FILES:
        upload = request.FILES.get("dump") or next(iter(request.FILES.values()))
        return upload.read()
    if request.body:
        return request.body
    raise ValidationError("No dump file or JSON body supplied.")


def incident_from_request(request: HttpRequest, incident_slug: str | None) -> Incident:
    candidate = (
        incident_slug
        or request.POST.get("incident")
        or request.GET.get("incident")
        or request.headers.get("X-Goggles-Incident")
        or "incoming"
    )
    slug = slugify(candidate)[:50] or "incoming"
    defaults = {"name": candidate.replace("-", " ").strip().title() or "Incoming"}
    incident, _ = Incident.objects.get_or_create(slug=slug, defaults=defaults)
    return incident


def client_ip(request: HttpRequest) -> str | None:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.META.get("REMOTE_ADDR")
