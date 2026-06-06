from django.contrib import admin

from .models import (
    AnalysisRun,
    DumpUpload,
    ForensicsMessage,
    ForensicsSnapshot,
    Incident,
    UploadToken,
)


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "created_at", "updated_at")
    search_fields = ("name", "slug", "notes")
    prepopulated_fields = {"slug": ("name",)}


@admin.register(UploadToken)
class UploadTokenAdmin(admin.ModelAdmin):
    list_display = ("name", "token_prefix", "is_active", "created_at", "last_used_at")
    list_filter = ("is_active",)
    search_fields = ("name", "token_prefix")
    readonly_fields = ("token_prefix", "token_hash", "created_at", "last_used_at")


class ForensicsMessageInline(admin.TabularInline):
    model = ForensicsMessage
    extra = 0
    fields = (
        "message_id",
        "epoch",
        "payload_kind",
        "openmls_content_kind",
        "openmls_source_epoch",
        "has_payload_hex",
    )
    readonly_fields = fields
    can_delete = False


class ForensicsSnapshotInline(admin.TabularInline):
    model = ForensicsSnapshot
    extra = 0
    readonly_fields = ("name",)
    can_delete = False


@admin.register(DumpUpload)
class DumpUploadAdmin(admin.ModelAdmin):
    list_display = (
        "incident",
        "group_id",
        "account_id",
        "epoch",
        "mode",
        "producer_version",
        "created_at",
    )
    list_filter = ("mode", "schema_version", "producer_name")
    search_fields = ("group_id", "account_id", "raw_sha256")
    readonly_fields = ("raw_sha256", "created_at")
    inlines = [ForensicsMessageInline, ForensicsSnapshotInline]


@admin.register(ForensicsMessage)
class ForensicsMessageAdmin(admin.ModelAdmin):
    list_display = (
        "message_id",
        "group_id",
        "epoch",
        "payload_kind",
        "openmls_content_kind",
        "openmls_source_epoch",
    )
    list_filter = ("payload_kind", "openmls_content_kind", "state")
    search_fields = ("message_id", "group_id", "payload_digest", "openmls_message_digest")


@admin.register(ForensicsSnapshot)
class ForensicsSnapshotAdmin(admin.ModelAdmin):
    list_display = ("name", "dump")
    search_fields = ("name",)


@admin.register(AnalysisRun)
class AnalysisRunAdmin(admin.ModelAdmin):
    list_display = ("incident", "created_at")
    readonly_fields = ("created_at",)
