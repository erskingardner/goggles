from __future__ import annotations

import hashlib
import hmac
import secrets

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.validators import MinValueValidator
from django.db import models
from django.utils import timezone


class Incident(models.Model):
    name = models.CharField(max_length=200)
    slug = models.SlugField(unique=True)
    notes = models.TextField(blank=True)
    expected_redaction_salt_id = models.CharField(max_length=128, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at", "-created_at"]

    def __str__(self) -> str:
        return self.name


class UploadToken(models.Model):
    TOKEN_PREFIX = "goggles"

    name = models.CharField(max_length=120)
    token_prefix = models.CharField(max_length=16, unique=True)
    token_hash = models.CharField(max_length=128)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["name", "token_prefix"]

    def __str__(self) -> str:
        state = "active" if self.is_active else "disabled"
        return f"{self.name} ({self.token_prefix}, {state})"

    @classmethod
    def issue(cls, name: str) -> tuple[str, UploadToken]:
        prefix = secrets.token_hex(4)
        secret = secrets.token_urlsafe(32)
        raw_token = f"{cls.TOKEN_PREFIX}_{prefix}_{secret}"
        token = cls.objects.create(
            name=name,
            token_prefix=prefix,
            token_hash=cls.hash_secret(secret),
        )
        return raw_token, token

    @classmethod
    def hash_secret(cls, secret: str) -> str:
        key = settings.SECRET_KEY.encode("utf-8")
        return hmac.new(key, secret.encode("utf-8"), hashlib.sha256).hexdigest()

    @classmethod
    def authenticate(cls, raw_token: str | None) -> UploadToken | None:
        if not raw_token:
            return None
        parts = raw_token.split("_", 2)
        if len(parts) != 3 or parts[0] != cls.TOKEN_PREFIX:
            return None
        _, prefix, secret = parts
        try:
            token = cls.objects.get(token_prefix=prefix, is_active=True)
        except cls.DoesNotExist:
            return None
        if not hmac.compare_digest(token.token_hash, cls.hash_secret(secret)):
            return None
        return token

    def mark_used(self) -> None:
        self.last_used_at = timezone.now()
        self.save(update_fields=["last_used_at"])


class DumpUpload(models.Model):
    MODE_PUBLIC = "public"
    MODE_SENSITIVE = "sensitive"
    MODE_CHOICES = [(MODE_PUBLIC, "Public"), (MODE_SENSITIVE, "Sensitive")]

    incident = models.ForeignKey(Incident, related_name="uploads", on_delete=models.CASCADE)
    upload_token = models.ForeignKey(
        UploadToken,
        related_name="uploads",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    uploaded_by = models.ForeignKey(
        get_user_model(),
        related_name="forensic_uploads",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )

    raw_sha256 = models.CharField(max_length=64)
    raw_text = models.TextField()
    raw_json = models.JSONField()

    schema_version = models.CharField(max_length=80)
    mode = models.CharField(max_length=16, choices=MODE_CHOICES)
    redaction_salt_id = models.CharField(max_length=128, blank=True)
    exported_at_ms = models.PositiveBigIntegerField()

    producer_name = models.CharField(max_length=120)
    producer_version = models.CharField(max_length=80)
    account_ref = models.CharField(max_length=256)
    account_id = models.CharField(max_length=256)
    group_id = models.CharField(max_length=256)
    epoch = models.PositiveBigIntegerField(validators=[MinValueValidator(0)])
    member_count = models.PositiveIntegerField()
    required_app_components = models.JSONField(default=list, blank=True)
    admins = models.JSONField(default=list, blank=True)
    relays = models.JSONField(default=list, blank=True)
    nostr_group_id = models.CharField(max_length=256, blank=True)
    warnings = models.JSONField(default=list, blank=True)

    source_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["incident", "raw_sha256"],
                name="unique_dump_upload_per_incident_sha256",
            )
        ]
        indexes = [
            models.Index(fields=["group_id", "epoch"]),
            models.Index(fields=["account_id"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.group_id} / {self.account_id} / epoch {self.epoch}"


class ForensicsMessage(models.Model):
    dump = models.ForeignKey(DumpUpload, related_name="messages", on_delete=models.CASCADE)
    message_id = models.CharField(max_length=256)
    group_id = models.CharField(max_length=256)
    epoch = models.PositiveBigIntegerField()
    state = models.CharField(max_length=80)
    payload_kind = models.CharField(max_length=120)
    envelope_kind = models.CharField(max_length=120)
    timestamp = models.PositiveBigIntegerField()
    payload_len = models.PositiveBigIntegerField()
    payload_digest = models.CharField(max_length=256)
    has_payload_hex = models.BooleanField(default=False)
    openmls_content_kind = models.CharField(max_length=120, blank=True)
    openmls_source_epoch = models.PositiveBigIntegerField(null=True, blank=True)
    openmls_message_digest = models.CharField(max_length=256, blank=True)

    class Meta:
        ordering = ["timestamp", "id"]
        indexes = [
            models.Index(fields=["group_id", "epoch"]),
            models.Index(fields=["openmls_content_kind", "openmls_source_epoch"]),
            models.Index(fields=["payload_digest"]),
        ]

    def __str__(self) -> str:
        return f"{self.message_id} ({self.payload_kind})"


class ForensicsSnapshot(models.Model):
    dump = models.ForeignKey(DumpUpload, related_name="snapshots", on_delete=models.CASCADE)
    name = models.CharField(max_length=256)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class AnalysisRun(models.Model):
    incident = models.ForeignKey(Incident, related_name="analysis_runs", on_delete=models.CASCADE)
    report_json = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.incident} analysis at {self.created_at:%Y-%m-%d %H:%M:%S}"
