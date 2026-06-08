import json
from io import StringIO

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from .analysis import timeline_by_engine
from .models import AuditEvent, AuditFile, AuditGroup, UploadToken

SCHEMA_VERSION = "marmot-forensics-audit/v1"
ENGINE_ALICE = "0123456789abcdef0123456789abcdef"
ENGINE_BOB = "abcdef0123456789abcdef0123456789"
ACCOUNT_ALICE = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ACCOUNT_BOB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
GROUP_REF = "11" * 32
OTHER_GROUP_REF = "44" * 32
MSG_ID = "22" * 32
OTHER_MSG_ID = "33" * 32
DIGEST_A = "aa" * 32
DIGEST_B = "bb" * 32


def audit_event(
    seq,
    engine_id=ENGINE_ALICE,
    group_ref=GROUP_REF,
    account_ref=ACCOUNT_ALICE,
    kind=None,
    wall_time_ms=None,
):
    return {
        "schema_version": SCHEMA_VERSION,
        "seq": seq,
        "wall_time_ms": wall_time_ms or 1_700_000_000_000 + seq,
        "account_ref": account_ref,
        "engine_id": engine_id,
        "group_ref": group_ref,
        "kind": kind
        or {
            "type": "ingest_entry",
            "msg_id": MSG_ID,
            "envelope_kind": "group_message",
            "payload_len": 512,
            "payload_digest": DIGEST_A,
        },
    }


def jsonl(*events):
    return "\n".join(json.dumps(event, separators=(",", ":")) for event in events) + "\n"


def representative_audit_log(engine_id=ENGINE_ALICE):
    return jsonl(
        audit_event(
            0,
            engine_id=engine_id,
            kind={
                "type": "ingest_entry",
                "msg_id": MSG_ID,
                "envelope_kind": "group_message",
                "payload_len": 512,
                "payload_digest": DIGEST_A,
            },
        ),
        audit_event(
            1,
            engine_id=engine_id,
            kind={
                "type": "ingest_outcome",
                "msg_id": MSG_ID,
                "outcome_kind": "processed",
                "epoch": 7,
            },
        ),
    )


class AuditLogIngestionTests(TestCase):
    def test_bearer_token_post_stores_valid_jsonl_and_normalizes_events(self):
        raw_token, token = UploadToken.issue("ios test client")
        body = representative_audit_log()

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["created"], True)
        self.assertEqual(response.json()["group"], GROUP_REF)
        self.assertEqual(response.json()["groups"], [GROUP_REF])
        self.assertEqual(response.json()["validation_status"], "valid")
        self.assertEqual(response.json()["event_count"], 2)

        group = AuditGroup.objects.get(slug=GROUP_REF)
        self.assertEqual(group.group_ref, GROUP_REF)
        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.upload_token, token)
        self.assertEqual(audit_file.raw_text, body)
        self.assertEqual(audit_file.byte_size, len(body.encode("utf-8")))
        self.assertEqual(audit_file.account_refs, [ACCOUNT_ALICE])
        self.assertEqual(audit_file.engine_ids, [ENGINE_ALICE])
        self.assertEqual(audit_file.group_refs, [GROUP_REF])
        self.assertEqual(audit_file.schema_versions, [SCHEMA_VERSION])

        events = list(AuditEvent.objects.filter(group=group).order_by("line_number"))
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].event_type, "ingest_entry")
        self.assertEqual(events[0].account_ref, ACCOUNT_ALICE)
        self.assertEqual(events[0].engine_id, ENGINE_ALICE)
        self.assertEqual(events[0].group_ref, GROUP_REF)
        self.assertEqual(events[0].msg_id, MSG_ID)
        self.assertEqual(events[0].payload_digest, DIGEST_A)
        self.assertEqual(events[1].event_type, "ingest_outcome")
        self.assertEqual(events[1].outcome_kind, "processed")
        self.assertEqual(events[1].epoch, 7)

    def test_api_rejects_upload_without_valid_token(self):
        for authorization in ("", "Bearer invalid-token"):
            headers = {}
            if authorization:
                headers["HTTP_AUTHORIZATION"] = authorization
            response = self.client.post(
                reverse("api-audit-log-upload"),
                data=representative_audit_log(),
                content_type="application/x-ndjson",
                **headers,
            )

            self.assertEqual(response.status_code, 401)
        self.assertEqual(AuditFile.objects.count(), 0)
        self.assertEqual(AuditEvent.objects.count(), 0)

    def test_api_rejects_non_post_upload_attempts_cleanly(self):
        raw_token, _token = UploadToken.issue("ios test client")

        response = self.client.get(
            reverse("api-audit-log-upload"),
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 405)
        self.assertEqual(AuditFile.objects.count(), 0)
        self.assertEqual(AuditEvent.objects.count(), 0)

    @override_settings(
        GOGGLES_MAX_DUMP_BYTES=10,
        DATA_UPLOAD_MAX_MEMORY_SIZE=1024,
        FILE_UPLOAD_MAX_MEMORY_SIZE=1024,
    )
    def test_api_rejects_oversized_upload_without_saving(self):
        raw_token, _token = UploadToken.issue("ios test client")

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data="x" * 11,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json()["error"], "audit log exceeds maximum upload size")
        self.assertEqual(AuditFile.objects.count(), 0)
        self.assertEqual(AuditEvent.objects.count(), 0)

    @override_settings(
        GOGGLES_MAX_DUMP_BYTES=100,
        DATA_UPLOAD_MAX_MEMORY_SIZE=10,
        FILE_UPLOAD_MAX_MEMORY_SIZE=10,
    )
    def test_api_rejects_django_body_limit_without_saving(self):
        raw_token, _token = UploadToken.issue("ios test client")

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data="x" * 11,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json()["error"], "audit log exceeds maximum upload size")
        self.assertEqual(AuditFile.objects.count(), 0)
        self.assertEqual(AuditEvent.objects.count(), 0)

    def test_multipart_audit_log_upload_is_accepted(self):
        raw_token, _token = UploadToken.issue("android qa client")
        body = representative_audit_log(ENGINE_BOB)
        upload_file = SimpleUploadedFile(
            "audit-android.jsonl",
            body.encode("utf-8"),
            content_type="application/x-ndjson",
        )

        response = self.client.post(
            reverse("api-group-audit-log-upload", kwargs={"group_slug": "mobile-qa"}),
            data={"audit_log": upload_file},
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["group"], GROUP_REF)
        self.assertEqual(response.json()["groups"], [GROUP_REF])
        self.assertFalse(AuditGroup.objects.filter(slug="mobile-qa").exists())
        self.assertEqual(AuditFile.objects.get().source_name, "audit-android.jsonl")
        self.assertEqual(AuditEvent.objects.get(event_type="ingest_entry").engine_id, ENGINE_BOB)

    def test_one_engine_upload_can_populate_multiple_groups(self):
        raw_token, _token = UploadToken.issue("alice devices")
        body = jsonl(
            audit_event(0),
            audit_event(
                1,
                group_ref=OTHER_GROUP_REF,
                kind={
                    "type": "message_state_changed",
                    "msg_id": OTHER_MSG_ID,
                    "new_state": "processed",
                    "reason": "state_update",
                },
            ),
        )

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["groups"], [GROUP_REF, OTHER_GROUP_REF])

        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.account_refs, [ACCOUNT_ALICE])
        self.assertEqual(audit_file.engine_ids, [ENGINE_ALICE])
        self.assertEqual(audit_file.group_refs, [GROUP_REF, OTHER_GROUP_REF])
        self.assertIsNone(getattr(audit_file, "group", None))

        first_group = AuditGroup.objects.get(group_ref=GROUP_REF)
        second_group = AuditGroup.objects.get(group_ref=OTHER_GROUP_REF)
        self.assertEqual(
            list(AuditEvent.objects.filter(group=first_group).values_list("seq", flat=True)),
            [0],
        )
        self.assertEqual(
            list(AuditEvent.objects.filter(group=second_group).values_list("seq", flat=True)),
            [1],
        )

    def test_long_group_refs_with_same_slug_prefix_create_distinct_groups(self):
        raw_token, _token = UploadToken.issue("alice devices")
        shared_prefix = "aa" * 80
        first_group_ref = shared_prefix + "00"
        second_group_ref = shared_prefix + "11"

        first_response = self.client.post(
            reverse("api-audit-log-upload"),
            data=jsonl(audit_event(0, group_ref=first_group_ref)),
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )
        second_response = self.client.post(
            reverse("api-audit-log-upload"),
            data=jsonl(audit_event(1, group_ref=second_group_ref)),
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(first_response.status_code, 201)
        self.assertEqual(second_response.status_code, 201)
        self.assertEqual(AuditGroup.objects.count(), 2)

        first_group = AuditGroup.objects.get(group_ref=first_group_ref)
        second_group = AuditGroup.objects.get(group_ref=second_group_ref)
        self.assertNotEqual(first_group.slug, second_group.slug)
        self.assertEqual(
            list(AuditEvent.objects.filter(group=first_group).values_list("group_ref", flat=True)),
            [first_group_ref],
        )
        self.assertEqual(
            list(AuditEvent.objects.filter(group=second_group).values_list("group_ref", flat=True)),
            [second_group_ref],
        )

    def test_upload_source_metadata_headers_are_saved(self):
        raw_token, _token = UploadToken.issue("alice iphone")

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=representative_audit_log(),
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
            HTTP_X_GOGGLES_ACCOUNT_LABEL="Alice",
            HTTP_X_GOGGLES_DEVICE_LABEL="Alice iPhone",
            HTTP_X_GOGGLES_PLATFORM="ios",
            HTTP_X_GOGGLES_APP_VERSION="2026.6.8",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            response.json()["source"],
            {
                "account_label": "Alice",
                "device_label": "Alice iPhone",
                "platform": "ios",
                "app_version": "2026.6.8",
            },
        )

        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.source_account_label, "Alice")
        self.assertEqual(audit_file.source_device_label, "Alice iPhone")
        self.assertEqual(audit_file.source_platform, "ios")
        self.assertEqual(audit_file.source_app_version, "2026.6.8")

    def test_invalid_jsonl_returns_400_and_saves_quarantined_upload(self):
        raw_token, _token = UploadToken.issue("ios test client")
        bad_body = representative_audit_log() + "{not-json}\n"

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=bad_body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["validation_status"], "invalid")
        self.assertIn("line 3", response.json()["error"])

        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.validation_status, "invalid")
        self.assertIn("line 3", audit_file.validation_error)
        self.assertEqual(audit_file.group_refs, [GROUP_REF])
        self.assertEqual(audit_file.events.count(), 3)
        bad_event = audit_file.events.get(line_number=3)
        self.assertEqual(bad_event.parse_status, "invalid")
        self.assertEqual(bad_event.raw_line, "{not-json}")
        self.assertIn("JSON", bad_event.validation_error)

    def test_overlong_normalized_value_returns_400_and_is_quarantined(self):
        raw_token, _token = UploadToken.issue("ios test client")
        body = jsonl(
            audit_event(
                0,
                kind={
                    "type": "ingest_entry",
                    "msg_id": MSG_ID,
                    "envelope_kind": "x" * 121,
                    "payload_len": 512,
                    "payload_digest": DIGEST_A,
                },
            )
        )

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["validation_status"], "invalid")
        self.assertIn("envelope_kind", response.json()["error"])

        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.validation_status, AuditFile.STATUS_INVALID)
        event = audit_file.events.get()
        self.assertEqual(event.parse_status, AuditEvent.STATUS_INVALID)
        self.assertIn("envelope_kind", event.validation_error)
        self.assertEqual(event.envelope_kind, "")

    def test_mixed_engine_audit_log_returns_400_and_is_quarantined(self):
        raw_token, _token = UploadToken.issue("mixed client")
        body = jsonl(
            audit_event(0, engine_id=ENGINE_ALICE),
            audit_event(1, engine_id=ENGINE_BOB),
        )

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["validation_status"], "invalid")
        self.assertIn("multiple engine_ids", response.json()["error"])

        group = AuditGroup.objects.get(slug=GROUP_REF)
        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.validation_status, "invalid")
        self.assertEqual(audit_file.valid_event_count, 2)
        self.assertEqual(audit_file.invalid_event_count, 0)
        self.assertEqual(audit_file.engine_ids, [ENGINE_ALICE, ENGINE_BOB])
        self.assertEqual(audit_file.events.count(), 2)
        self.assertEqual(timeline_by_engine(group), [])

    def test_reuploading_grown_append_only_log_deduplicates_existing_lines(self):
        raw_token, _token = UploadToken.issue("ios test client")
        first = representative_audit_log()
        grown = first + json.dumps(
            audit_event(
                2,
                kind={
                    "type": "message_state_changed",
                    "msg_id": MSG_ID,
                    "new_state": "processed",
                    "reason": "state_update",
                },
            ),
            separators=(",", ":"),
        )

        first_response = self.client.post(
            reverse("api-audit-log-upload"),
            data=first,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )
        grown_response = self.client.post(
            reverse("api-audit-log-upload"),
            data=grown,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(first_response.status_code, 201)
        self.assertEqual(grown_response.status_code, 201)
        self.assertEqual(AuditFile.objects.count(), 2)
        self.assertEqual(AuditEvent.objects.filter(group__slug=GROUP_REF).count(), 3)
        self.assertEqual(AuditFile.objects.order_by("created_at").last().duplicate_event_count, 2)

    def test_corrected_valid_upload_keeps_lines_seen_in_quarantined_upload(self):
        raw_token, _token = UploadToken.issue("ios test client")
        bad_body = json.dumps(audit_event(0), separators=(",", ":")) + "\n{not-json}\n"
        corrected_body = jsonl(
            audit_event(0),
            audit_event(
                1,
                kind={
                    "type": "message_state_changed",
                    "msg_id": OTHER_MSG_ID,
                    "new_state": "processed",
                    "reason": "state_update",
                },
            ),
        )

        bad_response = self.client.post(
            reverse("api-audit-log-upload"),
            data=bad_body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )
        corrected_response = self.client.post(
            reverse("api-audit-log-upload"),
            data=corrected_body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(bad_response.status_code, 400)
        self.assertEqual(corrected_response.status_code, 201)
        self.assertEqual(corrected_response.json()["duplicate_event_count"], 0)

        valid_file = AuditFile.objects.get(validation_status=AuditFile.STATUS_VALID)
        self.assertEqual(valid_file.valid_event_count, 2)
        self.assertEqual(valid_file.events.count(), 2)
        self.assertEqual(
            list(
                AuditEvent.objects.filter(
                    group__slug=GROUP_REF,
                    audit_file__validation_status=AuditFile.STATUS_VALID,
                    parse_status=AuditEvent.STATUS_VALID,
                ).values_list("msg_id", flat=True)
            ),
            [MSG_ID, OTHER_MSG_ID],
        )

    def test_upload_batches_database_work_for_many_lines(self):
        raw_token, _token = UploadToken.issue("ios test client")
        body = jsonl(
            *[
                audit_event(
                    seq,
                    kind={
                        "type": "ingest_entry",
                        "msg_id": f"{seq:064x}",
                        "envelope_kind": "group_message",
                        "payload_len": 512,
                        "payload_digest": DIGEST_A,
                    },
                )
                for seq in range(20)
            ]
        )

        with CaptureQueriesContext(connection) as queries:
            response = self.client.post(
                reverse("api-audit-log-upload"),
                data=body,
                content_type="application/x-ndjson",
                HTTP_AUTHORIZATION=f"Bearer {raw_token}",
            )

        self.assertEqual(response.status_code, 201)
        self.assertLessEqual(len(queries), 35)
        self.assertEqual(AuditEvent.objects.count(), 20)


class DashboardTests(TestCase):
    def test_group_detail_is_login_required_and_shows_audit_workflows(self):
        group = AuditGroup.objects.create(
            name="QA fork group",
            slug=GROUP_REF,
            group_ref=GROUP_REF,
        )
        raw_token, _token = UploadToken.issue("qa clients")
        alice = jsonl(
            audit_event(
                0,
                engine_id=ENGINE_ALICE,
                kind={
                    "type": "send_outcome",
                    "intent_kind": "invite",
                    "result_kind": "group_evolution",
                    "outbound_msg_id": MSG_ID,
                    "outbound_welcome_msg_ids": [OTHER_MSG_ID],
                },
            ),
            audit_event(
                1,
                engine_id=ENGINE_ALICE,
                kind={
                    "type": "fork_resolution",
                    "source_epoch": 6,
                    "candidate_digest": DIGEST_A,
                    "incumbent_digest": DIGEST_B,
                    "winner": "candidate",
                    "invalidated_msg_id": OTHER_MSG_ID,
                },
            ),
            audit_event(
                2,
                engine_id=ENGINE_ALICE,
                kind={
                    "type": "convergence_decision",
                    "current_tip_epoch": 6,
                    "candidate_count": 2,
                    "eligible_count": 1,
                    "max_rewind_commits": 5,
                    "selected_branch_id": "branch-a",
                    "selected_fork_epoch": 6,
                    "selected_tip_epoch": 7,
                },
            ),
        )
        bob = jsonl(
            audit_event(
                0,
                engine_id=ENGINE_BOB,
                kind={
                    "type": "ingest_entry",
                    "msg_id": MSG_ID,
                    "envelope_kind": "group_message",
                    "payload_len": 512,
                    "payload_digest": DIGEST_A,
                },
                wall_time_ms=1_700_000_000_050,
            ),
            audit_event(
                1,
                engine_id=ENGINE_BOB,
                kind={
                    "type": "peeler_outcome",
                    "msg_id": MSG_ID,
                    "outcome": "decrypt_failed",
                    "fallback_snapshot_used": False,
                    "detail": "no_matching_epoch",
                },
                wall_time_ms=1_700_000_000_060,
            ),
            audit_event(
                2,
                engine_id=ENGINE_BOB,
                kind={
                    "type": "message_state_changed",
                    "msg_id": OTHER_MSG_ID,
                    "new_state": "epoch_invalidated",
                    "reason": "fork_loser",
                },
                wall_time_ms=1_700_000_000_070,
            ),
        )

        for body in (alice, bob):
            response = self.client.post(
                reverse("api-group-audit-log-upload", kwargs={"group_slug": group.slug}),
                data=body,
                content_type="application/x-ndjson",
                HTTP_AUTHORIZATION=f"Bearer {raw_token}",
            )
            self.assertEqual(response.status_code, 201)

        response = self.client.get(reverse("group-detail", kwargs={"slug": group.slug}))
        self.assertEqual(response.status_code, 302)

        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")
        response = self.client.get(reverse("group-detail", kwargs={"slug": group.slug}))

        self.assertContains(response, "QA fork group")
        self.assertContains(response, "Audit Timeline")
        self.assertContains(response, ENGINE_ALICE)
        self.assertContains(response, ENGINE_BOB)
        self.assertContains(response, "Message Trace")
        self.assertContains(response, MSG_ID)
        self.assertContains(response, "Fork And Convergence")
        self.assertContains(response, "candidate")
        self.assertContains(response, "Peeler And Rejections")
        self.assertContains(response, "decrypt_failed")
        self.assertContains(response, "Missing Observations")
        self.assertContains(response, OTHER_MSG_ID)


class HealthCheckTests(TestCase):
    def test_healthz_returns_minimal_json_without_login(self):
        response = self.client.get(reverse("healthz"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertEqual(response.json(), {"status": "ok"})


class SeedDevCommandTests(TestCase):
    def test_seed_dev_creates_admin_user_and_sample_audit_log_idempotently(self):
        output = StringIO()

        call_command("seed_dev", stdout=output)
        call_command("seed_dev", stdout=StringIO())

        admin = User.objects.get(username="admin")
        self.assertTrue(admin.check_password("pass123"))
        self.assertTrue(admin.is_staff)
        self.assertTrue(admin.is_superuser)

        group = AuditGroup.objects.get(group_ref=GROUP_REF)
        self.assertEqual(group.slug, GROUP_REF)
        self.assertEqual(
            AuditFile.objects.filter(events__group=group).distinct().count(),
            2,
        )
        self.assertEqual(AuditEvent.objects.filter(group=group).count(), 5)
        self.assertIn("admin / pass123", output.getvalue())
