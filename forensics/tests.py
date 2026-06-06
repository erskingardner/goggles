import json

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

from .models import DumpUpload, ForensicsMessage, Incident, UploadToken


def sensitive_bundle(**overrides):
    bundle = {
        "schema_version": "marmot-forensics/v1",
        "mode": "sensitive",
        "exported_at_ms": 1780742400000,
        "producer": {"name": "marmot-app", "version": "0.1.0"},
        "account": {"account_ref": "alice-phone", "account_id": "alice"},
        "group": {
            "group_id": "group-1",
            "epoch": 7,
            "member_count": 3,
            "required_app_components": [1, 2, 5],
            "admins": ["alice"],
            "relays": ["wss://relay.example"],
            "nostr_group_id": "nostr-group-1",
        },
        "messages": [
            {
                "message_id": "msg-commit-a",
                "group_id": "group-1",
                "epoch": 6,
                "state": "processed",
                "payload_kind": "openmls_wire",
                "envelope_kind": "group_message",
                "timestamp": 1780742301,
                "payload_len": 3,
                "payload_digest": "sha256:commit-a",
                "payload_hex": "0a0b0c",
                "openmls": {
                    "content_kind": "commit",
                    "source_epoch": 6,
                    "message_digest": "sha256:openmls-commit-a",
                },
            },
            {
                "message_id": "msg-app",
                "group_id": "group-1",
                "epoch": 7,
                "state": "processed",
                "payload_kind": "app_event",
                "envelope_kind": "group_message",
                "timestamp": 1780742360,
                "payload_len": 2,
                "payload_digest": "sha256:app",
                "payload_hex": "0d0e",
            },
        ],
        "snapshots": [{"name": "openmls-retained-anchor-6"}],
        "warnings": [],
    }
    bundle.update(overrides)
    return bundle


class DumpIngestionTests(TestCase):
    def test_bearer_token_post_stores_sensitive_dump_and_normalizes_messages(self):
        raw_token, token = UploadToken.issue("ios test client")
        body = json.dumps(sensitive_bundle(), sort_keys=True)

        response = self.client.post(
            reverse("api-dump-upload"),
            data=body,
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
            HTTP_X_GOGGLES_INCIDENT="qa fork incident",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["created"], True)
        self.assertEqual(response.json()["incident"], "qa-fork-incident")

        incident = Incident.objects.get(slug="qa-fork-incident")
        upload = DumpUpload.objects.get(incident=incident)
        self.assertEqual(upload.mode, "sensitive")
        self.assertEqual(upload.account_id, "alice")
        self.assertEqual(upload.group_id, "group-1")
        self.assertEqual(upload.epoch, 7)
        self.assertEqual(upload.raw_text, body)
        self.assertEqual(upload.upload_token, token)

        messages = list(ForensicsMessage.objects.filter(dump=upload).order_by("timestamp"))
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0].openmls_content_kind, "commit")
        self.assertEqual(messages[0].openmls_source_epoch, 6)
        self.assertEqual(messages[0].openmls_message_digest, "sha256:openmls-commit-a")
        self.assertTrue(messages[0].has_payload_hex)

    def test_api_rejects_upload_without_valid_token(self):
        response = self.client.post(
            reverse("api-dump-upload"),
            data=json.dumps(sensitive_bundle()),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(DumpUpload.objects.count(), 0)

    def test_multipart_file_upload_is_accepted(self):
        raw_token, _token = UploadToken.issue("android qa client")
        body = json.dumps(sensitive_bundle())
        upload_file = SimpleUploadedFile(
            "alice-sensitive-forensics.json",
            body.encode("utf-8"),
            content_type="application/json",
        )

        response = self.client.post(
            reverse("api-incident-dump-upload", kwargs={"incident_slug": "mobile-qa"}),
            data={"dump": upload_file},
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["incident"], "mobile-qa")
        self.assertEqual(DumpUpload.objects.get().raw_text, body)


class DashboardTests(TestCase):
    def test_incident_detail_is_login_required_and_shows_uploaded_group_state(self):
        incident = Incident.objects.create(name="QA fork incident", slug="qa-fork-incident")
        raw_token, token = UploadToken.issue("ios test client")
        self.client.post(
            reverse("api-dump-upload"),
            data=json.dumps(sensitive_bundle()),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
            HTTP_X_GOGGLES_INCIDENT=incident.slug,
        )

        response = self.client.get(reverse("incident-detail", kwargs={"slug": incident.slug}))
        self.assertEqual(response.status_code, 302)

        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")
        response = self.client.get(reverse("incident-detail", kwargs={"slug": incident.slug}))

        self.assertContains(response, "QA fork incident")
        self.assertContains(response, "group-1")
        self.assertContains(response, "alice")
        self.assertContains(response, "epoch 7")
        self.assertContains(response, "sha256:openmls-commit-a")
        token.delete()

    def test_incident_detail_highlights_branch_conflicts_across_clients(self):
        incident = Incident.objects.create(name="Fork check", slug="fork-check")
        raw_token, _token = UploadToken.issue("qa clients")

        alice = sensitive_bundle()
        bob = sensitive_bundle()
        bob["account"] = {"account_ref": "bob-phone", "account_id": "bob"}
        bob["messages"][0]["message_id"] = "msg-commit-b"
        bob["messages"][0]["payload_digest"] = "sha256:commit-b"
        bob["messages"][0]["openmls"]["message_digest"] = "sha256:openmls-commit-b"

        for bundle in (alice, bob):
            response = self.client.post(
                reverse("api-dump-upload"),
                data=json.dumps(bundle, sort_keys=True),
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {raw_token}",
                HTTP_X_GOGGLES_INCIDENT=incident.slug,
            )
            self.assertEqual(response.status_code, 201)

        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")
        response = self.client.get(reverse("incident-detail", kwargs={"slug": incident.slug}))

        self.assertContains(response, "Branch Conflicts")
        self.assertContains(response, "sha256:openmls-commit-a")
        self.assertContains(response, "sha256:openmls-commit-b")
        self.assertContains(response, "alice")
        self.assertContains(response, "bob")
