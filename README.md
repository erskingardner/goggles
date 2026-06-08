# Goggles

Internal Marmot audit-log explorer.

Goggles accepts sensitive `marmot-forensics-audit/v1` JSONL audit logs from Dark Matter clients, preserves the exact uploaded text and raw lines, normalizes common forensic columns into PostgreSQL tables, and gives the team a login-gated dashboard for comparing what multiple account-device engines saw and decided inside each group.

## Local Development

The easiest local workflow uses `just` and a durable SQLite database at `var/goggles-dev.sqlite3`:

```sh
uv sync --python /opt/homebrew/bin/python3.13
just reset-db
just dev
```

The seeded development login is:

```text
username: admin
password: pass123
```

Useful commands:

```sh
just dev                 # run the dev server on 127.0.0.1:8000
just seed                # create/update admin/pass123 and load sample audit data
just reset-db            # delete, recreate, migrate, and seed the dev database
just token "ios qa"      # create an upload bearer token in the dev database
just migrate             # apply migrations to the dev database
just makemigrations      # create migrations from model changes
just check               # run tests, Ruff, and migration drift check
```

Set `GOGGLES_DEV_DB` to use a different local SQLite path, or `GOGGLES_DEV_PORT` to run the dev server on another port. The VM path should use PostgreSQL.

## Upload An Audit Log

If the JSONL includes valid `group_ref` values, Goggles will create or reuse those groups automatically. One uploaded file can contain multiple groups, but it should normally contain one `engine_id` and one `account_ref`.

```sh
curl -X POST http://127.0.0.1:8000/api/v1/audit-logs/ \
  -H "Authorization: Bearer $GOGGLES_UPLOAD_TOKEN" \
  -H "Content-Type: application/x-ndjson" \
  -H "X-Goggles-Account-Label: Alice" \
  -H "X-Goggles-Device-Label: Alice iPhone" \
  -H "X-Goggles-Platform: ios" \
  -H "X-Goggles-App-Version: 2026.6.8" \
  --data-binary @fixtures/sample-audit-log-alice.jsonl
```

The source metadata headers are optional labels for humans. The forensic joins still come from the JSONL `account_ref`, `engine_id`, and `group_ref` fields.

The group URL is only a fallback for group-less lines or broken logs. Event-level `group_ref` values take precedence:

```sh
curl -X POST http://127.0.0.1:8000/api/v1/groups/qa-fork/audit-logs/ \
  -H "Authorization: Bearer $GOGGLES_UPLOAD_TOKEN" \
  -F "audit_log=@fixtures/sample-audit-log-alice.jsonl;type=application/x-ndjson"
```

Query parameters also work as the same fallback:

```sh
curl -X POST "http://127.0.0.1:8000/api/v1/audit-logs/?group=qa-fork" \
  -H "Authorization: Bearer $GOGGLES_UPLOAD_TOKEN" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary @fixtures/sample-audit-log-alice.jsonl
```

Upload another one-engine file, such as `fixtures/sample-audit-log-bob.jsonl`, to compare multiple clients in the same group. Invalid JSONL, mixed-engine uploads, or mixed-account uploads return `400` and are still saved as quarantined audit files so damaged lines can be inspected.

## VM Deployment

1. Put the VM behind Tailscale, WireGuard, or another private network. Do not expose the app directly to the public internet.
2. Copy `.env.example` to `.env` and replace every secret value.
3. Set `DJANGO_ALLOWED_HOSTS` to the internal hostname.
4. Put Caddy, nginx, or another TLS-terminating reverse proxy in front of `127.0.0.1:8000`.
5. Start the app:

```sh
docker compose up -d --build
docker compose exec web uv run python manage.py createsuperuser
docker compose exec web uv run python manage.py create_upload_token "ios qa"
```

The compose file binds the web service to `127.0.0.1:8000` on the VM so a reverse proxy or SSH tunnel has to be the public face.

## Security Notes

- Web UI access uses Django users; there is no public signup.
- Uploads require bearer tokens generated with `create_upload_token`.
- Upload token secrets are shown once and stored only as keyed hashes.
- Audit logs preserve raw engine ids, group refs, message ids, digests, payload metadata, raw lines, and raw uploaded text; protect the database and backups accordingly.
- Brain disk encryption is the expected at-rest protection for v1.
- Upload size defaults to 50 MiB via `GOGGLES_MAX_DUMP_BYTES`.

## What The Dashboard Shows

- Imported audit files, validation status, duplicate counts, and quarantined bad lines.
- Per-account and per-engine audit timelines with hover correlation and click-to-inspect event details.
- Message traces across engines.
- Missing observations when one engine saw a message and another did not.
- Fork and convergence events.
- Peeler failures, rejections, invalidated messages, and failed message states.
