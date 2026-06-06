# Goggles

Internal Dark Matter forensic dump explorer.

Goggles accepts sensitive `marmot-forensics/v1` JSON dumps from Dark Matter clients, stores the exact uploaded text plus parsed JSON, normalizes group/message fields into PostgreSQL tables, and gives the team a login-gated dashboard for comparing client state.

## Local Development

```sh
uv sync --python /opt/homebrew/bin/python3.13
uv run python manage.py migrate
uv run python manage.py createsuperuser
uv run python manage.py create_upload_token "local test client"
uv run python manage.py runserver
```

The development default uses `db.sqlite3` if `DATABASE_URL` is not set. The VM path should use PostgreSQL.

## Upload A Dump

```sh
curl -X POST http://127.0.0.1:8000/api/v1/incidents/qa-fork/dumps/ \
  -H "Authorization: Bearer $GOGGLES_UPLOAD_TOKEN" \
  -F "dump=@/path/to/private-forensics.json"
```

Raw JSON bodies also work:

```sh
curl -X POST "http://127.0.0.1:8000/api/v1/dumps/?incident=qa-fork" \
  -H "Authorization: Bearer $GOGGLES_UPLOAD_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @/path/to/private-forensics.json
```

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
- Sensitive dumps preserve plaintext payload bytes in `raw_text` and `raw_json`; protect database backups accordingly.
- Upload size defaults to 50 MiB via `GOGGLES_MAX_DUMP_BYTES`.

## What The Dashboard Shows

- Incidents and upload counts.
- Group state by client/account, including epoch, member count, message count, snapshot count, and mode.
- OpenMLS commit observations.
- Branch conflicts when different commit digests are observed for the same group/source epoch.
- Per-dump message table and exact raw JSON.
