# Agent Notes

`AGENTS.md` is the canonical instruction file for this repository. `CLAUDE.md`
should remain a symlink to this file.

## Project

Goggles is a Django app for inspecting sensitive Marmot audit-log JSONL. Treat
raw uploads, bearer tokens, engine IDs, account refs, group refs, message IDs,
payload digests, IPs, and user agents as sensitive data.

## Local Workflow

- Install dependencies with `uv sync`.
- Use `just dev` for the seeded local app at `127.0.0.1:8000`.
- Use `just reset-db` to recreate the durable local SQLite database.
- Use `just token "name"` to create a one-time upload bearer token.
- Use `just check` for the quick local verification suite.
- Use `just ci` before publishing when you need parity with GitHub Actions.

## Guardrails

- Keep upload and forensic behavior grounded in the JSONL schema and existing
  ingestion tests.
- Preserve raw audit-log text and line-level evidence unless a task explicitly
  asks to change storage behavior.
- Do not log bearer tokens or raw upload bodies.
- Keep UI changes compact and operational; this is an internal investigation
  tool, not a marketing surface.
