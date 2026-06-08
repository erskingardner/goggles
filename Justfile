set dotenv-load := true

dev_db := env_var_or_default("GOGGLES_DEV_DB", "var/goggles-dev.sqlite3")
database_url := "sqlite:///" + justfile_directory() + "/" + dev_db
port := env_var_or_default("GOGGLES_DEV_PORT", "8000")
python := "uv run python"

alias run := dev
alias reset := reset-db

# Show available commands.
default:
    @just --list

# Install or update local Python dependencies.
sync:
    uv sync

# Apply migrations to the durable local development database.
migrate: _dev-db-dir
    DATABASE_URL='{{database_url}}' {{python}} manage.py migrate

# Create Django migrations from model changes.
makemigrations:
    {{python}} manage.py makemigrations

# Fail if model changes need migrations.
check-migrations:
    {{python}} manage.py makemigrations --check --dry-run

# Seed admin/pass123 and sample audit-log data into the dev database.
seed: migrate
    DATABASE_URL='{{database_url}}' {{python}} manage.py seed_dev

# Delete, recreate, migrate, and seed the durable local development database.
reset-db: _dev-db-dir
    rm -f '{{justfile_directory()}}/{{dev_db}}' '{{justfile_directory()}}/{{dev_db}}-shm' '{{justfile_directory()}}/{{dev_db}}-wal'
    DATABASE_URL='{{database_url}}' {{python}} manage.py migrate
    DATABASE_URL='{{database_url}}' {{python}} manage.py seed_dev

# Run the Django dev server against the durable local development database.
dev: migrate
    @echo 'Goggles dev: http://127.0.0.1:{{port}}'
    @echo 'Seeded login: admin / pass123'
    DATABASE_URL='{{database_url}}' {{python}} manage.py runserver 127.0.0.1:{{port}}

# Create an upload bearer token in the durable local development database.
token name="local test client": migrate
    DATABASE_URL='{{database_url}}' {{python}} manage.py create_upload_token "{{name}}"

# Open a Django shell against the durable local development database.
shell: migrate
    DATABASE_URL='{{database_url}}' {{python}} manage.py shell

# Run the Django test suite.
test:
    {{python}} manage.py test

# Run Ruff checks.
lint:
    uv run ruff check .

# Run the normal local verification suite.
check: test lint check-migrations

_dev-db-dir:
    @mkdir -p "$(dirname '{{justfile_directory()}}/{{dev_db}}')"
