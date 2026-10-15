#!/usr/bin/env bash

set -Eeuo pipefail

TEST_DB_PORT="${TEST_DB_PORT:-55432}"
MAILPIT_SMTP_PORT="${MAILPIT_SMTP_PORT:-11025}"
MAILPIT_API_PORT="${MAILPIT_API_PORT:-18025}"
MAILPIT_IMAGE="${MAILPIT_IMAGE:-axllent/mailpit:v1.21.8}"
MAILPIT_CONTAINER_PREFIX="${MAILPIT_CONTAINER_NAME:-keylo-test-mail}"
RUN_ID="$(openssl rand -hex 8)"
TEST_POSTGRES_CONTAINER_NAME="keylo-test-db-${RUN_ID}"
MAILPIT_CONTAINER_NAME="${MAILPIT_CONTAINER_PREFIX}-${RUN_ID}"
RUN_LABEL="com.keylo.test-run"
TEST_TEMP_DIR=""
DB_CONTAINER_ATTEMPTED=0
MAILPIT_CONTAINER_ATTEMPTED=0

log() {
    printf '[INFO] %s\n' "$1"
}

die() {
    printf '[ERROR] %s\n' "$1" >&2
    exit 1
}

on_error() {
    local status=$?
    printf '[ERROR] Command failed at line %s (exit %s).\n' "${BASH_LINENO[0]:-unknown}" "$status" >&2
    exit "$status"
}

container_owned_by_this_run() {
    local container_name="$1"
    local label_value
    label_value="$(docker inspect --format "{{ index .Config.Labels \"${RUN_LABEL}\" }}" "$container_name" 2>/dev/null)" || return 1
    [[ "$label_value" == "$RUN_ID" ]]
}

remove_run_container() {
    local container_name="$1"
    local attempted="$2"
    local cleanup_failed=0

    [[ "$attempted" == "1" ]] || return 0
    if container_owned_by_this_run "$container_name"; then
        if docker rm -f -v "$container_name" >/dev/null; then
            log "Removed test container $container_name and its anonymous volumes."
        else
            printf '[ERROR] Could not remove test container %s.\n' "$container_name" >&2
            cleanup_failed=1
        fi
    elif ! docker info >/dev/null 2>&1; then
        printf '[ERROR] Docker is unavailable; cleanup of test container %s could not be verified.\n' "$container_name" >&2
        cleanup_failed=1
    fi

    return "$cleanup_failed"
}

cleanup() {
    local exit_status=$?
    local cleanup_failed=0
    trap - EXIT ERR
    set +e

    remove_run_container "$MAILPIT_CONTAINER_NAME" "$MAILPIT_CONTAINER_ATTEMPTED" || cleanup_failed=1
    remove_run_container "$TEST_POSTGRES_CONTAINER_NAME" "$DB_CONTAINER_ATTEMPTED" || cleanup_failed=1

    if [[ -n "$TEST_TEMP_DIR" && -d "$TEST_TEMP_DIR" ]]; then
        if rm -rf -- "$TEST_TEMP_DIR"; then
            log "Removed temporary test credentials."
        else
            printf '[ERROR] Could not remove temporary test credentials at %s.\n' "$TEST_TEMP_DIR" >&2
            cleanup_failed=1
        fi
    fi

    if (( exit_status == 0 && cleanup_failed != 0 )); then
        exit_status=1
    fi
    exit "$exit_status"
}

trap on_error ERR
trap cleanup EXIT

validate_port() {
    local name="$1"
    local value="$2"
    if [[ ! "$value" =~ ^[0-9]+$ ]] || (( 10#$value < 1024 || 10#$value > 65535 )); then
        die "$name must be a TCP port between 1024 and 65535."
    fi
}

validate_port TEST_DB_PORT "$TEST_DB_PORT"
validate_port MAILPIT_SMTP_PORT "$MAILPIT_SMTP_PORT"
validate_port MAILPIT_API_PORT "$MAILPIT_API_PORT"
[[ -n "$MAILPIT_IMAGE" ]] || die "MAILPIT_IMAGE must not be empty."
[[ "$MAILPIT_CONTAINER_PREFIX" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die "MAILPIT_CONTAINER_NAME must be a valid container-name prefix."

for command_name in docker cargo curl openssl python3; do
    command -v "$command_name" >/dev/null 2>&1 || die "Required command not found: $command_name"
done

docker info >/dev/null 2>&1 || die "Docker is unavailable. Start Docker and retry."

umask 077
TEST_TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/keylo-test-${RUN_ID}.XXXXXX")"
TEST_PASSWORD_FILE="$TEST_TEMP_DIR/postgres_password"
TEST_PASSWORD_KEY_FILE="$TEST_TEMP_DIR/database_password.key"
TEST_PASSWORD_ENC_FILE="$TEST_TEMP_DIR/postgres_password.enc"

openssl rand -base64 32 | tr -d '\r\n' > "$TEST_PASSWORD_FILE"
openssl rand -base64 32 | tr -d '\r\n' > "$TEST_PASSWORD_KEY_FILE"
DATABASE_PASSWORD_FILE="$TEST_PASSWORD_FILE" \
DATABASE_PASSWORD_KEY_FILE="$TEST_PASSWORD_KEY_FILE" \
    cargo run --quiet --bin keylo-encrypt-db-password > "$TEST_PASSWORD_ENC_FILE"

log "Starting PostgreSQL on 127.0.0.1:${TEST_DB_PORT}..."
DB_CONTAINER_ATTEMPTED=1
if ! docker run --detach \
    --name "$TEST_POSTGRES_CONTAINER_NAME" \
    --label "${RUN_LABEL}=${RUN_ID}" \
    --env POSTGRES_USER=postgres \
    --env POSTGRES_PASSWORD_FILE=/run/secrets/.postgres_password \
    --env POSTGRES_DB=keylo_test \
    --volume "${TEST_PASSWORD_FILE}:/run/secrets/.postgres_password:ro" \
    --publish "127.0.0.1:${TEST_DB_PORT}:5432" \
    postgres:17-alpine >/dev/null; then
    die "Failed to start the PostgreSQL test container."
fi

log "Waiting for PostgreSQL readiness..."
database_ready=false
for _ in {1..30}; do
    if docker exec "$TEST_POSTGRES_CONTAINER_NAME" pg_isready -U postgres -d keylo_test >/dev/null 2>&1; then
        database_ready=true
        break
    fi
    sleep 1
done
[[ "$database_ready" == true ]] || die "PostgreSQL did not become ready within 30 seconds."

log "Starting Mailpit on 127.0.0.1:${MAILPIT_SMTP_PORT} (API ${MAILPIT_API_PORT})..."
MAILPIT_CONTAINER_ATTEMPTED=1
if ! docker run --detach \
    --name "$MAILPIT_CONTAINER_NAME" \
    --label "${RUN_LABEL}=${RUN_ID}" \
    --publish "127.0.0.1:${MAILPIT_SMTP_PORT}:1025" \
    --publish "127.0.0.1:${MAILPIT_API_PORT}:8025" \
    "$MAILPIT_IMAGE" >/dev/null; then
    die "Failed to start the Mailpit test container."
fi

log "Waiting for Mailpit readiness..."
mailpit_ready=false
for _ in {1..30}; do
    if curl --fail --silent "http://127.0.0.1:${MAILPIT_API_PORT}/api/v1/messages" >/dev/null; then
        mailpit_ready=true
        break
    fi
    sleep 1
done
[[ "$mailpit_ready" == true ]] || die "Mailpit did not become ready within 30 seconds."

TEST_DB_PASSWORD="$(<"$TEST_PASSWORD_FILE")"
ENCODED_TEST_DB_PASSWORD="$(printf '%s' "$TEST_DB_PASSWORD" | python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read(), safe=""))')"
export TEST_DATABASE_URL="postgres://postgres:${ENCODED_TEST_DB_PASSWORD}@127.0.0.1:${TEST_DB_PORT}/keylo_test"
export DATABASE_URL="$TEST_DATABASE_URL"
export DATABASE_PASSWORD_ENC_FILE="$TEST_PASSWORD_ENC_FILE"
export DATABASE_PASSWORD_KEY_FILE="$TEST_PASSWORD_KEY_FILE"
export TEST_POSTGRES_CONTAINER_NAME
export SMTP_TEST_HOST=127.0.0.1
export SMTP_TEST_PORT="$MAILPIT_SMTP_PORT"
export SMTP_TEST_API_URL="http://127.0.0.1:${MAILPIT_API_PORT}/api/v1/messages"
export SMTP_TEST_CONTAINER_NAME="$MAILPIT_CONTAINER_NAME"
export RUST_LOG="${RUST_LOG:-debug}"
export RUST_TEST_THREADS=1

log "Running dependency-free library tests..."
cargo test --lib -- --test-threads=1

log "Running dependency-free load tests..."
cargo test --test load_test -- --test-threads=1

log "Running dependency-free HTTP tests..."
cargo test --test integration_test tests::dependency_free:: -- --test-threads=1

log "Running formatting checks..."
cargo fmt --all -- --check

log "Running workspace Clippy checks..."
cargo clippy --workspace --all-targets -- -D warnings

log "Running all workspace tests with PostgreSQL, Mailpit, and one test thread..."
cargo test --workspace --all-targets -- --test-threads=1

log "Checking test failure-path coverage..."
python3 scripts/check_test_failures.py

log "All validation checks passed."
