#!/bin/bash

# Keylo Integration Test Runner
# This script sets up the test environment and runs all tests

set -e

MAILPIT_CONTAINER_NAME="${MAILPIT_CONTAINER_NAME:-keylo-test-mail}"
MAILPIT_SMTP_PORT="${MAILPIT_SMTP_PORT:-11025}"
MAILPIT_API_PORT="${MAILPIT_API_PORT:-18025}"
MAILPIT_IMAGE="${MAILPIT_IMAGE:-axllent/mailpit:v1.21.8}"

cleanup_test_services() {
    docker rm -f "$MAILPIT_CONTAINER_NAME" > /dev/null 2>&1 || true
    docker rm -f keylo-test-db > /dev/null 2>&1 || true
}

trap cleanup_test_services EXIT

echo "🚀 Starting Keylo Integration Tests"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

# Start PostgreSQL test database
print_status "Starting PostgreSQL test database..."
mkdir -p .secrets
if [ ! -s .secrets/.test_postgres_password ]; then
    openssl rand -base64 32 > .secrets/.test_postgres_password
fi
if [ ! -s .secrets/.test_database_password.key ]; then
    openssl rand -base64 32 > .secrets/.test_database_password.key
fi
DATABASE_PASSWORD_FILE="$(pwd)/.secrets/.test_postgres_password" \
DATABASE_PASSWORD_KEY_FILE="$(pwd)/.secrets/.test_database_password.key" \
    cargo run --quiet --bin keylo-encrypt-db-password > .secrets/.test_postgres_password.enc
if docker run -d --name keylo-test-db \
    -e POSTGRES_PASSWORD_FILE=/run/secrets/.postgres_password \
    -e POSTGRES_DB=keylo_test \
    -v "$(pwd)/.secrets/.test_postgres_password:/run/secrets/.postgres_password:ro" \
    -p 5432:5432 postgres:17-alpine > /dev/null 2>&1; then
    print_success "PostgreSQL test database started"
else
    print_warning "PostgreSQL container already exists or failed to start"
fi

# Wait for database to be ready
print_status "Waiting for database to be ready..."
database_ready=false
for i in {1..30}; do
    if docker exec keylo-test-db pg_isready -U postgres -d keylo_test > /dev/null 2>&1; then
        print_success "Database is ready"
        database_ready=true
        break
    fi
    echo -n "."
    sleep 1
done

if [ "$database_ready" != true ]; then
    print_error "Database failed to start within 30 seconds"
    exit 1
fi

print_status "Starting Mailpit SMTP test service..."
docker rm -f "$MAILPIT_CONTAINER_NAME" > /dev/null 2>&1 || true
docker run -d --name "$MAILPIT_CONTAINER_NAME" \
    -p "127.0.0.1:${MAILPIT_SMTP_PORT}:1025" \
    -p "127.0.0.1:${MAILPIT_API_PORT}:8025" \
    "$MAILPIT_IMAGE" > /dev/null
print_success "Mailpit SMTP test service started"

print_status "Waiting for Mailpit to be ready..."
mailpit_ready=false
for i in {1..30}; do
    if curl --fail --silent "http://127.0.0.1:${MAILPIT_API_PORT}/api/v1/messages" > /dev/null; then
        print_success "Mailpit is ready"
        mailpit_ready=true
        break
    fi
    echo -n "."
    sleep 1
done

if [ "$mailpit_ready" != true ]; then
    print_error "Mailpit failed to start within 30 seconds"
    exit 1
fi

# Set test environment variables
TEST_DB_PASSWORD="$(tr -d '\r\n' < .secrets/.test_postgres_password)"
export TEST_DATABASE_URL="postgres://postgres:${TEST_DB_PASSWORD}@localhost:5432/keylo_test"
export DATABASE_PASSWORD_ENC_FILE="$(pwd)/.secrets/.test_postgres_password.enc"
export DATABASE_PASSWORD_KEY_FILE="$(pwd)/.secrets/.test_database_password.key"
export SMTP_TEST_HOST="127.0.0.1"
export SMTP_TEST_PORT="$MAILPIT_SMTP_PORT"
export SMTP_TEST_API_URL="http://127.0.0.1:${MAILPIT_API_PORT}/api/v1/messages"
export SMTP_TEST_CONTAINER_NAME="$MAILPIT_CONTAINER_NAME"
export RUST_LOG=debug

# Run tests
print_status "Running unit tests..."
if cargo test --lib; then
    print_success "Unit tests passed"
else
    print_error "Unit tests failed"
    exit 1
fi

print_status "Running integration tests..."
if cargo test --test integration_test -- --test-threads=1; then
    print_success "Integration tests passed"
else
    print_error "Integration tests failed"
    exit 1
fi

print_status "Running user integration tests..."
if cargo test --test user_integration_test -- --test-threads=1; then
    print_success "User integration tests passed"
else
    print_error "User integration tests failed"
    exit 1
fi

print_status "Running SMTP integration tests..."
if cargo test --test smtp_integration_test -- --test-threads=1; then
    print_success "SMTP integration tests passed"
else
    print_error "SMTP integration tests failed"
    exit 1
fi

print_status "Running RBAC integration tests..."
if cargo test --test rbac_integration_test -- --test-threads=1; then
    print_success "RBAC integration tests passed"
else
    print_error "RBAC integration tests failed"
    exit 1
fi

print_status "Running OAuth integration tests..."
if cargo test --test oauth_integration_test -- --test-threads=1; then
    print_success "OAuth integration tests passed"
else
    print_error "OAuth integration tests failed"
    exit 1
fi

print_status "Running database integration tests..."
if cargo test --test database_integration_test -- --test-threads=1; then
    print_success "Database integration tests passed"
else
    print_error "Database integration tests failed"
    exit 1
fi

print_status "Running load tests..."
if cargo test --test load_test -- --test-threads=1; then
    print_success "Load tests passed"
else
    print_error "Load tests failed"
    exit 1
fi

# Clean up
print_status "Cleaning up Docker test services..."
cleanup_test_services
print_success "Docker test services cleaned up"

print_success "🎉 All tests passed successfully!"

# Run additional checks
print_status "Running additional checks..."

# Check code formatting
if cargo fmt --all -- --check > /dev/null 2>&1; then
    print_success "Code formatting is correct"
else
    print_warning "Code formatting issues found. Run 'cargo fmt' to fix."
fi

# Run clippy
if cargo clippy --workspace --all-targets -- -D warnings > /dev/null 2>&1; then
    print_success "Clippy checks passed"
else
    print_warning "Clippy found issues. Run 'cargo clippy' to see details."
fi

print_success "✅ All checks completed!"
