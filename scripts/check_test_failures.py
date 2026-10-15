#!/usr/bin/env python3
"""Verify that real integration-test setup and authentication faults fail the suite.

Requires the runner's local Docker PostgreSQL container and TEST_DATABASE_URL.
All destructive probes use a newly created database, never the configured database.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit, urlunsplit
import uuid


ROOT = Path(__file__).resolve().parent.parent
DATABASE_TEST = "database_tests::test_database_migrations"
HTTP_TEST = "tests::test_oidc_public_client_token_request_rejects_a_secret"
AUTH_PROBE = "tests::probe_admin_authentication_500_fails"
DEPENDENT_CASES = {
    "database_integration_test": DATABASE_TEST,
    "integration_test": HTTP_TEST,
    "user_integration_test": "tests::test_auth_me_returns_non_empty_uid",
    "rbac_integration_test": "tests::test_create_role",
    "oauth_integration_test": "tests::test_create_oauth_provider",
    "customer_support_integration_test": "tests::customer_support_grant_is_live_tenant_bound_and_audited",
}
CONNECTION_ERRORS = {
    "database_integration_test": "connect to the PostgreSQL test database",
    "integration_test": "HTTP test router initialization failed",
    "user_integration_test": "PostgreSQL test database must initialize",
    "rbac_integration_test": "RBAC test failed to connect",
    "oauth_integration_test": "OAuth test failed to connect",
    "customer_support_integration_test": "customer-support test could not connect",
}


def execute(command, *, env=None, sql=None):
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        input=sql,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
        check=False,
    )


def require_success(result, operation):
    if result.returncode:
        raise RuntimeError(f"{operation} failed:\n{result.stdout[-8000:]}")


def main():
    database_url = os.environ["TEST_DATABASE_URL"].strip()
    container = os.environ["TEST_POSTGRES_CONTAINER_NAME"].strip()
    if not database_url or not container:
        raise ValueError("TEST_DATABASE_URL and TEST_POSTGRES_CONTAINER_NAME must be nonempty")
    parsed = urlsplit(database_url)
    if parsed.scheme not in ("postgres", "postgresql") or not parsed.hostname:
        raise ValueError("TEST_DATABASE_URL must be a PostgreSQL URL")

    command = ["cargo", "test", "--locked", "--no-run", "--message-format=json"]
    for target in (*DEPENDENT_CASES, "smtp_integration_test"):
        command.extend(["--test", target])
    built = execute(command)
    require_success(built, "Building the actual integration-test binaries")
    binaries = {}
    for line in built.stdout.splitlines():
        if line.startswith("{"):
            event = json.loads(line)
            if event.get("reason") == "compiler-artifact" and event.get("executable"):
                binaries[event["target"]["name"]] = event["executable"]
    for target in (*DEPENDENT_CASES, "smtp_integration_test"):
        if target not in binaries:
            raise RuntimeError(f"Cargo did not produce the {target} test binary")

    database_name = f"keylo_fault_{uuid.uuid4().hex}"
    probe_url = urlunsplit(parsed._replace(path=f"/{database_name}"))
    probe_env = dict(os.environ, TEST_DATABASE_URL=probe_url, RUST_BACKTRACE="0")

    def psql(sql, database="postgres"):
        result = execute([
            "docker", "exec", "-i", container, "psql", "-X", "-q",
            "-v", "ON_ERROR_STOP=1", "-U", unquote(parsed.username or "postgres"),
            "-d", database,
        ], sql=sql)
        require_success(result, "Preparing/cleaning the isolated failure-probe database")

    def run_case(label, target, name, *, env=None, failure=None, ignored=False):
        command = [binaries[target], "--exact", name, "--nocapture", "--test-threads=1"]
        if ignored:
            command.append("--ignored")
        result = execute(command, env=probe_env if env is None else env)
        if failure is None:
            require_success(result, label)
            expected = r"test result: ok\. 1 passed; 0 failed; 0 ignored;"
        else:
            if result.returncode == 0 or failure not in result.stdout:
                raise RuntimeError(f"{label} did not fail for the expected reason:\n{result.stdout[-8000:]}")
            expected = r"test result: FAILED\. 0 passed; 1 failed; 0 ignored;"
        if not re.search(expected, result.stdout):
            raise RuntimeError(f"{label} did not execute exactly one test:\n{result.stdout[-8000:]}")
        print(f"[PASS] {label}", flush=True)

    missing_env = dict(probe_env)
    missing_env.pop("TEST_DATABASE_URL")
    unreachable_env = dict(probe_env, TEST_DATABASE_URL="postgres://postgres@127.0.0.1:1/keylo_fault")
    for target, test in DEPENDENT_CASES.items():
        run_case(f"{target}: missing database configuration fails", target, test,
                 env=missing_env, failure="TEST_DATABASE_URL")
        run_case(f"{target}: unavailable PostgreSQL fails", target, test,
                 env=unreachable_env, failure=CONNECTION_ERRORS[target])
    run_case("Dependency-free HTTP runs without PostgreSQL", "integration_test",
             "tests::dependency_free::test_health_check", env=missing_env)
    run_case("Destructive probe validates its database name before connecting", "integration_test", AUTH_PROBE,
             env=unreachable_env, failure="failure probe may only modify", ignored=True)
    missing_mail_env = dict(probe_env)
    missing_mail_env.pop("SMTP_TEST_HOST", None)
    run_case("Missing SMTP configuration fails", "smtp_integration_test",
             "smtp_provider_delivers_a_message_to_mailpit", env=missing_mail_env,
             failure="SMTP_TEST_HOST")

    created = False
    try:
        psql(f'CREATE DATABASE "{database_name}";')
        created = True
        run_case("Healthy PostgreSQL executes the migration assertions", "database_integration_test", DATABASE_TEST)
        psql("UPDATE _sqlx_migrations SET checksum = decode('00', 'hex') "
             "WHERE version = (SELECT MIN(version) FROM _sqlx_migrations);", database_name)
        run_case("Migration checksum failure fails", "database_integration_test", DATABASE_TEST,
                 failure="was previously applied but has been modified")
        psql(f'DROP DATABASE "{database_name}" WITH (FORCE);')
        created = False
        psql(f'CREATE DATABASE "{database_name}";')
        created = True
        run_case("Fresh PostgreSQL executes the migration assertions", "database_integration_test", DATABASE_TEST)
        psql("ALTER TABLE clients ADD CONSTRAINT reject_probe_admin "
             "CHECK (id <> 'cli-admin-root');", database_name)
        run_case("Admin fixture initialization failure fails", "integration_test", HTTP_TEST,
                 failure="reject_probe_admin")
        psql("ALTER TABLE clients DROP CONSTRAINT reject_probe_admin;", database_name)
        run_case("Healthy HTTP setup executes the authorization assertions", "integration_test", HTTP_TEST)
        run_case("An actual admin-token HTTP 500 fails the shared login assertion", "integration_test", AUTH_PROBE,
                 failure="actual status: 500", ignored=True)
    finally:
        if created:
            psql(f'DROP DATABASE "{database_name}" WITH (FORCE);')
    print("[PASS] Failure probes completed; isolated database removed.")


if __name__ == "__main__":
    try:
        main()
    except (KeyError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"[FAIL] {error}", file=sys.stderr)
        sys.exit(1)
