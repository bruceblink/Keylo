#!/usr/bin/env python3
"""Generate database and Redis deployment secrets.

The encrypted value format is:

    secret:v1:aes-256-gcm:<nonce_base64>:<ciphertext_base64>
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import secrets
import string
import stat
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "secret:v1:aes-256-gcm"
DEFAULT_SECRET_DIR = ".secrets"
PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}:,.?"
DEFAULT_PASSWORD_LENGTH = 32
DEFAULT_REDIS_KEY_PATTERN = "*"


def ensure_writable(path: Path) -> None:
    if os.name == "nt" and path.exists():
        subprocess.run(
            ["attrib", "-h", "-r", str(path)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        path.chmod(stat.S_IWRITE)


def hide_if_dot_path(path: Path) -> None:
    if os.name != "nt":
        return
    for item in [path.parent, path]:
        if item.name.startswith(".") and item.exists():
            subprocess.run(
                ["attrib", "+h", str(item)],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    ensure_writable(path)
    path.write_text(value, encoding="utf-8")
    hide_if_dot_path(path)


def redis_acl_key_pattern(value: str) -> str:
    value = value.strip()
    if value in ("*", "~*"):
        return "~*"
    if value.startswith("~"):
        return value
    return f"~{value}:*"


def read_text_if_non_empty(path: Path) -> str | None:
    if not path.exists():
        return None
    value = path.read_text(encoding="utf-8").strip()
    return value or None


def generate_key_value() -> str:
    return base64.b64encode(os.urandom(32)).decode("ascii")


def generate_password(length: int = DEFAULT_PASSWORD_LENGTH) -> str:
    if length < 9:
        raise ValueError("password length must be greater than 8")

    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()-_=+[]{}:,.?"),
    ]
    remaining = [secrets.choice(PASSWORD_ALPHABET) for _ in range(length - len(required))]
    password_chars = required + remaining
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def decode_key(value: str) -> bytes:
    value = value.strip()
    try:
        decoded = base64.b64decode(value, validate=True)
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass

    raw = value.encode("utf-8")
    if len(raw) == 32:
        return raw

    raise ValueError("key must be 32 raw bytes or standard base64 for 32 bytes")


def encrypt_value(plaintext: str, key: bytes) -> str:
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return (
        f"{PREFIX}:"
        f"{base64.b64encode(nonce).decode('ascii')}:"
        f"{base64.b64encode(ciphertext).decode('ascii')}"
    )


def generate_rsa_keypair(bits: int) -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()

    private_key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return (
        base64.b64encode(private_key_der).decode("ascii"),
        base64.b64encode(public_key_der).decode("ascii"),
    )


def cmd_generate_deployment(args: argparse.Namespace) -> None:
    secret_dir = Path(args.secret_dir)
    database_plain_file = secret_dir / ".database_password"
    redis_plain_file = secret_dir / ".redis_password"

    provided_database_password = read_text_if_non_empty(database_plain_file)
    provided_redis_password = read_text_if_non_empty(redis_plain_file)

    database_password = provided_database_password or generate_password(args.password_length)
    database_key = generate_key_value()
    redis_password = provided_redis_password or generate_password(args.password_length)
    redis_key = generate_key_value()
    redis_hash = hashlib.sha256(redis_password.encode("utf-8")).hexdigest()
    keep_database_plain = args.keep_database_plain

    write_text(database_plain_file, database_password)
    write_text(secret_dir / ".database_password.key", database_key)
    write_text(secret_dir / ".database_password.enc", encrypt_value(database_password, decode_key(database_key)))
    write_text(secret_dir / ".redis_password.key", redis_key)
    write_text(secret_dir / ".redis_password.enc", encrypt_value(redis_password, decode_key(redis_key)))
    write_text(
        secret_dir / ".redis.acl",
        "user default off\n"
        f"user {args.redis_user} on #{redis_hash} {redis_acl_key_pattern(args.redis_key_prefix)} "
        "+@read +@write +@connection +@scripting +@info",
    )
    if not keep_database_plain:
        ensure_writable(database_plain_file)
        database_plain_file.unlink(missing_ok=True)
    ensure_writable(redis_plain_file)
    redis_plain_file.unlink(missing_ok=True)

    print(f"secret_dir: {secret_dir}")
    print(f"database_password_source: {'provided' if provided_database_password else 'generated'}")
    print(f"database_password: {'kept' if keep_database_plain else 'removed'}")
    print("database_password_enc: written")
    print("database_password_key: written")
    print("redis_acl: written")
    print("redis_password_enc: written")
    print("redis_password_key: written")
    print("plain_redis_password_written: false")


def cmd_generate_rsa(args: argparse.Namespace) -> None:
    private_key, public_key = generate_rsa_keypair(args.bits)

    print("# Keystone RSA key pair")
    print(f"# key_size={args.bits}")
    print("KEYSTONE_RSA_PRIVATE_KEY=" + private_key)
    print("KEYSTONE_RSA_PUBLIC_KEY=" + public_key)
    print()
    print("# Raw values")
    print(private_key)
    print(public_key)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Database and Redis secret utility")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser(
        "generate-deployment",
        help="generate hidden Docker secrets for database and Redis",
    )
    generate.add_argument("--secret-dir", default=DEFAULT_SECRET_DIR)
    generate.add_argument("--redis-user", default="keystone")
    generate.add_argument("--redis-key-prefix", default=DEFAULT_REDIS_KEY_PATTERN)
    generate.add_argument("--password-length", type=int, default=DEFAULT_PASSWORD_LENGTH)
    generate.add_argument(
        "--keep-database-plain",
        action="store_true",
        help="keep docker/.secrets/.database_password for first-time database initialization",
    )
    generate.set_defaults(func=cmd_generate_deployment)

    generate_rsa = subparsers.add_parser(
        "generate-rsa",
        help="generate an RSA key pair for Keystone login password encryption",
    )
    generate_rsa.add_argument(
        "--bits",
        type=int,
        default=2048,
        choices=(2048, 3072, 4096),
        help="RSA key size. Default: 2048",
    )
    generate_rsa.set_defaults(func=cmd_generate_rsa)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
