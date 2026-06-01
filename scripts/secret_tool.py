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
PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}:,.?"
DEFAULT_PASSWORD_LENGTH = 32
DEFAULT_JWT_SECRET_BYTES = 32
DEFAULT_KEYSTONE_REDIS_KEY_PATTERN = "*"
DEFAULT_KEYLO_REDIS_KEY_PREFIX = "keylo"


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

    for item in (path.parent, path):
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


def generate_jwt_secret(length_bytes: int = DEFAULT_JWT_SECRET_BYTES) -> str:
    if length_bytes < 32:
        raise ValueError("JWT secret must use at least 32 random bytes")
    return base64.urlsafe_b64encode(os.urandom(length_bytes)).decode("ascii").rstrip("=")


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


def read_key(args: argparse.Namespace) -> bytes:
    if args.key:
        return decode_key(args.key)
    if args.key_file:
        return decode_key(Path(args.key_file).read_text(encoding="utf-8"))
    raise ValueError("--key or --key-file is required")


def encrypt_value(plaintext: str, key: bytes) -> str:
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return (
        f"{PREFIX}:"
        f"{base64.b64encode(nonce).decode('ascii')}:"
        f"{base64.b64encode(ciphertext).decode('ascii')}"
    )


def decrypt_value(encrypted: str, key: bytes) -> str:
    encrypted = encrypted.strip()
    parts = encrypted.split(":", 4)
    if len(parts) != 5 or ":".join(parts[:3]) != PREFIX:
        raise ValueError(f"invalid encrypted value format: {encrypted[:32]}")

    try:
        nonce = base64.b64decode(parts[3], validate=True)
        ciphertext = base64.b64decode(parts[4], validate=True)
    except Exception as exc:
        raise ValueError("invalid encrypted value payload") from exc

    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise ValueError("failed to decrypt value") from exc

    return plaintext.decode("utf-8")


def write_database_secret(
    secret_dir: Path,
    password_length: int,
    keep_plain: bool,
) -> tuple[Path, Path, Path, bool]:
    plain_file = secret_dir / ".database_password"
    key_file = secret_dir / ".database_password.key"
    enc_file = secret_dir / ".database_password.enc"

    provided_password = read_text_if_non_empty(plain_file)
    password = provided_password or generate_password(password_length)
    key_text = generate_key_value()

    write_text(plain_file, password)
    write_text(key_file, key_text)
    write_text(enc_file, encrypt_value(password, decode_key(key_text)))

    if not keep_plain:
        ensure_writable(plain_file)
        plain_file.unlink(missing_ok=True)

    return plain_file, key_file, enc_file, provided_password is not None


def write_keystone_redis_secret(args: argparse.Namespace) -> tuple[Path, Path, Path, bool]:
    secret_dir = Path(args.secret_dir)
    plain_file = secret_dir / ".redis_password"
    key_file = secret_dir / ".redis_password.key"
    enc_file = secret_dir / ".redis_password.enc"
    acl_file = secret_dir / ".redis.acl"

    provided_password = read_text_if_non_empty(plain_file)
    password = provided_password or generate_password(args.password_length)
    key_text = generate_key_value()
    password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    acl_text = (
        "user default off\n"
        f"user {args.redis_user} on #{password_hash} "
        f"{redis_acl_key_pattern(args.redis_key_prefix)} +@read +@write +@connection +@scripting +info"
    )

    write_text(key_file, key_text)
    write_text(enc_file, encrypt_value(password, decode_key(key_text)))
    write_text(acl_file, acl_text)

    ensure_writable(plain_file)
    plain_file.unlink(missing_ok=True)

    return acl_file, key_file, enc_file, provided_password is not None


def write_keylo_redis_secret(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    plain_file = Path(args.secret_dir) / ".redis_password"
    provided_password = read_text_if_non_empty(plain_file)
    password = provided_password or base64.b64encode(
        os.urandom(args.redis_password_bytes)
    ).decode("ascii")
    password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    username = args.redis_user.strip()
    key_prefix = args.redis_key_prefix.strip()

    key_text = generate_key_value()
    acl_text = (
        "user default off\n"
        f"user {username} on #{password_hash} ~{key_prefix}:* +@read +@write +@connection +info"
    )

    acl_file = Path(args.acl_out)
    key_file = Path(args.key_out)
    enc_file = Path(args.enc_out)
    write_text(acl_file, acl_text)
    write_text(key_file, key_text)
    write_text(enc_file, encrypt_value(password, decode_key(key_text)))
    ensure_writable(plain_file)
    plain_file.unlink(missing_ok=True)
    return acl_file, key_file, enc_file


def generate_rsa_keypair(bits: int, output_format: str) -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()

    if output_format == "pem":
        private_value = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")
        public_value = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        return private_value, public_value

    private_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return (
        base64.b64encode(private_der).decode("ascii"),
        base64.b64encode(public_der).decode("ascii"),
    )


def cmd_generate_key(args: argparse.Namespace) -> None:
    key = generate_key_value()
    if args.out:
        write_text(Path(args.out), key)
    else:
        print(key)


def cmd_generate_jwt_secret(args: argparse.Namespace) -> None:
    jwt_secret = generate_jwt_secret(args.bytes)
    if args.out:
        write_text(Path(args.out), jwt_secret)
    elif args.raw:
        print(jwt_secret)
    else:
        print(f"{args.env_name}={jwt_secret}")


def cmd_encrypt(args: argparse.Namespace) -> None:
    if args.text is not None:
        plaintext = args.text
    elif args.text_file:
        plaintext = Path(args.text_file).read_text(encoding="utf-8").rstrip("\r\n")
    else:
        raise ValueError("--text or --text-file is required")

    encrypted = encrypt_value(plaintext, read_key(args))
    if args.out:
        write_text(Path(args.out), encrypted)
    else:
        print(encrypted)


def cmd_decrypt(args: argparse.Namespace) -> None:
    if args.text is not None:
        encrypted = args.text
    elif args.text_file:
        encrypted = Path(args.text_file).read_text(encoding="utf-8")
    else:
        raise ValueError("--text or --text-file is required")

    plaintext = decrypt_value(encrypted, read_key(args))
    if args.out:
        write_text(Path(args.out), plaintext)
    else:
        print(plaintext)


def cmd_encrypt_file_and_remove(args: argparse.Namespace) -> None:
    text_file = Path(args.text_file)
    key_file = Path(args.key_file)
    out_file = Path(args.out)

    if not text_file.is_file():
        raise FileNotFoundError(f"plain text password file does not exist: {text_file}")
    if out_file.exists() and not args.force:
        raise FileExistsError(
            f"encrypted output already exists: {out_file}; pass --force to overwrite"
        )

    plaintext = text_file.read_text(encoding="utf-8").rstrip("\r\n")
    if not plaintext:
        raise ValueError(f"plain text password file is empty: {text_file}")

    if key_file.exists():
        key_text = key_file.read_text(encoding="utf-8")
        key = decode_key(key_text)
        created_key = False
    else:
        key_text = generate_key_value()
        write_text(key_file, key_text)
        key = decode_key(key_text)
        created_key = True

    write_text(out_file, encrypt_value(plaintext, key))
    text_file.unlink(missing_ok=True)

    print(f"encrypted: {out_file}")
    print(f"key_file: {key_file} ({'created' if created_key else 'reused'})")
    print(f"removed_plaintext: {text_file}")


def cmd_generate_keystone_deployment(args: argparse.Namespace) -> None:
    secret_dir = Path(args.secret_dir)
    database_plain, database_key, database_enc, provided_database_password = (
        write_database_secret(secret_dir, args.password_length, args.keep_database_plain)
    )
    redis_acl, redis_key, redis_enc, provided_redis_password = write_keystone_redis_secret(args)

    print(f"secret_dir: {secret_dir}")
    print(f"database_password_source: {'provided' if provided_database_password else 'generated'}")
    print(f"database_password: {'kept' if args.keep_database_plain else 'removed'}")
    print(f"database_password_enc: {database_enc}")
    print(f"database_password_key: {database_key}")
    print(f"database_password_plain: {database_plain}")
    print(f"redis_password_source: {'provided' if provided_redis_password else 'generated'}")
    print(f"redis_acl: {redis_acl}")
    print(f"redis_password_enc: {redis_enc}")
    print(f"redis_password_key: {redis_key}")
    print("plain_redis_password_written: false")


def cmd_generate_keylo_redis(args: argparse.Namespace) -> None:
    secret_dir = Path(args.secret_dir)
    args.acl_out = args.acl_out or str(secret_dir / ".redis.acl")
    args.key_out = args.key_out or str(secret_dir / ".redis_password.key")
    args.enc_out = args.enc_out or str(secret_dir / ".redis_password.enc")
    acl_file, key_file, enc_file = write_keylo_redis_secret(args)
    print(f"redis_acl: {acl_file}")
    print(f"redis_password_key: {key_file}")
    print(f"redis_password_enc: {enc_file}")
    print("plain_password_written: false")


def cmd_generate_keylo_deployment(args: argparse.Namespace) -> None:
    secret_dir = Path(args.secret_dir)
    database_plain, database_key, database_enc, provided_database_password = (
        write_database_secret(secret_dir, args.password_length, args.keep_database_plain)
    )

    args.acl_out = str(secret_dir / ".redis.acl")
    args.key_out = str(secret_dir / ".redis_password.key")
    args.enc_out = str(secret_dir / ".redis_password.enc")
    acl_file, redis_key, redis_enc = write_keylo_redis_secret(args)

    print(f"secret_dir: {secret_dir}")
    print(f"database_password_source: {'provided' if provided_database_password else 'generated'}")
    print(f"database_password: {'kept' if args.keep_database_plain else 'removed'}")
    print(f"database_password_enc: {database_enc}")
    print(f"database_password_key: {database_key}")
    print(f"database_password_plain: {database_plain}")
    print(f"redis_acl: {acl_file}")
    print(f"redis_password_enc: {redis_enc}")
    print(f"redis_password_key: {redis_key}")
    print("plain_redis_password_written: false")


def cmd_generate_rsa(args: argparse.Namespace) -> None:
    private_value, public_value = generate_rsa_keypair(args.bits, args.format)

    if args.format == "der-env":
        print("# Keystone RSA key pair")
        print(f"# key_size={args.bits}")
        print("KEYSTONE_RSA_PRIVATE_KEY=" + private_value)
        print("KEYSTONE_RSA_PUBLIC_KEY=" + public_value)
        if args.raw:
            print()
            print("# Raw values")
            print(private_value)
            print(public_value)
        return

    if args.stdout:
        print("# RSA key pair")
        print(f"# key_size={args.bits}")
        print("# private_key_pem")
        print(private_value.rstrip("\n"))
        print("# public_key_pem")
        print(public_value.rstrip("\n"))
        return

    private_path = Path(args.out_private)
    public_path = Path(args.out_public)
    write_text(private_path, private_value.rstrip("\n"))
    write_text(public_path, public_value.rstrip("\n"))
    if os.name != "nt":
        private_path.chmod(0o600)
        public_path.chmod(0o644)
    print(f"rsa_private_key: {private_path}")
    print(f"rsa_public_key: {public_path}")
    print(f"key_size: {args.bits}")


def add_database_args(parser: argparse.ArgumentParser, default_secret_dir: str) -> None:
    parser.add_argument("--secret-dir", default=default_secret_dir)
    parser.add_argument("--password-length", type=int, default=DEFAULT_PASSWORD_LENGTH)
    parser.add_argument(
        "--keep-database-plain",
        action="store_true",
        help="keep .database_password for first-time database initialization",
    )


def add_keylo_redis_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--redis-user", default="keylo")
    parser.add_argument("--redis-key-prefix", default=DEFAULT_KEYLO_REDIS_KEY_PREFIX)
    parser.add_argument("--secret-dir", default=".secrets")
    parser.add_argument("--redis-password-bytes", type=int, default=32)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Keylo secret utility")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate_key = subparsers.add_parser("generate-key", help="generate a base64 AES-256 key")
    generate_key.add_argument("--out", help="write generated key to this file")
    generate_key.set_defaults(func=cmd_generate_key)

    jwt_secret = subparsers.add_parser(
        "generate-jwt-secret",
        help="generate a random secret for TOKEN_SECRET",
    )
    jwt_secret.add_argument("--bytes", type=int, default=DEFAULT_JWT_SECRET_BYTES)
    jwt_secret.add_argument("--env-name", default="TOKEN_SECRET")
    jwt_secret.add_argument("--raw", action="store_true", help="print only the secret value")
    jwt_secret.add_argument("--out", help="write only the secret value to this file")
    jwt_secret.set_defaults(func=cmd_generate_jwt_secret)

    encrypt = subparsers.add_parser("encrypt", help="encrypt text with AES-256-GCM")
    encrypt.add_argument("--text", help="plain text value to encrypt")
    encrypt.add_argument("--text-file", help="file containing plain text to encrypt")
    encrypt.add_argument("--key", help="32-byte raw key or base64 AES-256 key")
    encrypt.add_argument("--key-file", help="file containing the key")
    encrypt.add_argument("--out", help="write encrypted value to this file")
    encrypt.set_defaults(func=cmd_encrypt)

    decrypt = subparsers.add_parser("decrypt", help="decrypt text with AES-256-GCM")
    decrypt.add_argument("--text", help="encrypted value to decrypt")
    decrypt.add_argument("--text-file", help="file containing encrypted value to decrypt")
    decrypt.add_argument("--key", help="32-byte raw key or base64 AES-256 key")
    decrypt.add_argument("--key-file", help="file containing the key")
    decrypt.add_argument("--out", help="write decrypted value to this file")
    decrypt.set_defaults(func=cmd_decrypt)

    encrypt_file = subparsers.add_parser(
        "encrypt-file-and-remove",
        help="encrypt a plain text file, then delete the plain text file",
    )
    encrypt_file.add_argument("--text-file", default=".secrets/.database_password")
    encrypt_file.add_argument("--key-file", default=".secrets/.database_password.key")
    encrypt_file.add_argument("--out", default=".secrets/.database_password.enc")
    encrypt_file.add_argument("--force", action="store_true")
    encrypt_file.set_defaults(func=cmd_encrypt_file_and_remove)

    keystone = subparsers.add_parser(
        "generate-keystone-deployment",
        help="generate shared MySQL and Keystone Redis secrets",
    )
    add_database_args(keystone, ".secrets")
    keystone.add_argument("--redis-user", default="keystone")
    keystone.add_argument("--redis-key-prefix", default=DEFAULT_KEYSTONE_REDIS_KEY_PATTERN)
    keystone.set_defaults(func=cmd_generate_keystone_deployment)

    keylo_redis = subparsers.add_parser(
        "generate-keylo-redis",
        help="generate Keylo Redis ACL, AES key, and encrypted Redis password",
    )
    add_keylo_redis_args(keylo_redis)
    keylo_redis.add_argument("--acl-out")
    keylo_redis.add_argument("--key-out")
    keylo_redis.add_argument("--enc-out")
    keylo_redis.set_defaults(func=cmd_generate_keylo_redis)

    keylo = subparsers.add_parser(
        "generate-keylo-deployment",
        help="generate Keylo Postgres and Redis password secrets",
    )
    add_database_args(keylo, ".secrets")
    keylo.add_argument("--redis-user", default="keylo")
    keylo.add_argument("--redis-key-prefix", default=DEFAULT_KEYLO_REDIS_KEY_PREFIX)
    keylo.add_argument("--redis-password-bytes", type=int, default=32)
    keylo.set_defaults(func=cmd_generate_keylo_deployment)

    deployment = subparsers.add_parser(
        "generate-deployment",
        help="alias for generate-keylo-deployment",
    )
    add_database_args(deployment, ".secrets")
    deployment.add_argument("--redis-user", default="keylo")
    deployment.add_argument("--redis-key-prefix", default=DEFAULT_KEYLO_REDIS_KEY_PREFIX)
    deployment.add_argument("--redis-password-bytes", type=int, default=32)
    deployment.set_defaults(func=cmd_generate_keylo_deployment)

    redis = subparsers.add_parser(
        "generate-redis",
        help="alias for generate-keylo-redis",
    )
    add_keylo_redis_args(redis)
    redis.add_argument("--acl-out")
    redis.add_argument("--key-out")
    redis.add_argument("--enc-out")
    redis.set_defaults(func=cmd_generate_keylo_redis)

    rsa_parser = subparsers.add_parser("generate-rsa", help="generate an RSA key pair")
    rsa_parser.add_argument("--bits", type=int, default=2048, choices=(2048, 3072, 4096))
    rsa_parser.add_argument(
        "--format",
        choices=("der-env", "pem"),
        default="pem",
        help="pem writes or prints PEM files; der-env prints KEYSTONE_RSA_* values",
    )
    rsa_parser.add_argument("--out-private", default="keys/private.pem")
    rsa_parser.add_argument("--out-public", default="keys/public.pem")
    rsa_parser.add_argument("--stdout", action="store_true", help="print PEM keys")
    rsa_parser.add_argument(
        "--raw",
        action="store_true",
        help="also print raw base64 DER values with --format der-env",
    )
    rsa_parser.set_defaults(func=cmd_generate_rsa)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
