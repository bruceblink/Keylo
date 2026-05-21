#!/usr/bin/env python3
"""Generate and encrypt shared deployment secrets.

The encrypted value format is:

    secret:v1:aes-256-gcm:<nonce_base64>:<ciphertext_base64>

It uses AES-256-GCM with a random 12-byte nonce. The GCM tag is appended to
the ciphertext by cryptography's AESGCM implementation, matching Java, .NET,
Rust, and Python defaults.

The tool also covers shared deployment flows used across the Keylo and
docker-compose-all layouts, including JWT secret generation and RSA export
helpers.
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
from urllib.parse import quote

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "secret:v1:aes-256-gcm"
DEFAULT_TEXT_FILE = ".secrets/.database_password"
DEFAULT_KEY_FILE = ".secrets/.database_password.key"
DEFAULT_OUT_FILE = ".secrets/.database_password.enc"
DEFAULT_REDIS_ACL_FILE = ".secrets/.redis.acl"
DEFAULT_REDIS_URL_KEY_FILE = ".secrets/.redis_url.key"
DEFAULT_REDIS_URL_ENC_FILE = ".secrets/.redis_url.enc"
DEFAULT_RSA_PRIVATE_KEY_FILE = "keys/private.pem"
DEFAULT_RSA_PUBLIC_KEY_FILE = "keys/public.pem"
PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}:,.?"
DEFAULT_PASSWORD_LENGTH = 32
DEFAULT_JWT_SECRET_BYTES = 32
DEFAULT_KEYSTONE_REDIS_KEY_PATTERN = "*"


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
    path.write_text(value + "\n", encoding="utf-8")
    hide_if_dot_path(path)


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


def redis_acl_key_pattern(value: str) -> str:
    value = value.strip()
    if value in ("*", "~*"):
        return "~*"
    if value.startswith("~"):
        return value
    return f"~{value}:*"


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
        out_file = Path(args.out)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        ensure_writable(out_file)
        out_file.write_text(plaintext, encoding="utf-8")
        hide_if_dot_path(out_file)
    else:
        print(plaintext)


def cmd_encrypt_file_and_remove(args: argparse.Namespace) -> None:
    text_file = Path(args.text_file)
    key_file = Path(args.key_file)
    out_file = Path(args.out)

    if not text_file.is_file():
        raise FileNotFoundError(
            f"plain text password file does not exist: {text_file}"
        )
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

    encrypted = encrypt_value(plaintext, key)
    write_text(out_file, encrypted)

    try:
        text_file.unlink()
    except FileNotFoundError:
        pass

    print(f"encrypted: {out_file}")
    print(f"key_file: {key_file} ({'created' if created_key else 'reused'})")
    print(f"removed_plaintext: {text_file}")


def write_keylo_redis_secret(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    password = base64.b64encode(os.urandom(args.redis_password_bytes)).decode("ascii")
    password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    username = args.redis_username.strip()
    key_prefix = args.redis_key_prefix.strip()
    redis_url = (
        f"redis://{quote(username, safe='')}:"
        f"{quote(password, safe='')}@{args.redis_host}:{args.redis_port}"
    )

    key_text = generate_key_value()
    acl_text = (
        "user default off\n"
        f"user {username} on #{password_hash} {redis_acl_key_pattern(key_prefix)} "
        "+@read +@write +@connection\n"
    )

    acl_file = Path(args.acl_out)
    key_file = Path(args.key_out)
    enc_file = Path(args.enc_out)
    acl_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.parent.mkdir(parents=True, exist_ok=True)
    enc_file.parent.mkdir(parents=True, exist_ok=True)
    ensure_writable(acl_file)
    acl_file.write_text(acl_text, encoding="utf-8")
    hide_if_dot_path(acl_file)
    write_text(key_file, key_text)
    write_text(enc_file, encrypt_value(redis_url, decode_key(key_text)))

    return acl_file, key_file, enc_file


def write_database_secret(args: argparse.Namespace) -> tuple[Path, Path, Path, bool, bool]:
    secret_dir = Path(args.secret_dir)
    plain_file = secret_dir / ".database_password"
    key_file = secret_dir / ".database_password.key"
    enc_file = secret_dir / ".database_password.enc"

    provided_password = read_text_if_non_empty(plain_file)
    password = provided_password or generate_password(args.password_length)
    key_text = generate_key_value()

    write_text(plain_file, password)
    write_text(key_file, key_text)
    write_text(enc_file, encrypt_value(password, decode_key(key_text)))

    keep_plain = args.keep_database_plain
    if not keep_plain:
        ensure_writable(plain_file)
        plain_file.unlink(missing_ok=True)

    return plain_file, key_file, enc_file, provided_password is not None, keep_plain


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
        f"{redis_acl_key_pattern(args.redis_key_prefix)} +@read +@write +@connection +@scripting\n"
    )

    write_text(key_file, key_text)
    write_text(enc_file, encrypt_value(password, decode_key(key_text)))
    write_text(acl_file, acl_text.rstrip("\n"))

    ensure_writable(plain_file)
    plain_file.unlink(missing_ok=True)

    return acl_file, key_file, enc_file, provided_password is not None


def cmd_generate_redis(args: argparse.Namespace) -> None:
    acl_file, key_file, enc_file = write_keylo_redis_secret(args)

    print(f"redis_acl: {acl_file}")
    print(f"redis_url_key: {key_file}")
    print(f"redis_url_enc: {enc_file}")
    print("plain_password_written: false")


def cmd_generate_deployment(args: argparse.Namespace) -> None:
    database_plain, database_key, database_enc, provided_database_password, keep_database_plain = (
        write_database_secret(args)
    )

    redis_args = argparse.Namespace(
        redis_username=args.redis_username,
        redis_key_prefix=args.redis_key_prefix,
        redis_host=args.redis_host,
        redis_port=args.redis_port,
        redis_password_bytes=args.redis_password_bytes,
        acl_out=str(Path(args.secret_dir) / ".redis.acl"),
        key_out=str(Path(args.secret_dir) / ".redis_url.key"),
        enc_out=str(Path(args.secret_dir) / ".redis_url.enc"),
    )
    cmd_generate_redis(redis_args)

    print(f"secret_dir: {Path(args.secret_dir)}")
    print(f"database_password_source: {'provided' if provided_database_password else 'generated'}")
    print(f"database_password: {'kept' if keep_database_plain else 'removed'}")
    print(f"database_password_enc: {database_enc}")
    print(f"database_password_key: {database_key}")
    print(f"database_password_plain: {database_plain}")


def cmd_generate_keystone_deployment(args: argparse.Namespace) -> None:
    secret_dir = Path(args.secret_dir)
    database_plain, database_key, database_enc, provided_database_password, keep_database_plain = (
        write_database_secret(args)
    )
    redis_acl, redis_key, redis_enc, provided_redis_password = write_keystone_redis_secret(args)

    print(f"secret_dir: {secret_dir}")
    print(f"database_password_source: {'provided' if provided_database_password else 'generated'}")
    print(f"database_password: {'kept' if keep_database_plain else 'removed'}")
    print(f"database_password_enc: {database_enc}")
    print(f"database_password_key: {database_key}")
    print(f"database_password_plain: {database_plain}")
    print(f"redis_password_source: {'provided' if provided_redis_password else 'generated'}")
    print(f"redis_acl: {redis_acl}")
    print(f"redis_password_enc: {redis_enc}")
    print(f"redis_password_key: {redis_key}")
    print("plain_redis_password_written: false")


def generate_rsa_keypair(bits: int, output_format: str) -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()

    if output_format == "pem":
        private_key_value = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")
        public_key_value = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        return private_key_value, public_key_value

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


def cmd_generate_rsa(args: argparse.Namespace) -> None:
    private_key_value, public_key_value = generate_rsa_keypair(args.bits, args.format)

    if args.format == "der-env":
        print("# Keystone RSA key pair")
        print(f"# key_size={args.bits}")
        print("KEYSTONE_RSA_PRIVATE_KEY=" + private_key_value)
        print("KEYSTONE_RSA_PUBLIC_KEY=" + public_key_value)
        if args.raw:
            print()
            print("# Raw values")
            print(private_key_value)
            print(public_key_value)
        return

    if args.stdout:
        print("# Keylo RSA key pair")
        print(f"# key_size={args.bits}")
        print("# private_key_pem")
        print(private_key_value.rstrip("\n"))
        print("# public_key_pem")
        print(public_key_value.rstrip("\n"))
        return

    private_path = Path(args.out_private)
    public_path = Path(args.out_public)
    write_text(private_path, private_key_value.rstrip("\n"))
    write_text(public_path, public_key_value.rstrip("\n"))
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
    parser.add_argument("--redis-username", "--redis-user", "--username", default="keylo")
    parser.add_argument("--redis-key-prefix", "--key-prefix", default="keylo")
    parser.add_argument("--redis-host", "--host", default="redis")
    parser.add_argument("--redis-port", "--port", default="6379")
    parser.add_argument("--redis-password-bytes", "--password-bytes", type=int, default=32)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Shared AES-256-GCM secret utility")
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

    encrypt_file_and_remove = subparsers.add_parser(
        "encrypt-file-and-remove",
        help=(
            "read a plain text password file, create the key file if missing, "
            "write encrypted output, then delete the plain text file"
        ),
    )
    encrypt_file_and_remove.add_argument(
        "--text-file",
        default=DEFAULT_TEXT_FILE,
        help=f"plain text password file to read and remove (default: {DEFAULT_TEXT_FILE})",
    )
    encrypt_file_and_remove.add_argument(
        "--key-file",
        default=DEFAULT_KEY_FILE,
        help=f"key file to reuse or create (default: {DEFAULT_KEY_FILE})",
    )
    encrypt_file_and_remove.add_argument(
        "--out",
        default=DEFAULT_OUT_FILE,
        help=f"encrypted output file (default: {DEFAULT_OUT_FILE})",
    )
    encrypt_file_and_remove.add_argument(
        "--force",
        action="store_true",
        help="overwrite encrypted output if it already exists",
    )
    encrypt_file_and_remove.set_defaults(func=cmd_encrypt_file_and_remove)

    keystone = subparsers.add_parser(
        "generate-keystone-deployment",
        help="generate shared database and Keystone Redis secrets",
    )
    add_database_args(keystone, ".secrets")
    keystone.add_argument("--redis-user", default="keystone")
    keystone.add_argument("--redis-key-prefix", default=DEFAULT_KEYSTONE_REDIS_KEY_PATTERN)
    keystone.set_defaults(func=cmd_generate_keystone_deployment)

    generate_redis = subparsers.add_parser(
        "generate-redis",
        help=(
            "generate Redis ACL hash, AES key, and encrypted Redis URL without "
            "writing the plain password"
        ),
    )
    add_keylo_redis_args(generate_redis)
    generate_redis.add_argument(
        "--acl-out",
        default=DEFAULT_REDIS_ACL_FILE,
        help=f"Redis ACL output path (default: {DEFAULT_REDIS_ACL_FILE})",
    )
    generate_redis.add_argument(
        "--key-out",
        default=DEFAULT_REDIS_URL_KEY_FILE,
        help=f"AES key output path (default: {DEFAULT_REDIS_URL_KEY_FILE})",
    )
    generate_redis.add_argument(
        "--enc-out",
        default=DEFAULT_REDIS_URL_ENC_FILE,
        help=f"encrypted Redis URL output path (default: {DEFAULT_REDIS_URL_ENC_FILE})",
    )
    generate_redis.set_defaults(func=cmd_generate_redis)

    generate_keylo_redis = subparsers.add_parser(
        "generate-keylo-redis",
        help="alias for generate-redis",
    )
    add_keylo_redis_args(generate_keylo_redis)
    generate_keylo_redis.add_argument("--acl-out", default="keylo/.secrets/.redis.acl")
    generate_keylo_redis.add_argument("--key-out", default="keylo/.secrets/.redis_url.key")
    generate_keylo_redis.add_argument("--enc-out", default="keylo/.secrets/.redis_url.enc")
    generate_keylo_redis.set_defaults(func=cmd_generate_redis)

    generate_deployment = subparsers.add_parser(
        "generate-deployment",
        help="generate database and Redis deployment secrets",
    )
    add_database_args(generate_deployment, ".secrets")
    add_keylo_redis_args(generate_deployment)
    generate_deployment.set_defaults(func=cmd_generate_deployment)

    generate_keylo_deployment = subparsers.add_parser(
        "generate-keylo-deployment",
        help="alias for generate-deployment",
    )
    add_database_args(generate_keylo_deployment, "keylo/.secrets")
    add_keylo_redis_args(generate_keylo_deployment)
    generate_keylo_deployment.set_defaults(func=cmd_generate_deployment)

    generate_rsa = subparsers.add_parser(
        "generate-rsa",
        help="generate an RSA key pair for JWT signing",
    )
    generate_rsa.add_argument(
        "--bits",
        type=int,
        default=2048,
        choices=(2048, 3072, 4096),
        help="RSA key size. Default: 2048",
    )
    generate_rsa.add_argument(
        "--format",
        choices=("pem", "der-env"),
        default="pem",
        help="pem writes or prints PEM files; der-env prints KEYSTONE_RSA_* values",
    )
    generate_rsa.add_argument(
        "--out-private",
        default=DEFAULT_RSA_PRIVATE_KEY_FILE,
        help=f"private key output path (default: {DEFAULT_RSA_PRIVATE_KEY_FILE})",
    )
    generate_rsa.add_argument(
        "--out-public",
        default=DEFAULT_RSA_PUBLIC_KEY_FILE,
        help=f"public key output path (default: {DEFAULT_RSA_PUBLIC_KEY_FILE})",
    )
    generate_rsa.add_argument(
        "--stdout",
        action="store_true",
        help="print PEM keys instead of writing files",
    )
    generate_rsa.add_argument(
        "--raw",
        action="store_true",
        help="also print raw base64 DER values when using --format der-env",
    )
    generate_rsa.set_defaults(func=cmd_generate_rsa)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
