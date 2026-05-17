#!/usr/bin/env python3
"""Generate and encrypt shared deployment secrets.

The encrypted value format is:

    secret:v1:aes-256-gcm:<nonce_base64>:<ciphertext_base64>

It uses AES-256-GCM with a random 12-byte nonce. The GCM tag is appended to
the ciphertext by cryptography's AESGCM implementation, matching Java, .NET,
Rust, and Python defaults.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import stat
import subprocess
from pathlib import Path
from urllib.parse import quote

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "secret:v1:aes-256-gcm"
DEFAULT_TEXT_FILE = ".secrets/.postgres_password"
DEFAULT_KEY_FILE = ".secrets/.database_password.key"
DEFAULT_OUT_FILE = ".secrets/.postgres_password.enc"
DEFAULT_REDIS_ACL_FILE = ".secrets/.redis.acl"
DEFAULT_REDIS_URL_KEY_FILE = ".secrets/.redis_url.key"
DEFAULT_REDIS_URL_ENC_FILE = ".secrets/.redis_url.enc"


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
            os.system(f'attrib +h "{item}" >nul 2>nul')


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    ensure_writable(path)
    path.write_text(value + "\n", encoding="utf-8")
    hide_if_dot_path(path)


def generate_key_value() -> str:
    return base64.b64encode(os.urandom(32)).decode("ascii")


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


def cmd_generate_key(args: argparse.Namespace) -> None:
    key = generate_key_value()
    if args.out:
        write_text(Path(args.out), key)
    else:
        print(key)


def encrypt_value(plaintext: str, key: bytes) -> str:
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return (
        f"{PREFIX}:"
        f"{base64.b64encode(nonce).decode('ascii')}:"
        f"{base64.b64encode(ciphertext).decode('ascii')}"
    )


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


def cmd_generate_redis(args: argparse.Namespace) -> None:
    password = base64.b64encode(os.urandom(args.password_bytes)).decode("ascii")
    password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    username = args.username.strip()
    key_prefix = args.key_prefix.strip()
    redis_url = (
        f"redis://{quote(username, safe='')}:"
        f"{quote(password, safe='')}@{args.host}:{args.port}"
    )

    key_text = generate_key_value()
    encrypted_url = encrypt_value(redis_url, decode_key(key_text))
    acl_text = (
        "user default off\n"
        f"user {username} on #{password_hash} ~{key_prefix}:* +@read +@write +@connection\n"
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
    write_text(enc_file, encrypted_url)

    print(f"redis_acl: {acl_file}")
    print(f"redis_url_key: {key_file}")
    print(f"redis_url_enc: {enc_file}")
    print("plain_password_written: false")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Shared AES-256-GCM secret utility")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate_key = subparsers.add_parser("generate-key", help="generate a base64 AES-256 key")
    generate_key.add_argument("--out", help="write generated key to this file")
    generate_key.set_defaults(func=cmd_generate_key)

    encrypt = subparsers.add_parser("encrypt", help="encrypt text with AES-256-GCM")
    encrypt.add_argument("--text", help="plain text value to encrypt")
    encrypt.add_argument("--text-file", help="file containing plain text to encrypt")
    encrypt.add_argument("--key", help="32-byte raw key or base64 AES-256 key")
    encrypt.add_argument("--key-file", help="file containing the key")
    encrypt.add_argument("--out", help="write encrypted value to this file")
    encrypt.set_defaults(func=cmd_encrypt)

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

    generate_redis = subparsers.add_parser(
        "generate-redis",
        help=(
            "generate Redis ACL hash, AES key, and encrypted Redis URL without "
            "writing the plain password"
        ),
    )
    generate_redis.add_argument(
        "--username",
        default="keylo",
        help="Redis ACL username (default: keylo)",
    )
    generate_redis.add_argument(
        "--key-prefix",
        default="keylo",
        help="Redis key prefix allowed by ACL (default: keylo)",
    )
    generate_redis.add_argument(
        "--host",
        default="redis",
        help="Redis host used in the encrypted URL (default: redis)",
    )
    generate_redis.add_argument(
        "--port",
        default="6379",
        help="Redis port used in the encrypted URL (default: 6379)",
    )
    generate_redis.add_argument(
        "--password-bytes",
        type=int,
        default=32,
        help="number of random bytes for the generated password (default: 32)",
    )
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

    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
