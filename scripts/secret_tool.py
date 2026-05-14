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
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "secret:v1:aes-256-gcm"


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value + "\n", encoding="utf-8")


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
    key = base64.b64encode(os.urandom(32)).decode("ascii")
    if args.out:
        write_text(Path(args.out), key)
    else:
        print(key)


def cmd_encrypt(args: argparse.Namespace) -> None:
    if args.text is not None:
        plaintext = args.text
    elif args.text_file:
        plaintext = Path(args.text_file).read_text(encoding="utf-8").rstrip("\r\n")
    else:
        raise ValueError("--text or --text-file is required")

    key = read_key(args)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    encrypted = (
        f"{PREFIX}:"
        f"{base64.b64encode(nonce).decode('ascii')}:"
        f"{base64.b64encode(ciphertext).decode('ascii')}"
    )

    if args.out:
        write_text(Path(args.out), encrypted)
    else:
        print(encrypted)


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

    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
