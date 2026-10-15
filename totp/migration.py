"""Import Google Authenticator exports (otpauth-migration:// URIs).

The `data` parameter is a base64-encoded MigrationPayload protobuf. This module
decodes the protobuf wire format with the standard library only; the schema it
reads is: OtpParameters{secret=1, name=2, issuer=3, algorithm=4, digits=5,
type=6}, with algorithm 0/1=SHA1 2=SHA256 3=SHA512, digits 0/1=6 2=8, and
type 1=HOTP 2=TOTP.
"""

from __future__ import annotations

import base64
import binascii
from urllib.parse import unquote, urlparse

from .uri import Account, build_name, split_issuer_label

_ALGORITHMS = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512"}
_DIGITS = {0: 6, 1: 6, 2: 8}


def parse_migration_uri(text: str) -> tuple[list[Account], list[str]]:
    """Decode a migration URI into (accounts, skipped-reasons)."""
    parts = urlparse(text.strip())
    if parts.scheme.lower() != "otpauth-migration":
        raise ValueError(f"not a migration URI: {text.strip()[:40]!r}")
    data = _data_param(parts.query)
    if not data:
        raise ValueError("migration URI is missing the data parameter")
    payload = _b64decode(data)

    accounts: list[Account] = []
    skipped: list[str] = []
    entries = [value for number, wire, value in _decode_fields(payload)
               if number == 1 and wire == 2]
    for raw in entries:
        try:
            account = _parse_entry(raw)
        except ValueError as exc:
            skipped.append(f"(unreadable entry: {exc})")
            continue
        if isinstance(account, Account):
            accounts.append(account)
        else:
            skipped.append(account)
    if not accounts and not skipped:
        raise ValueError("migration payload contains no accounts")
    return accounts, skipped


def _parse_entry(raw: bytes) -> Account | str:
    """Parse one OtpParameters message; returns an Account or a skip reason."""
    entry = {number: value for number, _, value in _decode_fields(raw)}
    secret = entry.get(1, b"")
    try:
        name = entry.get(2, b"").decode("utf-8")
        issuer = entry.get(3, b"").decode("utf-8")
    except (UnicodeDecodeError, AttributeError):
        return "(unreadable entry: bad name encoding)"
    tag = name or "(unnamed)"
    if not isinstance(secret, bytes) or not secret:
        return f"{tag} (empty secret)"
    entry_type = entry.get(6, 2)
    if entry_type == 1:
        return f"{tag} (HOTP not supported)"
    if entry_type != 2:
        return f"{tag} (unsupported entry type)"
    algorithm = _ALGORITHMS.get(entry.get(4, 0))
    if algorithm is None:
        return f"{tag} (unsupported algorithm)"
    digits = _DIGITS.get(entry.get(5, 0))
    if digits is None:
        return f"{tag} (unsupported digit count)"
    issuer, label = split_issuer_label(name, issuer)
    if not label:
        return f"{tag} (empty label)"
    secret_b32 = base64.b32encode(secret).decode("ascii").rstrip("=")
    return Account(name=build_name(issuer, label), issuer=issuer, label=label,
                   secret_b32=secret_b32, algorithm=algorithm, digits=digits, period=30)


def _data_param(query: str) -> str:
    """Extract `data` without turning base64 '+' into spaces (parse_qsl would)."""
    for chunk in query.split("&"):
        key, separator, value = chunk.partition("=")
        if separator and key == "data":
            return unquote(value).strip()
    return ""


def _b64decode(data: str) -> bytes:
    padded = data + "=" * (-len(data) % 4)
    for kwargs in ({}, {"altchars": b"-_"}):
        try:
            return base64.b64decode(padded, validate=True, **kwargs)
        except (binascii.Error, ValueError):
            continue
    raise ValueError("migration data is not valid base64")


def _decode_fields(buf: bytes) -> list[tuple[int, int, int | bytes]]:
    """Parse protobuf fields into (field_number, wire_type, value) triples."""
    fields: list[tuple[int, int, int | bytes]] = []
    pos = 0
    while pos < len(buf):
        key, pos = _varint(buf, pos)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = _varint(buf, pos)
        elif wire == 2:
            length, pos = _varint(buf, pos)
            value = bytes(buf[pos:pos + length])
            if len(value) != length:
                raise ValueError("truncated migration payload")
            pos += length
        elif wire in (1, 5):
            size = 8 if wire == 1 else 4
            value = bytes(buf[pos:pos + size])
            if len(value) != size:
                raise ValueError("truncated migration payload")
            pos += size
        else:
            raise ValueError(f"unsupported wire type {wire} in migration payload")
        fields.append((number, wire, value))
    return fields


def _varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated migration payload")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift >= 64:
            raise ValueError("oversized varint in migration payload")
