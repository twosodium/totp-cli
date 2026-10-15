"""Parse otpauth:// URIs and raw secrets into account records."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlparse

DEFAULT_ALGORITHM = "SHA1"
DEFAULT_DIGITS = 6
DEFAULT_PERIOD = 30
SUPPORTED_ALGORITHMS = ("SHA1", "SHA256", "SHA512")


@dataclass(frozen=True)
class Account:
    """One TOTP account. `secret_b32` is normalized base32 (uppercase, no whitespace)."""

    name: str
    issuer: str
    label: str
    secret_b32: str
    algorithm: str = DEFAULT_ALGORITHM
    digits: int = DEFAULT_DIGITS
    period: int = DEFAULT_PERIOD


def normalize_secret(text: str) -> str:
    """Uppercase and strip whitespace; validate base32-decodability."""
    cleaned = "".join(text.split()).upper()
    if not cleaned:
        raise ValueError("empty secret")
    try:
        base64.b32decode(_pad(cleaned), casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"secret is not valid base32: {exc}") from exc
    return cleaned


def decode_secret(secret_b32: str) -> bytes:
    """Decode a normalized base32 secret to raw bytes."""
    return base64.b32decode(_pad(secret_b32), casefold=True)


def _pad(text: str) -> str:
    return text + "=" * (-len(text) % 8)


def parse_otpauth_uri(text: str, name_override: str | None = None) -> Account:
    """Parse an `otpauth://totp/...` URI. Only `totp` is accepted."""
    parts = urlparse(text.strip())
    if parts.scheme.lower() != "otpauth":
        raise ValueError(f"not an otpauth URI: {text.strip()[:40]!r}")
    if parts.netloc.lower() != "totp":
        if parts.netloc.lower() == "hotp":
            raise ValueError("HOTP URIs are not supported (TOTP only)")
        raise ValueError(f"unsupported otpauth type: {parts.netloc!r}")
    raw_label = unquote(parts.path.lstrip("/"))
    if not raw_label:
        raise ValueError("otpauth URI is missing its label")

    params = {key.lower(): value for key, value in parse_qsl(parts.query, keep_blank_values=True)}
    if "secret" not in params or not params["secret"].strip():
        raise ValueError("otpauth URI is missing the secret parameter")
    secret_b32 = normalize_secret(params["secret"])

    issuer = unquote(params.get("issuer", ""))
    algorithm = params.get("algorithm", DEFAULT_ALGORITHM).upper()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"unsupported algorithm: {algorithm!r}")
    digits = _parse_int(params.get("digits", DEFAULT_DIGITS), "digits", 6, 8)
    period = _parse_int(params.get("period", DEFAULT_PERIOD), "period", 1, 86400)

    issuer, label = split_issuer_label(raw_label, issuer)
    if not label:
        raise ValueError("otpauth URI has an empty account label")

    name = build_name(issuer, label, name_override)
    return Account(name=name, issuer=issuer, label=label, secret_b32=secret_b32,
                   algorithm=algorithm, digits=digits, period=period)


def parse_raw_secret(text: str, *, issuer: str = "", label: str,
                     name_override: str | None = None) -> Account:
    """Build an account from a pasted base32 secret with standard defaults."""
    if not label.strip():
        raise ValueError("a --label is required when adding a raw secret")
    secret_b32 = normalize_secret(text)
    issuer = issuer.strip()
    label = label.strip()
    name = name_override or (f"{issuer}:{label}" if issuer else label)
    return Account(name=name, issuer=issuer, label=label, secret_b32=secret_b32)


def split_issuer_label(raw_label: str, issuer_param: str) -> tuple[str, str]:
    """Resolve (issuer, label); a param wins, else split "issuer:label" labels."""
    if issuer_param:
        label = raw_label.split(":", 1)[1] if ":" in raw_label else raw_label
        return issuer_param, label
    if ":" in raw_label:
        issuer, label = raw_label.split(":", 1)
        return issuer, label
    return "", raw_label


def build_name(issuer: str, label: str, override: str | None = None) -> str:
    """Roster key for an account."""
    if override:
        return override
    return f"{issuer}:{label}" if issuer else label


def _parse_int(value: object, field: str, low: int, high: int) -> int:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError(f"invalid {field}: {value!r}") from None
    if not low <= number <= high:
        raise ValueError(f"invalid {field}: {value!r} (expected {low}-{high})")
    return number
