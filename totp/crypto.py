"""RFC 6238 TOTP computation over the RFC 4226 HOTP core."""

from __future__ import annotations

import hashlib
import hmac

_DIGESTS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}


def hotp(secret: bytes, counter: int, digits: int = 6, algorithm: str = "SHA1") -> str:
    """HMAC-based one-time password for a counter value."""
    if counter < 0:
        raise ValueError("counter must be non-negative")
    try:
        digestmod = _DIGESTS[algorithm.upper()]
    except KeyError:
        raise ValueError(f"unsupported algorithm: {algorithm!r}") from None
    mac = hmac.new(secret, counter.to_bytes(8, "big"), digestmod).digest()
    offset = mac[-1] & 0x0F
    code = int.from_bytes(mac[offset:offset + 4], "big") & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp(secret: bytes, at: int, period: int = 30, t0: int = 0,
         digits: int = 6, algorithm: str = "SHA1") -> str:
    """Time-based one-time password: TOTP = HOTP(K, T), T = (at - T0) / period."""
    if at < t0:
        raise ValueError("timestamp precedes T0")
    return hotp(secret, (at - t0) // period, digits, algorithm)


def seconds_remaining(at: int, period: int = 30, t0: int = 0) -> int:
    """Seconds until the current time step rolls over."""
    return period - ((at - t0) % period)
