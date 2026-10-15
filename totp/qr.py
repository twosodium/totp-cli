"""Decode otpauth URIs from QR-code images."""

from __future__ import annotations

from PIL import Image
from pyzbar.pyzbar import decode


class QRError(Exception):
    """QR image could not be read or contained no decodable payload."""


def decode_qr_image(path: str) -> str:
    """Return the UTF-8 payload of the first QR code in an image file."""
    try:
        with Image.open(path) as img:
            found = decode(img)
    except FileNotFoundError:
        raise QRError(f"no such image: {path}") from None
    except Exception as exc:
        raise QRError(f"cannot read image {path}: {exc}") from exc
    if not found:
        raise QRError(f"no QR code found in {path}")
    try:
        return found[0].data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise QRError(f"QR payload in {path} is not text: {exc}") from exc
