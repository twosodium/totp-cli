"""Live camera QR scanning. Payload-agnostic: normal and migration QRs."""

from __future__ import annotations

try:
    import cv2
except ImportError:  # pragma: no cover
    cv2 = None

WINDOW = "totp scan (press q to cancel)"


class ScanError(Exception):
    """Camera unavailable, read failed, or scan cancelled."""


def decode_image(path: str) -> str:
    """Decode the first QR payload in a still image file."""
    _require_cv2()
    img = cv2.imread(path)
    if img is None:
        raise ScanError(f"cannot read image {path}")
    data, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
    if not data:
        raise ScanError(f"no QR code found in {path}")
    return data


def scan_camera() -> str:
    """Capture camera frames until a QR code decodes; q/Esc cancels."""
    _require_cv2()
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        raise ScanError("could not open the camera")
    try:
        detector = cv2.QRCodeDetector()
        while True:
            ok, frame = cap.read()
            if not ok:
                raise ScanError("camera read failed")
            data, _, _ = detector.detectAndDecode(frame)
            cv2.imshow(WINDOW, frame)
            if data:
                return data
            if cv2.waitKey(1) & 0xFF in (ord("q"), 27):
                raise ScanError("scan cancelled")
    finally:
        cap.release()
        cv2.destroyAllWindows()


def _require_cv2() -> None:
    if cv2 is None:
        raise ScanError("camera scanning needs the opencv-python package")
