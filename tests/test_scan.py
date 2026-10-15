"""Camera scanning: still-image decode plus the capture loop with fakes."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cv2
import numpy

from tests.test_migration import SAMPLE_URI
from totp.scan import ScanError, decode_image, scan_camera

FIXTURES = Path(__file__).parent / "fixtures"
OTPAUTH_URI = ("otpauth://totp/Example:alice@example.com"
               "?secret=JBSWY3DPEHPK3PXP&issuer=Example")


class FakeCapture:
    def __init__(self, frames, opened=True):
        self.frames = list(frames)
        self.opened = opened
        self.released = False

    def isOpened(self):
        return self.opened

    def read(self):
        if self.frames:
            return True, self.frames.pop(0)
        return False, None

    def release(self):
        self.released = True


def _patched_window(cap, key):
    return (patch("totp.scan.cv2.VideoCapture", return_value=cap),
            patch("totp.scan.cv2.imshow"),
            patch("totp.scan.cv2.waitKey", return_value=key),
            patch("totp.scan.cv2.destroyAllWindows"))


class ScanTest(unittest.TestCase):
    def test_decode_image_both_payload_types(self):
        self.assertEqual(decode_image(str(FIXTURES / "otpauth_qr.png")), OTPAUTH_URI)
        self.assertEqual(decode_image(str(FIXTURES / "migration_qr.png")), SAMPLE_URI)

    def test_decode_image_failures(self):
        with self.assertRaises(ScanError):
            decode_image(str(FIXTURES / "does-not-exist.png"))
        blank = numpy.zeros((100, 100, 3), dtype=numpy.uint8)
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "blank.png")
            cv2.imwrite(path, blank)
            with self.assertRaisesRegex(ScanError, "no QR code"):
                decode_image(path)

    def test_scan_camera_finds_code(self):
        frame = cv2.imread(str(FIXTURES / "migration_qr.png"))
        cap = FakeCapture([frame])
        patches = _patched_window(cap, -1)
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.assertEqual(scan_camera(), SAMPLE_URI)
        self.assertTrue(cap.released)

    def test_scan_camera_unavailable(self):
        cap = FakeCapture([], opened=False)
        patches = _patched_window(cap, -1)
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        with self.assertRaisesRegex(ScanError, "could not open"):
            scan_camera()

    def test_scan_camera_cancel(self):
        blank = numpy.zeros((100, 100, 3), dtype=numpy.uint8)
        cap = FakeCapture([blank] * 3)
        patches = _patched_window(cap, ord("q"))
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        with self.assertRaisesRegex(ScanError, "cancelled"):
            scan_camera()
        self.assertTrue(cap.released)


if __name__ == "__main__":
    unittest.main()
