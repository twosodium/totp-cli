"""QR ingest: checked-in fixture plus failure modes."""

import tempfile
import unittest
from pathlib import Path

from PIL import Image

from totp.qr import QRError, decode_qr_image

FIXTURE = Path(__file__).parent / "fixtures" / "otpauth_qr.png"
EXPECTED_URI = ("otpauth://totp/Example:alice@example.com"
                "?secret=JBSWY3DPEHPK3PXP&issuer=Example")


class QrTest(unittest.TestCase):
    def test_fixture_decodes_to_exact_uri(self):
        self.assertEqual(decode_qr_image(str(FIXTURE)), EXPECTED_URI)

    def test_missing_file_rejected(self):
        with self.assertRaises(QRError):
            decode_qr_image(str(FIXTURE.parent / "does-not-exist.png"))

    def test_image_without_qr_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            blank = Path(tmp) / "blank.png"
            Image.new("RGB", (100, 100), "white").save(blank)
            with self.assertRaisesRegex(QRError, "no QR code"):
                decode_qr_image(str(blank))


if __name__ == "__main__":
    unittest.main()
