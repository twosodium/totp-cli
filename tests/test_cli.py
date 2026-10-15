"""End-to-end CLI runs with an isolated roster and fake Keychain."""

import io
import re
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tests.test_migration import SAMPLE_URI
from tests.test_store import FakeKeyring

from totp.cli import main

FIXTURE = Path(__file__).parent / "fixtures" / "otpauth_qr.png"
MIGRATION_FIXTURE = Path(__file__).parent / "fixtures" / "migration_qr.png"
SECRET = "JBSWY3DPEHPK3PXP"


class CliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = str(Path(self.tmp.name) / "accounts.json")
        patcher = patch("totp.store.keyring", FakeKeyring())
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_cli(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["--config", self.config, *argv])
        return code, out.getvalue()

    def test_add_list_code_remove_via_stdin(self):
        with patch("sys.stdin", io.StringIO(SECRET)):
            code, out = self.run_cli("add", "--stdin", "--issuer", "Example", "--label", "alice")
        self.assertEqual((code, out.strip()), (0, "added Example:alice"))

        code, out = self.run_cli("list")
        self.assertEqual(code, 0)
        self.assertIn("Example:alice", out)
        self.assertNotIn(SECRET, out)

        code, out = self.run_cli("code", "Example:alice")
        self.assertEqual(code, 0)
        self.assertRegex(out.strip(), r"^\d{6} expires in \d+s$")

        code, out = self.run_cli("remove", "Example:alice")
        self.assertEqual((code, out.strip()), (0, "removed Example:alice"))

    def test_add_from_qr_fixture(self):
        code, out = self.run_cli("add", "--qr", str(FIXTURE))
        self.assertEqual((code, out.strip()), (0, "added Example:alice@example.com"))
        code, out = self.run_cli("code", "Example:alice@example.com")
        self.assertEqual(code, 0)
        self.assertRegex(out.strip(), r"^\d{6} expires in \d+s$")

    def test_code_by_list_number(self):
        with patch("sys.stdin", io.StringIO(SECRET)):
            self.run_cli("add", "--stdin", "--issuer", "B", "--label", "second")
        with patch("sys.stdin", io.StringIO(SECRET)):
            self.run_cli("add", "--stdin", "--issuer", "A", "--label", "first")
        code, out = self.run_cli("list")
        self.assertEqual(code, 0)
        self.assertRegex(out, r"(?m)^1  A:first ")
        self.assertRegex(out, r"(?m)^2  B:second ")
        code, out = self.run_cli("code", "2")
        self.assertEqual(code, 0)
        self.assertRegex(out.strip(), r"^\d{6} expires in \d+s$")
        code, _ = self.run_cli("code", "3")
        self.assertEqual(code, 1)

    def test_add_migration_qr_fixture(self):
        code, out = self.run_cli("add", "--qr", str(MIGRATION_FIXTURE))
        self.assertEqual((code, out.strip()), (0, "added Example:alice@google.com"))
        code, out = self.run_cli("code", "Example:alice@google.com")
        self.assertEqual(code, 0)
        self.assertRegex(out.strip(), r"^\d{6} expires in \d+s$")

    def test_add_migration_skips_existing(self):
        with patch("sys.stdin", io.StringIO(SAMPLE_URI)):
            code, out = self.run_cli("add", "--stdin")
        self.assertEqual((code, out.strip()), (0, "added Example:alice@google.com"))
        with patch("sys.stdin", io.StringIO(SAMPLE_URI)):
            code, out = self.run_cli("add", "--stdin")
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "")

    def test_add_migration_rejects_overrides(self):
        with patch("sys.stdin", io.StringIO(SAMPLE_URI)):
            code, _ = self.run_cli("add", "--stdin", "--name", "x")
        self.assertEqual(code, 1)

    def test_add_camera(self):
        with patch("totp.scan.scan_camera", return_value=SAMPLE_URI):
            code, out = self.run_cli("add", "--camera")
        self.assertEqual((code, out.strip()), (0, "added Example:alice@google.com"))

    def test_remove_by_list_number(self):
        with patch("sys.stdin", io.StringIO(SECRET)):
            self.run_cli("add", "--stdin", "--issuer", "B", "--label", "second")
        with patch("sys.stdin", io.StringIO(SECRET)):
            self.run_cli("add", "--stdin", "--issuer", "A", "--label", "first")
        code, out = self.run_cli("remove", "1")
        self.assertEqual((code, out.strip()), (0, "removed A:first"))
        code, out = self.run_cli("list")
        self.assertNotIn("A:first", out)
        self.assertIn("B:second", out)
        code, _ = self.run_cli("remove", "5")
        self.assertEqual(code, 1)

    def test_code_once_prints_single_line(self):
        with patch("sys.stdin", io.StringIO(SECRET)):
            self.run_cli("add", "--stdin", "--issuer", "E", "--label", "a")
        code, out = self.run_cli("code", "1", "--once")
        self.assertEqual(code, 0)
        self.assertRegex(out.strip(), r"^\d{6} expires in \d+s$")

    def test_uri_flags_rejected(self):
        with patch("sys.stdin", io.StringIO(
                "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP")):
            code, _ = self.run_cli("add", "--stdin", "--label", "x")
        self.assertEqual(code, 1)

    def test_unknown_account_code_fails(self):
        code, _ = self.run_cli("code", "nope")
        self.assertEqual(code, 1)

    def test_interactive_stdin_uses_hidden_prompt(self):
        class TtyStdin(io.StringIO):
            def isatty(self):
                return True

        with patch("sys.stdin", TtyStdin("")):
            with patch("totp.cli.getpass.getpass", return_value=SECRET) as prompt:
                code, out = self.run_cli("add", "--stdin", "--issuer", "E", "--label", "a")
        self.assertEqual((code, out.strip()), (0, "added E:a"))
        prompt.assert_called_once()

    def test_interactive_eof_cancels_cleanly(self):
        class TtyStdin(io.StringIO):
            def isatty(self):
                return True

        with patch("sys.stdin", TtyStdin("")):
            with patch("totp.cli.getpass.getpass", side_effect=EOFError):
                code, _ = self.run_cli("add", "--stdin", "--issuer", "E", "--label", "a")
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
