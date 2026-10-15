"""Block-character display frames and the interactive loop."""

import io
import re
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from totp import display

PARAMS = {"algorithm": "SHA1", "digits": 6, "period": 30}


class FrameTest(unittest.TestCase):
    def test_dimensions(self):
        rows = display.render_frame("123456", 17, 30, "n").split("\n")
        self.assertEqual(len(rows), 15)
        for row in rows:
            self.assertEqual(len(row), 64)

    def test_digits_use_block_characters(self):
        frame = display.render_frame("1", 30, 30, "n")
        for glyph_row in display.FONT["1"]:
            self.assertIn(glyph_row.rstrip(), frame)
        self.assertIn("█", frame)
        self.assertNotIn("#", frame)

    def test_frame_border(self):
        rows = display.render_frame("1", 1, 30, "n").split("\n")
        self.assertTrue(rows[0].startswith("┌"))
        self.assertTrue(rows[14].startswith("└"))
        self.assertEqual(rows[5][0], "│")
        self.assertIn("c copy", display.render_frame("1", 1, 30, "n"))

    def test_countdown_bar_scales(self):
        full = display.render_frame("1", 30, 30, "n")
        third = display.render_frame("1", 10, 30, "n")
        full_bar = re.search(r"\[(█*)(░*)\]", full)
        third_bar = re.search(r"\[(█*)(░*)\]", third)
        self.assertEqual((len(full_bar.group(1)), len(third_bar.group(1))), (20, 6))
        self.assertEqual(len(third_bar.group(1)) + len(third_bar.group(2)), 20)
        self.assertIn("10s", third)

    def test_background_animates(self):
        first = display.render_frame("1", 1, 30, "n", tick=20)
        self.assertNotEqual(first, display.render_frame("1", 1, 30, "n", tick=21))
        self.assertEqual(first, display.render_frame("1", 1, 30, "n", tick=20))
        for char in ("▓", "▒", "≈", "~", "·"):
            self.assertIn(char, first)

    def test_notice_replaces_countdown(self):
        frame = display.render_frame("1", 17, 30, "n", notice="✓ copied to clipboard")
        self.assertIn("✓ copied to clipboard", frame)
        self.assertNotIn("[", frame)


class CopyTest(unittest.TestCase):
    def test_copies_via_pbcopy(self):
        with patch("totp.display.subprocess.run") as run:
            self.assertTrue(display.copy_to_clipboard("123456"))
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["pbcopy"])
        self.assertEqual(kwargs["input"], b"123456")

    def test_copy_failure(self):
        with patch("totp.display.subprocess.run", side_effect=OSError("nope")):
            self.assertFalse(display.copy_to_clipboard("123456"))


class FakeStdin(io.StringIO):
    def isatty(self):
        return True

    def fileno(self):
        return 0


class LoopTest(unittest.TestCase):
    def test_copy_then_quit(self):
        keys = ["c", "q"]
        out = io.StringIO()
        with (patch("sys.stdin", FakeStdin()),
              patch("totp.display._enable_raw", return_value="old") as enable,
              patch("totp.display._restore") as restore,
              patch("totp.display._poll_key", side_effect=lambda timeout: keys.pop(0)),
              patch("totp.display.copy_to_clipboard", return_value=True) as copy,
              patch("totp.display.time.time", return_value=59.0),
              redirect_stdout(out)):
            display.interactive(b"12345678901234567890", PARAMS, "n")
        text = out.getvalue()
        self.assertIn("█", text)
        self.assertIn("\x1b[15A", text)
        self.assertNotIn("\x1b[2J", text)
        self.assertIn("✓ copied to clipboard", text)
        copy.assert_called_once_with("287082")
        enable.assert_called_once_with(0)
        restore.assert_called_once_with(0, "old")

    def test_terminal_restored_on_interrupt(self):
        out = io.StringIO()
        with (patch("sys.stdin", FakeStdin()),
              patch("totp.display._enable_raw", return_value="old"),
              patch("totp.display._restore") as restore,
              patch("totp.display._poll_key", side_effect=KeyboardInterrupt),
              redirect_stdout(out)):
            with self.assertRaises(KeyboardInterrupt):
                display.interactive(b"secret", PARAMS, "n")
        restore.assert_called_once()
        self.assertIn("\x1b[?25h", out.getvalue())


if __name__ == "__main__":
    unittest.main()
