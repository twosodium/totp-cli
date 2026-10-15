"""Google Authenticator export (otpauth-migration://) imports."""

import base64
import unittest
from urllib.parse import quote

from totp import migration, uri

# Real-world export sample (dim13/otpauth example): one TOTP account,
# secret JBSWY3DPEHPK3PXP, name Example:alice@google.com, issuer Example.
SAMPLE_URI = ("otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8"
              "SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZTAC")

_MISSING = object()


def _varint(number):
    out = bytearray()
    while True:
        bits = number & 0x7F
        number >>= 7
        if number:
            out.append(bits | 0x80)
        else:
            out.append(bits)
            return bytes(out)


def _len_field(number, body):
    return _varint(number << 3 | 2) + _varint(len(body)) + body


def _int_field(number, value):
    return _varint(number << 3) + _varint(value)


def _entry(secret, name=_MISSING, issuer=_MISSING, algorithm=_MISSING,
           digits=_MISSING, otype=_MISSING):
    parts = [_len_field(1, secret)]
    if name is not _MISSING:
        parts.append(_len_field(2, name.encode()))
    if issuer is not _MISSING:
        parts.append(_len_field(3, issuer.encode()))
    if algorithm is not _MISSING:
        parts.append(_int_field(4, algorithm))
    if digits is not _MISSING:
        parts.append(_int_field(5, digits))
    if otype is not _MISSING:
        parts.append(_int_field(6, otype))
    return b"".join(parts)


def _migration_uri(*entries):
    payload = b"".join(_len_field(1, entry) for entry in entries)
    return "otpauth-migration://offline?data=" + base64.b64encode(payload).decode()


class MigrationTest(unittest.TestCase):
    def test_real_world_sample(self):
        accounts, skipped = migration.parse_migration_uri(SAMPLE_URI)
        self.assertEqual(skipped, [])
        (account,) = accounts
        self.assertEqual(account.name, "Example:alice@google.com")
        self.assertEqual(account.issuer, "Example")
        self.assertEqual(account.label, "alice@google.com")
        self.assertEqual(account.secret_b32, "JBSWY3DPEHPK3PXP")
        self.assertEqual((account.algorithm, account.digits, account.period),
                         ("SHA1", 6, 30))

    def test_enum_mapping(self):
        text = _migration_uri(_entry(b"12345678901234567890", name="bob",
                                     issuer="Acme", algorithm=2, digits=2, otype=2))
        (account,), skipped = migration.parse_migration_uri(text)
        self.assertEqual(skipped, [])
        self.assertEqual(account.name, "Acme:bob")
        self.assertEqual((account.algorithm, account.digits), ("SHA256", 8))
        self.assertEqual(uri.decode_secret(account.secret_b32), b"12345678901234567890")

    def test_missing_fields_get_totp_defaults(self):
        text = _migration_uri(_entry(b"secret-bytes", name="solo"))
        (account,), _ = migration.parse_migration_uri(text)
        self.assertEqual(account.name, "solo")
        self.assertEqual((account.algorithm, account.digits, account.period),
                         ("SHA1", 6, 30))

    def test_unsupported_entries_skipped(self):
        text = _migration_uri(
            _entry(b"a", name="hotp", otype=1),
            _entry(b"b", name="md5", algorithm=4, otype=2),
            _entry(b"c", name="digits", digits=9, otype=2),
            _entry(b"", name="empty", otype=2),
            _entry(b"e", name="weird", otype=7),
        )
        accounts, skipped = migration.parse_migration_uri(text)
        self.assertEqual(accounts, [])
        self.assertEqual(len(skipped), 5)
        blob = "\n".join(skipped)
        for needle in ("HOTP", "algorithm", "digit", "empty secret", "entry type"):
            self.assertIn(needle, blob)

    def test_base64_plus_survives_query_parsing(self):
        secret = None
        for byte in range(256):
            candidate = bytes([byte, byte ^ 0xFF, (byte * 7) & 0xFF]) * 4
            encoded = base64.b64encode(_len_field(1, _entry(candidate, name="p")))
            if b"+" in encoded:
                secret = candidate
                break
        self.assertIsNotNone(secret)
        accounts, _ = migration.parse_migration_uri(_migration_uri(
            _entry(secret, name="plus")))
        self.assertEqual(uri.decode_secret(accounts[0].secret_b32), secret)

    def test_percent_encoded_data_accepted(self):
        payload = SAMPLE_URI.split("data=", 1)[1]
        text = "otpauth-migration://offline?data=" + quote(payload, safe="")
        accounts, _ = migration.parse_migration_uri(text)
        self.assertEqual(accounts[0].name, "Example:alice@google.com")

    def test_malformed_uris_rejected(self):
        cases = [
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",  # not a migration URI
            "otpauth-migration://offline",               # missing data
            "otpauth-migration://offline?data=!!!",      # bad base64
            "otpauth-migration://offline?data=" + base64.b64encode(b"\x0a\xff").decode(),
            "otpauth-migration://offline?data=" + base64.b64encode(b"").decode(),
        ]
        for text in cases:
            with self.subTest(text=text[:50]):
                with self.assertRaises(ValueError):
                    migration.parse_migration_uri(text)


if __name__ == "__main__":
    unittest.main()
