"""otpauth URI and raw-secret parsing."""

import unittest

from totp import uri

FULL_URI = ("otpauth://totp/ACME%20Co:john.doe@email.com"
            "?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co"
            "&algorithm=SHA1&digits=6&period=30")
WIKI_URI = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"


class UriTest(unittest.TestCase):
    def test_full_uri(self):
        account = uri.parse_otpauth_uri(FULL_URI)
        self.assertEqual(account.issuer, "ACME Co")
        self.assertEqual(account.label, "john.doe@email.com")
        self.assertEqual(account.name, "ACME Co:john.doe@email.com")
        self.assertEqual(account.algorithm, "SHA1")
        self.assertEqual(account.digits, 6)
        self.assertEqual(account.period, 30)
        self.assertEqual(account.secret_b32, "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")

    def test_minimal_uri_gets_defaults(self):
        account = uri.parse_otpauth_uri("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP")
        self.assertEqual(account.name, "alice")
        self.assertEqual(account.issuer, "")
        self.assertEqual(account.label, "alice")
        self.assertEqual((account.algorithm, account.digits, account.period), ("SHA1", 6, 30))

    def test_issuer_from_label_prefix(self):
        account = uri.parse_otpauth_uri("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP")
        self.assertEqual(account.issuer, "Example")
        self.assertEqual(account.label, "alice")
        self.assertEqual(account.name, "Example:alice")

    def test_name_override(self):
        account = uri.parse_otpauth_uri(WIKI_URI, name_override="work")
        self.assertEqual(account.name, "work")
        self.assertEqual(account.issuer, "Example")

    def test_non_default_params(self):
        account = uri.parse_otpauth_uri(
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=sha256&digits=8&period=60")
        self.assertEqual((account.algorithm, account.digits, account.period), ("SHA256", 8, 60))

    def test_hotp_rejected(self):
        with self.assertRaisesRegex(ValueError, "TOTP only"):
            uri.parse_otpauth_uri("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP")

    def test_bad_inputs_rejected(self):
        cases = [
            "https://totp/x?secret=JBSWY3DPEHPK3PXP",   # wrong scheme
            "otpauth://steam/x?secret=JBSWY3DPEHPK3PXP",  # wrong type
            "otpauth://totp/?secret=JBSWY3DPEHPK3PXP",    # empty label
            "otpauth://totp/x",                            # missing secret
            "otpauth://totp/x?secret=not-valid!!!",        # bad base32
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=5",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0",
        ]
        for text in cases:
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    uri.parse_otpauth_uri(text)


class RawSecretTest(unittest.TestCase):
    def test_defaults_and_normalization(self):
        account = uri.parse_raw_secret("jbswy3dp ehpk3pxp", issuer="Ex", label="alice")
        self.assertEqual(account.secret_b32, "JBSWY3DPEHPK3PXP")
        self.assertEqual(account.name, "Ex:alice")
        self.assertEqual((account.algorithm, account.digits, account.period), ("SHA1", 6, 30))

    def test_label_required(self):
        with self.assertRaisesRegex(ValueError, "--label"):
            uri.parse_raw_secret("JBSWY3DPEHPK3PXP", label="  ")

    def test_bad_secret_rejected(self):
        with self.assertRaises(ValueError):
            uri.parse_raw_secret("!!!", label="x")


class SecretCodecTest(unittest.TestCase):
    def test_round_trip_without_padding(self):
        self.assertEqual(uri.decode_secret("JBSWY3DPEHPK3PXP"), b"Hello!\xde\xad\xbe\xef")


if __name__ == "__main__":
    unittest.main()
