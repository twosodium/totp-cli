"""RFC 6238 Appendix B vectors and edge cases for the TOTP core."""

import unittest

from totp import crypto

# Seeds from RFC 6238 Appendix B: the ASCII digits extended per digest size.
SEEDS = {
    "SHA1": b"12345678901234567890",
    "SHA256": b"12345678901234567890123456789012",
    "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234",
}

# (timestamp, SHA1, SHA256, SHA512) — 8-digit codes from RFC 6238 Appendix B.
RFC6238_VECTORS = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]

# (counter, code) — 6-digit HOTP values from RFC 4226 Appendix D.
RFC4226_VECTORS = [
    (0, "755224"), (1, "287082"), (2, "359152"), (3, "969429"), (4, "338314"),
    (5, "254676"), (6, "287922"), (7, "162583"), (8, "399871"), (9, "520489"),
]


class TotpTest(unittest.TestCase):
    def test_rfc6238_vectors(self):
        for at, sha1, sha256, sha512 in RFC6238_VECTORS:
            with self.subTest(at=at):
                self.assertEqual(crypto.totp(SEEDS["SHA1"], at, digits=8), sha1)
                self.assertEqual(
                    crypto.totp(SEEDS["SHA256"], at, digits=8, algorithm="SHA256"), sha256)
                self.assertEqual(
                    crypto.totp(SEEDS["SHA512"], at, digits=8, algorithm="SHA512"), sha512)

    def test_rfc4226_hotp_vectors(self):
        for counter, expected in RFC4226_VECTORS:
            with self.subTest(counter=counter):
                self.assertEqual(crypto.hotp(SEEDS["SHA1"], counter), expected)

    def test_six_digit_default_matches_vector(self):
        # 6-digit code is the same truncation mod 10^6.
        self.assertEqual(crypto.totp(SEEDS["SHA1"], 59), "287082")

    def test_rejects_timestamp_before_t0(self):
        with self.assertRaises(ValueError):
            crypto.totp(SEEDS["SHA1"], -1)

    def test_rejects_bad_algorithm(self):
        with self.assertRaises(ValueError):
            crypto.totp(SEEDS["SHA1"], 59, algorithm="MD5")
        with self.assertRaises(ValueError):
            crypto.hotp(SEEDS["SHA1"], 0, algorithm="SHA3")

    def test_rejects_negative_counter(self):
        with self.assertRaises(ValueError):
            crypto.hotp(SEEDS["SHA1"], -1)


class RemainingTest(unittest.TestCase):
    def test_counts_down_to_rollover(self):
        self.assertEqual(crypto.seconds_remaining(59, 30), 1)
        self.assertEqual(crypto.seconds_remaining(60, 30), 30)
        self.assertEqual(crypto.seconds_remaining(0, 30), 30)
        self.assertEqual(crypto.seconds_remaining(61, 30), 29)


if __name__ == "__main__":
    unittest.main()
