"""Roster storage with a fake Keychain: no real secrets leave the test."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from keyring.errors import KeyringError, PasswordDeleteError

from totp import store, uri

ACCOUNT = uri.Account(name="Example:alice", issuer="Example", label="alice",
                      secret_b32="JBSWY3DPEHPK3PXP")


class FakeKeyring:
    def __init__(self):
        self.data = {}

    def set_password(self, service, username, password):
        self.data[(service, username)] = password

    def get_password(self, service, username):
        return self.data.get((service, username))

    def delete_password(self, service, username):
        try:
            del self.data[(service, username)]
        except KeyError:
            raise PasswordDeleteError("not found") from None


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = Path(self.tmp.name) / "accounts.json"
        self.fake = FakeKeyring()
        patcher = patch("totp.store.keyring", self.fake)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_add_list_get_round_trip(self):
        store.add_account(self.config, ACCOUNT)
        self.assertEqual([name for name, _ in store.list_accounts(self.config)],
                         ["Example:alice"])
        params, secret = store.get_account(self.config, "Example:alice")
        self.assertEqual(secret, "JBSWY3DPEHPK3PXP")
        self.assertEqual(params["issuer"], "Example")

    def test_metadata_file_never_contains_secret(self):
        store.add_account(self.config, ACCOUNT)
        body = self.config.read_text(encoding="utf-8")
        self.assertNotIn("JBSWY3DPEHPK3PXP", body)

    def test_duplicate_add_rejected_then_forced(self):
        store.add_account(self.config, ACCOUNT)
        with self.assertRaises(store.StoreError):
            store.add_account(self.config, ACCOUNT)
        changed = uri.Account(name="Example:alice", issuer="Example", label="alice",
                              secret_b32="HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")
        store.add_account(self.config, changed, overwrite=True)
        _, secret = store.get_account(self.config, "Example:alice")
        self.assertEqual(secret, "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")

    def test_remove_deletes_both_stores(self):
        store.add_account(self.config, ACCOUNT)
        store.remove_account(self.config, "Example:alice")
        self.assertEqual(store.list_accounts(self.config), [])
        self.assertEqual(self.fake.data, {})
        with self.assertRaises(store.StoreError):
            store.remove_account(self.config, "Example:alice")

    def test_missing_keychain_secret_fails_closed(self):
        store.add_account(self.config, ACCOUNT)
        self.fake.data.clear()  # roster entry survives, secret gone
        with self.assertRaisesRegex(store.StoreError, "missing from Keychain"):
            store.get_account(self.config, "Example:alice")

    def test_missing_file_is_empty_roster(self):
        self.assertEqual(store.list_accounts(self.config), [])

    def test_corrupt_file_rejected(self):
        self.config.write_text("{nope", encoding="utf-8")
        with self.assertRaises(store.StoreError):
            store.list_accounts(self.config)

    def test_roster_file_is_owner_only(self):
        store.add_account(self.config, ACCOUNT)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)

    def test_resolve_name_exact_and_index(self):
        store.add_account(self.config, ACCOUNT)
        self.assertEqual(store.resolve_name(self.config, "Example:alice"), "Example:alice")
        self.assertEqual(store.resolve_name(self.config, "1"), "Example:alice")
        with self.assertRaises(store.StoreError):
            store.resolve_name(self.config, "2")
        with self.assertRaises(store.StoreError):
            store.resolve_name(self.config, "nope")

    def test_resolve_exact_name_beats_index(self):
        numeric = uri.Account(name="2", issuer="", label="2",
                              secret_b32="HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")
        store.add_account(self.config, ACCOUNT)
        store.add_account(self.config, numeric)
        # Index 2 is Example:alice, but the exact name "2" wins.
        self.assertEqual(store.resolve_name(self.config, "2"), "2")


class FailingKeyring:
    def set_password(self, *args):
        raise KeyringError("denied")

    def get_password(self, *args):
        raise KeyringError("denied")

    def delete_password(self, *args):
        raise KeyringError("denied")


class KeychainFailureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = Path(self.tmp.name) / "accounts.json"
        patcher = patch("totp.store.keyring", FailingKeyring())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_keychain_errors_surface_as_store_errors(self):
        with self.assertRaisesRegex(store.StoreError, "Keychain store failed"):
            store.add_account(self.config, ACCOUNT)
        self.assertFalse(self.config.exists())  # no orphan roster entry
        with self.assertRaises(store.StoreError):
            store.get_account(self.config, "Example:alice")
        with self.assertRaises(store.StoreError):
            store.remove_account(self.config, "Example:alice")


if __name__ == "__main__":
    unittest.main()
