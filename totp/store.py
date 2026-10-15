"""Account roster: secrets in macOS Keychain, non-secret params in a local file."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import keyring
from keyring.errors import KeyringError, PasswordDeleteError

from .uri import Account

SERVICE = "totp-cli"
METADATA_VERSION = 1


class StoreError(Exception):
    """Roster or Keychain failure. Missing secrets always fail closed."""


def default_metadata_path() -> Path:
    return Path.home() / ".config" / "totp-cli" / "accounts.json"


def load_metadata(path: str | Path) -> dict[str, Any]:
    """Read the roster file; a missing file means zero accounts."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"version": METADATA_VERSION, "accounts": {}}
    except json.JSONDecodeError as exc:
        raise StoreError(f"corrupt metadata file {path}: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("accounts"), dict):
        raise StoreError(f"corrupt metadata file {path}: bad shape")
    return raw


def add_account(path: str | Path, account: Account, overwrite: bool = False) -> None:
    """Store the secret in Keychain and the parameters in the roster file."""
    data = load_metadata(path)
    if account.name in data["accounts"] and not overwrite:
        raise StoreError(f"account {account.name!r} already exists (use --force to replace)")
    try:
        keyring.set_password(SERVICE, account.name, account.secret_b32)
    except KeyringError as exc:
        raise StoreError(f"Keychain store failed: {exc}") from exc
    data["accounts"][account.name] = {
        "issuer": account.issuer,
        "label": account.label,
        "algorithm": account.algorithm,
        "digits": account.digits,
        "period": account.period,
    }
    _save(path, data)


def remove_account(path: str | Path, name: str) -> None:
    """Delete an account from Keychain and the roster file."""
    data = load_metadata(path)
    if name not in data["accounts"]:
        raise StoreError(f"unknown account: {name!r}")
    try:
        keyring.delete_password(SERVICE, name)
    except PasswordDeleteError:
        pass  # Keychain entry already gone; converge on removed.
    except KeyringError as exc:
        raise StoreError(f"Keychain delete failed: {exc}") from exc
    del data["accounts"][name]
    _save(path, data)


def get_account(path: str | Path, name: str) -> tuple[dict[str, Any], str]:
    """Return (params, secret_b32). A missing Keychain secret is a hard error."""
    params = load_metadata(path)["accounts"].get(name)
    if params is None:
        raise StoreError(f"unknown account: {name!r}")
    try:
        secret = keyring.get_password(SERVICE, name)
    except KeyringError as exc:
        raise StoreError(f"Keychain read failed: {exc}") from exc
    if secret is None:
        raise StoreError(f"secret for {name!r} is missing from Keychain")
    return params, secret


def list_accounts(path: str | Path) -> list[tuple[str, dict[str, Any]]]:
    """Roster entries sorted by name. Never touches secrets."""
    return sorted(load_metadata(path)["accounts"].items())


def resolve_name(path: str | Path, ref: str) -> str:
    """Resolve a roster key: exact name first, else 1-based list position."""
    names = [name for name, _ in list_accounts(path)]
    if ref in names:
        return ref
    if ref.isdigit():
        index = int(ref)
        if 1 <= index <= len(names):
            return names[index - 1]
    raise StoreError(f"unknown account: {ref!r}")


def _save(path: str | Path, data: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    target.chmod(0o600)
