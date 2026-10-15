"""Command-line interface: add / list / code / remove."""

from __future__ import annotations

import argparse
import getpass
import sys
import time
from pathlib import Path

from . import crypto, store, uri
from .migration import parse_migration_uri
from .qr import QRError, decode_qr_image


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="totp", description="Minimal local TOTP tool backed by macOS Keychain.")
    parser.add_argument("--config", default=None,
                        help="roster file path (default: ~/.config/totp-cli/accounts.json)")
    sub = parser.add_subparsers(dest="command", required=True)

    add = sub.add_parser("add", help="add an account from a QR image, the camera, or pasted input")
    source = add.add_mutually_exclusive_group(required=True)
    source.add_argument("--qr", metavar="IMAGE", help="QR-code image file to decode")
    source.add_argument("--camera", action="store_true",
                        help="scan a QR code with the camera")
    source.add_argument("--stdin", action="store_true",
                        help="read a pasted secret or otpauth URI from stdin")
    add.add_argument("--issuer", default="", help="issuer (raw-secret input only)")
    add.add_argument("--label", default="", help="account label (raw-secret input only)")
    add.add_argument("--name", default=None, help="override the roster key")
    add.add_argument("--force", action="store_true", help="replace an existing account")

    sub.add_parser("list", help="list accounts (never prints secrets)")

    code = sub.add_parser("code", help="show the current code for an account")
    code.add_argument("name", help="account roster key or list number")
    code.add_argument("--once", action="store_true",
                      help="print one line and exit instead of the live display")

    remove = sub.add_parser("remove", help="delete an account from Keychain and roster")
    remove.add_argument("name", help="account roster key or list number")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = Path(args.config) if args.config else store.default_metadata_path()
    try:
        if args.command == "add":
            return _add(args, config)
        if args.command == "list":
            return _list(config)
        if args.command == "code":
            return _code(args, config)
        if args.command == "remove":
            return _remove(args, config)
    except (ValueError, store.StoreError, QRError) as exc:
        print(f"totp: error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130
    raise AssertionError(f"unreachable command: {args.command}")


def _add(args: argparse.Namespace, config: Path) -> int:
    if args.qr:
        text = decode_qr_image(args.qr)
    elif args.camera:
        from . import scan  # lazy: avoids the cv2 import cost on other commands
        try:
            text = scan.scan_camera()
        except scan.ScanError as exc:
            print(f"totp: error: {exc}", file=sys.stderr)
            return 1
    else:
        text = _read_text_input()
        if text is None:
            return 1
    lowered = text.strip().lower()
    if lowered.startswith("otpauth-migration://"):
        return _add_migration(args, config, text)
    if lowered.startswith("otpauth://"):
        if args.issuer or args.label:
            print("totp: error: --issuer/--label come from the URI; drop them "
                  "or use --name to override the roster key", file=sys.stderr)
            return 1
        account = uri.parse_otpauth_uri(text, name_override=args.name)
    else:
        account = uri.parse_raw_secret(text, issuer=args.issuer, label=args.label,
                                       name_override=args.name)
    store.add_account(config, account, overwrite=args.force)
    print(f"added {account.name}")
    return 0


def _read_text_input() -> str | None:
    if sys.stdin.isatty():
        try:
            return getpass.getpass("Secret, otpauth:// or migration URI: ")
        except EOFError:
            print("totp: error: no input received", file=sys.stderr)
            return None
    return sys.stdin.read()


def _add_migration(args: argparse.Namespace, config: Path, text: str) -> int:
    if args.issuer or args.label or args.name:
        print("totp: error: migration import names every account itself; "
              "drop --issuer/--label/--name", file=sys.stderr)
        return 1
    accounts, skipped = parse_migration_uri(text)
    known = {name for name, _ in store.list_accounts(config)}
    for account in accounts:
        if account.name in known and not args.force:
            print(f"skipped {account.name}: already exists", file=sys.stderr)
            continue
        store.add_account(config, account, overwrite=args.force)
        known.add(account.name)
        print(f"added {account.name}")
    for reason in skipped:
        print(f"skipped {reason}", file=sys.stderr)
    return 0


def _list(config: Path) -> int:
    entries = store.list_accounts(config)
    if not entries:
        print("no accounts configured")
        return 0
    for position, (name, params) in enumerate(entries, 1):
        print(f"{position}  {name} algo={params['algorithm']} "
              f"digits={params['digits']} period={params['period']}")
    return 0


def _code(args: argparse.Namespace, config: Path) -> int:
    name = store.resolve_name(config, args.name)
    params, secret_b32 = store.get_account(config, name)
    secret = uri.decode_secret(secret_b32)
    if not args.once and sys.stdout.isatty():
        from . import display  # lazy: keeps one-shot output fast
        display.interactive(secret, params, name)
        return 0
    now = int(time.time())
    code = crypto.totp(secret, at=now, period=params["period"],
                       digits=params["digits"], algorithm=params["algorithm"])
    print(f"{code} expires in {crypto.seconds_remaining(now, params['period'])}s")
    return 0


def _remove(args: argparse.Namespace, config: Path) -> int:
    name = store.resolve_name(config, args.name)
    store.remove_account(config, name)
    print(f"removed {name}")
    return 0
