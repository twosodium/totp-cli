# totp-cli

Minimal local time-based one-time password (TOTP) tool for macOS.
Replaces phone/cloud authenticator apps for day-to-day use:

- `add` an account from a QR-code image or a pasted secret / `otpauth://` URI
- secrets live only in macOS Keychain; a local roster file keeps non-secret parameters
- `code` prints the current RFC 6238 code plus seconds until expiry

Design: [docs/DESIGN.md](docs/DESIGN.md). macOS only, offline, no sync.

## Setup

Prerequisites: Python 3.10+, [uv](https://docs.astral.sh/uv/), and the zbar
shared library for QR decoding:

```sh
brew install zbar
```

Install from a checkout (uses the committed `uv.lock` for pinned versions):

```sh
git clone <this-repo> && cd totp-cli
uv sync
uv run totp list
```

Or install the `totp` command straight onto your PATH with no checkout:

```sh
brew install zbar
uv tool install git+https://<this-repo-url>
totp list
```

(Without uv: `python3 -m venv .venv && source .venv/bin/activate && pip install .`)


## Usage

```sh
# add from a QR screenshot (delete the screenshot afterwards)
totp add --qr ~/Downloads/qr.png

# ...or scan one live with the camera (preview window; q cancels).
# macOS will ask for camera permission on first use.
totp add --camera

# add from a pasted secret (reads stdin, so it never lands in shell history;
# interactive use shows a hidden password-style prompt)
totp add --stdin --issuer Example --label alice@example.com < secret.txt

# add from a pasted otpauth:// URI
totp add --stdin < uri.txt

# import a Google Authenticator export (otpauth-migration:// QR or pasted URI);
# every TOTP account in the payload is added, HOTP entries are skipped
totp add --qr export-qr.png
totp add --stdin < migration-uri.txt

# list accounts (never prints secrets)
totp list

# show the code in a live inline display (full name or list number);
# press c to copy, q to quit. Rewrites only its own lines.
totp code Example:alice@example.com
totp code 1

# ...or print one line and exit (also automatic when piped)
totp code 1 --once

# delete an account from Keychain and the roster (full name or list number)
totp remove Example:alice@example.com
totp remove 1
```

The roster file defaults to `~/.config/totp-cli/accounts.json`;
override per-command with `totp --config <path> ...`.

## Tests

```sh
.venv/bin/python -m unittest discover tests
```

The suite covers RFC 6238 Appendix B vectors (SHA-1/256/512), RFC 4226 HOTP
vectors, URI parsing, QR ingest from a checked-in fixture, and roster storage
against a fake Keychain.
