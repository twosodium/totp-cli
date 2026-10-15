"""Live block-character display: big digits over an animated pattern field.

Renders inline under the invoked command: frames rewrite their own lines with
cursor-up movement, so shell history above is never cleared or disturbed.
"""

from __future__ import annotations

import select
import subprocess
import sys
import termios
import time
import tty

from . import crypto

FONT = {
    "0": [" ███ ", "█   █", "█   █", "█   █", " ███ "],
    "1": ["  █  ", " ██  ", "  █  ", "  █  ", " ███ "],
    "2": [" ███ ", "█   █", "  ██ ", " █   ", "█████"],
    "3": [" ███ ", "█   █", "  ██ ", "█   █", " ███ "],
    "4": ["█  █ ", "█  █ ", "█████", "   █ ", "   █ "],
    "5": ["█████", "█    ", "████ ", "    █", "████ "],
    "6": [" ███ ", "█    ", "████ ", "█   █", " ███ "],
    "7": ["█████", "   █ ", "  █  ", " █   ", " █   "],
    "8": [" ███ ", "█   █", " ███ ", "█   █", " ███ "],
    "9": [" ███ ", "█   █", "█████", "    █", " ███ "],
}

WAVES = [
    ("  ≈≈  ≈   ≈≈≈   ", 1, 2),   # pattern, speed, row
    (" ~   ~~  ~    ~~ ", 2, 10),
]
SQUARES = [
    ("▓", 17, 1, (1, 3)),   # char, spacing, speed, rows
    ("▒", 23, 2, (9, 11)),
]
HINT = "c copy · q quit"

WIDTH = 64
HEIGHT = 15
BAR_WIDTH = 20


def render_frame(code: str, remaining: int, period: int, name: str,
                 tick: int = 0, width: int = WIDTH, notice: str = "") -> str:
    """Draw one frame: bordered field, ripples, waves, drifting blocks, digits."""
    inner = width - 2
    lines = ["│" + " " * inner + "│" for _ in range(HEIGHT)]
    lines[0] = "┌" + "─" * inner + "┐"
    lines[HEIGHT - 1] = "└" + "─" * inner + "┘"
    lines[12] = "│" + HINT.center(inner) + "│"
    for row in (1, 2, 3, 9, 10, 11):
        for col in range(1, width - 1):
            if (col + row * 2 + tick) % 18 == 0:
                _put(lines, "·", col, row)
    for pattern, speed, row in WAVES:
        _blit(lines, [_scroll(pattern, inner, tick * speed)], 1, row)
    for char, spacing, speed, rows in SQUARES:
        for slot in range(8):
            col = (slot * spacing + 5 - tick * speed) % inner + 1
            _blit(lines, [char], col, rows[slot % len(rows)])
    for row in range(4, 9):
        lines[row] = "│" + " " * inner + "│"
    glyphs = [FONT[digit] for digit in code]
    digits = [" ".join(glyph[row] for glyph in glyphs) for row in range(5)]
    _blit(lines, digits, 1 + max(0, (inner - len(digits[0])) // 2), 4)
    if notice:
        status = f"{name}  {notice}"
    else:
        filled = remaining * BAR_WIDTH // period
        status = f"{name} [{'█' * filled}{'░' * (BAR_WIDTH - filled)}] {remaining}s"
    status = status[:inner] if len(status) > inner else status.center(inner)
    lines[13] = "│" + status + "│"
    return "\n".join(lines)


def interactive(secret: bytes, params: dict, name: str) -> None:
    """Animate inline until q/Esc/Ctrl-C; c copies the current code."""
    period = params["period"]
    use_keys = sys.stdin.isatty()
    fd = sys.stdin.fileno() if use_keys else None
    old = _enable_raw(fd) if use_keys else None
    sys.stdout.write("\033[?25l")
    sys.stdout.flush()
    try:
        tick = 0
        notice, notice_until = "", 0.0
        first = True
        while True:
            now = int(time.time())
            code = _code(secret, params, now)
            remaining = crypto.seconds_remaining(now, period)
            active = notice if time.time() < notice_until else ""
            frame = render_frame(code, remaining, period, name, tick, notice=active)
            if first:
                print(frame)
                first = False
            else:
                sys.stdout.write(f"\033[{HEIGHT}A{frame}\n")
            sys.stdout.flush()
            tick += 1
            if not use_keys:
                time.sleep(0.25)
                continue
            key = _poll_key(0.25)
            if key in ("c", "C"):
                if copy_to_clipboard(code):
                    notice, notice_until = "✓ copied to clipboard", time.time() + 2
                else:
                    notice, notice_until = "✗ copy failed", time.time() + 2
            elif key in ("q", "Q", "\x1b"):
                return
    finally:
        if use_keys:
            _restore(fd, old)
        sys.stdout.write("\033[?25h\n")
        sys.stdout.flush()


def copy_to_clipboard(code: str) -> bool:
    """Copy text via pbcopy; False when unavailable or failing."""
    try:
        subprocess.run(["pbcopy"], input=code.encode(), check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=5)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False
    return True


def _enable_raw(fd: int):
    old = termios.tcgetattr(fd)
    tty.setcbreak(fd)
    return old


def _restore(fd: int, old) -> None:
    termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _poll_key(timeout: float) -> str | None:
    """Wait for a keypress; escape sequences (arrows) come back as None."""
    ready, _, _ = select.select([sys.stdin], [], [], timeout)
    if not ready:
        return None
    key = sys.stdin.read(1)
    if key == "\x1b":
        pending = False
        while select.select([sys.stdin], [], [], 0)[0]:
            sys.stdin.read(1)
            pending = True
        return None if pending else key
    return key


def _code(secret: bytes, params: dict, now: int) -> str:
    return crypto.totp(secret, at=now, period=params["period"],
                       digits=params["digits"], algorithm=params["algorithm"])


def _scroll(pattern: str, width: int, offset: int) -> str:
    """Slice a width-wide window from an endlessly repeated tiling pattern."""
    start = offset % len(pattern)
    tiled = pattern * (width // len(pattern) + 2)
    return tiled[start:start + width]


def _put(lines: list[str], char: str, x: int, y: int) -> None:
    lines[y] = lines[y][:x] + char + lines[y][x + 1:]


def _blit(lines: list[str], sprite: list[str], x: int, y: int) -> None:
    for dy, row in enumerate(sprite):
        yy = y + dy
        if 0 <= yy < len(lines):
            chars = list(lines[yy])
            for dx, char in enumerate(row):
                xx = x + dx
                if char != " " and 0 <= xx < len(chars):
                    chars[xx] = char
            lines[yy] = "".join(chars)
