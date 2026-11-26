"""The test-device code (hard rule 14.8): how a device with no vendor evidence - an emulator, or a phone a vendor will
not vouch for - enters the registry, on the host's say-so.

The host writes a code into the state dir (`recto bootloader test-device`); no network route issues one. A code is for
one plane and one registration, lives an hour at most, and is kept only as a MAC. Redeeming it is a file removal, so a
code opens once however many requests race for it.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

PLANES = ("member", "owner")
TEST_CODE_MAX_TTL_SECONDS = 3600
MAX_LIVE_CODES = 8
MAX_LABEL_CHARS = 40
KEY_NAME = "test_device.key"
CODES_DIR = "test_device_codes"
_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"   # Crockford base32: no I, L, O, U
_LENGTH = 10
ALPHABET = _ALPHABET


class TestCodeRefused(ValueError):
    __test__ = False    # not a pytest class


@dataclass(frozen=True)
class TestCode:
    __test__ = False
    plane: str
    label: str


def normalize(code: object, length: int = _LENGTH) -> str | None:
    if not isinstance(code, str):
        return None
    text = code.upper().replace("-", "").replace(" ", "").translate(str.maketrans("ILO", "110"))
    return text if len(text) == length and set(text) <= set(_ALPHABET) else None


def ensure_key(state_dir: Path) -> None:
    """The serving bootloader makes the MAC key, once. The host verb refuses a dir without one, so a mistyped dir never
    looks like an issued code."""
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(FileExistsError):
        fd = os.open(state_dir / KEY_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(secrets.token_bytes(32))


def _path(state_dir: Path, code: str) -> Path | None:
    try:
        key = (Path(state_dir) / KEY_NAME).read_bytes()
    except OSError:
        return None
    if len(key) != 32:
        return None
    mac = hmac.new(key, f"recto-test-device-code-v1|{code}".encode("ascii"), hashlib.sha256).hexdigest()
    return Path(state_dir) / CODES_DIR / f"{mac}.json"


def _read(path: Path) -> TestCode | None:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        plane, label, expires = doc["plane"], doc["label"], int(doc["expires_at_unix"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if plane not in PLANES or not isinstance(label, str) or expires <= time.time():
        return None
    return TestCode(plane, label)


def issue(state_dir: Path, *, plane: str, label: str, ttl_seconds: int = 900) -> tuple[str, int]:
    """(the code, its expiry). The code is returned here and stored nowhere."""
    state_dir = Path(state_dir)
    label = label.strip()
    if plane not in PLANES:
        raise TestCodeRefused(f"plane must be one of {PLANES}")
    if not label or len(label) > MAX_LABEL_CHARS or not label.isprintable():
        raise TestCodeRefused(f"a test device is named: a label of 1 to {MAX_LABEL_CHARS} printable characters")
    if not 60 <= ttl_seconds <= TEST_CODE_MAX_TTL_SECONDS:
        raise TestCodeRefused(f"a test-device code lives 60 to {TEST_CODE_MAX_TTL_SECONDS} seconds")
    code = "".join(secrets.choice(_ALPHABET) for _ in range(_LENGTH))
    path = _path(state_dir, code)
    if path is None:
        raise TestCodeRefused(f"no bootloader has served {state_dir} (no {KEY_NAME}); name its live state dir")
    path.parent.mkdir(mode=0o700, exist_ok=True)
    live = 0
    for old in path.parent.glob("*.json"):
        if _read(old) is None:
            old.unlink(missing_ok=True)
        else:
            live += 1
    if live >= MAX_LIVE_CODES:
        raise TestCodeRefused(f"{live} test-device codes are live; wait for one to be used or to expire")
    expires = int(time.time()) + ttl_seconds
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"plane": plane, "label": label, "expires_at_unix": expires}, fh)
    os.replace(tmp, path)
    return f"{code[:5]}-{code[5:]}", expires


def find(state_dir: Path, code: object, plane: str) -> TestCode | None:
    """The live code for this plane, unspent, or None."""
    text = normalize(code)
    path = _path(state_dir, text) if text else None
    found = _read(path) if path is not None else None
    return found if found is not None and found.plane == plane else None


def spend(state_dir: Path, code: object, plane: str) -> bool:
    """True for exactly one caller per code."""
    if find(state_dir, code, plane) is None:
        return False
    path = _path(state_dir, normalize(code) or "")
    try:
        path.unlink()       # type: ignore[union-attr]
        return True
    except OSError:
        return False
