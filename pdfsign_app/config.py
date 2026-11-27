"""Loading of config.ini / credentials.ini and the failure lock marker.

The token secret can be a numeric PIN or an alphanumeric password. For the card they are the
same thing: OpenSC sends the ASCII bytes verbatim (padded to 16 bytes with 0x00) in an ISO 7816
VERIFY, exactly as SafeNet's "Token Password" is sent.
"""

from __future__ import annotations

import configparser
import datetime as _dt
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from . import APP_DIR

CONFIG_FILE = APP_DIR / "config.ini"
# Secret file next to the program (git-ignored). Override with $PDFSIGN_CREDENTIALS.
CREDENTIALS_FILE = Path(os.environ.get("PDFSIGN_CREDENTIALS", APP_DIR / "credentials.ini"))
STATE_DIR = CREDENTIALS_FILE.parent
# Written after a rejected secret. While it exists the stored secret is never used again,
# so a wrong value in credentials.ini can cost at most ONE try, not three.
FAILURE_MARKER = STATE_DIR / ".pin_failure.lock"
CERT_CACHE = APP_DIR / "certs"

SECRET_TYPES = ("password", "pin")

# Searched when pkcs11_module / font is "auto" (Debian/Ubuntu, Fedora/RHEL, Arch, openSUSE).
PKCS11_CANDIDATES = (
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib64/opensc-pkcs11.so",
    "/usr/lib64/pkcs11/opensc-pkcs11.so",
    "/usr/lib/opensc-pkcs11.so",
    "/usr/lib/pkcs11/opensc-pkcs11.so",
)
FONT_CANDIDATES = (
    "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",         # Debian/Ubuntu fonts-noto-core
    "/usr/share/fonts/google-noto/NotoSans-Regular.ttf",           # Fedora
    "/usr/share/fonts/google-noto-vf/NotoSans[wght].ttf",
    "/usr/share/fonts/noto/NotoSans-Regular.ttf",                  # Arch noto-fonts
    "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
    "/usr/share/fonts/gnu-free/FreeSans.ttf",
)


def _first_existing(paths, default=""):
    return next((p for p in paths if os.path.exists(p)), default)


class ConfigError(Exception):
    pass


@dataclass
class Settings:
    pkcs11_module: str
    slot: str
    secret_type: str          # "password" or "pin"
    full_tries: int
    tsa_url: str
    level: str
    reason: str
    location: str
    contact: str
    stamp_text: str
    timestamp_format: str
    font: str
    font_size: int
    stamp_border: str = "auto"    # auto | yes | no
    output_suffix: str = "auto"   # auto = _<initials from certificate>, or literal text
    stamp_padding: int = 5        # pt between the stamp frame and its text
    field_radius: float = 120.0
    box_width: float = 160.0
    merge_gap: float = 200.0
    box_height: float = 50.0

    @property
    def secret_word(self) -> str:
        return "password" if self.secret_type == "password" else "PIN"


def load_settings(path: Path = CONFIG_FILE) -> Settings:
    cp = configparser.ConfigParser(interpolation=None)
    if path.exists():
        cp.read(path, encoding="utf-8")
    g = lambda s, k, d="": cp.get(s, k, fallback=d).strip()  # noqa: E731
    level = g("signature", "level", "B-LT").upper()
    if level not in ("B-T", "B-LT", "B-LTA"):
        raise ConfigError(f"config.ini: unknown signature level {level!r}")
    secret_type = g("token", "secret_type", "password").lower()
    module = g("token", "pkcs11_module", "auto")
    if module.lower() == "auto":
        module = _first_existing(PKCS11_CANDIDATES, PKCS11_CANDIDATES[0])
    font = g("signature", "font", "auto")
    if font.lower() == "auto":
        font = _first_existing(FONT_CANDIDATES)
    if secret_type not in SECRET_TYPES:
        raise ConfigError(f"config.ini: secret_type must be 'password' or 'pin', not {secret_type!r}")
    return Settings(
        pkcs11_module=module,
        slot=g("token", "slot", "auto"),
        secret_type=secret_type,
        full_tries=int(g("token", "full_tries", "3") or 3),
        tsa_url=g("tsa", "url", "https://timestamp.aped.gov.gr/qtss"),
        level=level,
        reason=g("signature", "reason"),
        location=g("signature", "location"),
        contact=g("signature", "contact"),
        stamp_text=g("signature", "stamp_text",
                     "Digitally signed by\n%(signer)s\nDate: %(ts)s"),
        timestamp_format=g("signature", "timestamp_format", "%Y-%m-%d %H:%M:%S %Z"),
        font=font,
        font_size=int(g("signature", "font_size", "9") or 9),
        stamp_border=(g("signature", "stamp_border", "auto") or "auto").lower(),
        output_suffix=g("signature", "output_suffix", "auto"),
        stamp_padding=int(float(g("signature", "stamp_padding", "5") or 5)),
        field_radius=float(g("autolocate", "field_radius", "120") or 120),
        box_width=float(g("autolocate", "box_width", "160") or 160),
        merge_gap=float(g("autolocate", "merge_gap", "200") or 0),
        box_height=float(g("autolocate", "box_height", "50") or 50),
    )


@dataclass
class Identities:
    """Text that marks where the user signs. names are primary, roles are the fallback."""
    names: list
    roles: list

    @property
    def empty(self) -> bool:
        return not (self.names or self.roles)


def _check_private(path: Path) -> None:
    st = path.stat()
    if st.st_uid != os.getuid():
        raise ConfigError(f"{path} is not owned by you - refusing to use it.")
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigError(f"{path} is accessible by group/others. Run:  chmod 600 {path}")


def read_identities(path: Path = CREDENTIALS_FILE) -> Identities:
    """[identities] section: 'names' (primary) and 'roles' or any other key (fallback).
    One entry per line (indent continuation lines)."""
    if not path.exists():
        return Identities([], [])
    _check_private(path)
    cp = configparser.ConfigParser(interpolation=None)
    cp.read(path, encoding="utf-8")
    if not cp.has_section("identities"):
        return Identities([], [])
    lines = lambda v: [x.strip() for x in v.splitlines() if x.strip() and not x.strip().startswith("#")]  # noqa: E731
    names, roles = [], []
    for key, value in cp.items("identities"):
        (names if key == "names" else roles).extend(lines(value))
    return Identities(names, roles)


def validate_secret(secret: str, secret_type: str = "password",
                    min_len: int = 4, max_len: int = 16) -> str:
    """Local sanity check so an obviously malformed secret never reaches the card."""
    word = "password" if secret_type == "password" else "PIN"
    if secret is None or secret == "":
        raise ConfigError(f"Empty {word} refused (an empty secret must never be sent to the token).")
    if secret != secret.strip():
        raise ConfigError(f"{word} has leading/trailing whitespace - refusing to send it.")
    if secret_type == "pin":
        if not (secret.isascii() and secret.isdigit()):
            raise ConfigError("PIN must consist of digits only "
                              "(set secret_type = password if it contains letters/symbols).")
    else:
        bad = [c for c in secret if not (0x20 <= ord(c) <= 0x7E)]
        if bad:
            raise ConfigError(
                "Password contains non-ASCII or control characters (e.g. Greek letters). "
                "Their byte encoding on the card is ambiguous, so it is refused to avoid "
                "wasting a try.")
    if not min_len <= len(secret) <= max_len:
        raise ConfigError(f"{word} length must be {min_len}..{max_len} characters "
                          f"(token limit; got {len(secret)}).")
    return secret


def read_stored_secret(secret_type: str, path: Path = CREDENTIALS_FILE) -> str | None:
    """Return the secret from credentials.ini, or None if none is stored.

    Raises ConfigError if the file is insecure, malformed, or locked by a previous failure.
    Format validation against the token limits happens at login time.
    """
    if not path.exists():
        return None
    if FAILURE_MARKER.exists():
        raise ConfigError(
            f"A previous signing attempt was rejected with a WRONG PIN/password "
            f"({FAILURE_MARKER.read_text().strip()}).\n"
            f"The stored secret is disabled to protect the token from locking.\n"
            f"Fix {path}, then delete {FAILURE_MARKER} to re-enable it.")
    _check_private(path)
    cp = configparser.ConfigParser(interpolation=None)
    cp.read(path, encoding="utf-8")
    keys = (["signature_password", "signature_pin"] if secret_type == "password"
            else ["signature_pin", "signature_password"])
    values = {k: cp.get("token", k, fallback="").strip() for k in keys}
    if values["signature_password"] and values["signature_pin"]:
        raise ConfigError(f"{path.name}: set either signature_password or signature_pin, not both.")
    if secret_type == "pin" and values["signature_password"]:
        raise ConfigError(f"{path.name} has signature_password but config.ini says secret_type = pin.")
    return values[keys[0]] or values[keys[1]] or None


def record_pin_failure(reason: str) -> None:
    ts = _dt.datetime.now().isoformat(timespec="seconds")
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    FAILURE_MARKER.write_text(f"{ts} {reason}\n")
