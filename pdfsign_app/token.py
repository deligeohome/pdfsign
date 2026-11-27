"""Hardware token access through PKCS#11 (OpenSC), with lockout protection.

The secret may be a numeric PIN or an alphanumeric password (SafeNet: "Token Password");
PKCS#11 calls both "PIN". Safety rules enforced here (the Digital Signature PIN/password
locks PERMANENTLY after 3 wrong tries):
  * the PIN retry counter is read (non-consuming ISO 7816 status query) BEFORE any login;
  * a stored secret is only used while the counter is FULL (no previous failures);
  * a typed secret is refused when only the final try is left (unless explicitly overridden);
  * at most ONE login attempt per process - never retried automatically;
  * a rejected secret writes a lock marker that disables the stored one until the user acts;
  * an empty secret is never sent (it would mean "use PIN pad" to OpenSC).
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass

import PyKCS11
from PyKCS11 import PyKCS11Error
from asn1crypto import x509 as asn1_x509

from .config import record_pin_failure, validate_secret

# Default number of tries of a fresh signature PIN (IDPrime 940 Digital Signature PIN: 3).
# Configurable via config.ini [token] full_tries.
FULL_SIGN_PIN_TRIES = 3

_MECH_BY_DIGEST = {
    "sha256": PyKCS11.CKM_SHA256_RSA_PKCS,
    "sha384": PyKCS11.CKM_SHA384_RSA_PKCS,
    "sha512": PyKCS11.CKM_SHA512_RSA_PKCS,
}


class TokenError(Exception):
    pass


class PinSafetyError(TokenError):
    """Login refused BEFORE contacting the card, to protect the retry counter."""


class WrongPinError(TokenError):
    """The card rejected the PIN/password (one try was consumed)."""


@dataclass
class PinState:
    label: str
    tries_left: int | None  # None = could not be determined
    locked: bool
    final_try: bool
    count_low: bool
    full: int = FULL_SIGN_PIN_TRIES

    def describe(self) -> str:
        if self.locked:
            return f"{self.label}: LOCKED"
        t = "unknown" if self.tries_left is None else f"{self.tries_left}/{self.full}"
        return f"{self.label}: tries left {t}"


def _pkcs15_info(opensc_conf_env: dict) -> tuple[dict, dict]:
    """Return ({key_id_hex: auth_id_hex}, {auth_id_hex: (label, tries_left)}) via pkcs15-tool.

    pkcs15-tool reads the retry counter with an ISO 7816 VERIFY *without* PIN data,
    which returns the remaining tries and does not consume one.
    """
    try:
        out = subprocess.run(
            ["pkcs15-tool", "--list-keys", "--list-pins"],
            capture_output=True, text=True, timeout=30, env=opensc_conf_env,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}, {}
    keys, pins = {}, {}
    for block in re.split(r"\n(?=\S)", out):
        head = block.splitlines()[0] if block.strip() else ""
        fields = dict(
            (m.group(1).strip(), m.group(2).strip())
            for m in re.finditer(r"^\s+([A-Za-z_ ]+?)\s*:\s*(.*)$", block, re.M)
        )
        if head.startswith("Private") and "ID" in fields and "Auth ID" in fields:
            keys[fields["ID"].lower()] = fields["Auth ID"].lower()
        elif head.startswith("PIN [") and "ID" in fields:
            label = head[len("PIN ["):].rstrip("]")
            tries = fields.get("Tries left")
            pins[fields["ID"].lower()] = (label, int(tries) if tries and tries.lstrip("-").isdigit() else None)
    return keys, pins


class Token:
    @classmethod
    def from_settings(cls, s) -> "Token":
        return cls(s.pkcs11_module, s.slot, s.full_tries)

    def __init__(self, module_path: str, slot_selector: str = "auto",
                 full_tries: int = FULL_SIGN_PIN_TRIES):
        self.full_tries = full_tries
        if not os.path.exists(module_path):
            raise TokenError(f"PKCS#11 module not found: {module_path}")
        self.lib = PyKCS11.PyKCS11Lib()
        self.lib.load(module_path)
        self.session = None
        self._pin: str | None = None
        self._login_attempted = False
        self._key = None
        self._always_auth = False
        self.slot, self.cert_der, self.cert_id = self._find_slot(slot_selector)
        self.certificate = asn1_x509.Certificate.load(self.cert_der)

    # ---------------------------------------------------------------- discovery
    def _find_slot(self, selector: str):
        slots = self.lib.getSlotList(tokenPresent=True)
        if not slots:
            raise TokenError("No token found. Is the TokenME plugged in and pcscd running?")
        candidates = []
        for s in slots:
            label = self.lib.getTokenInfo(s).label.strip()
            if selector != "auto" and label != selector:
                continue
            try:
                sess = self.lib.openSession(s)
            except PyKCS11Error:
                continue  # uninitialised / unreadable slot
            try:
                for obj in sess.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]):
                    der, cid = sess.getAttributeValue(obj, [PyKCS11.CKA_VALUE, PyKCS11.CKA_ID])
                    der = bytes(der)
                    cert = asn1_x509.Certificate.load(der)
                    ku = cert.key_usage_value.native if cert.key_usage_value else set()
                    if selector != "auto" or "non_repudiation" in ku:
                        candidates.append((s, der, bytes(cid)))
            finally:
                sess.closeSession()
        if not candidates:
            raise TokenError("No slot with a non-repudiation (signing) certificate found."
                             if selector == "auto" else f"No slot labelled {selector!r} with a certificate.")
        if len(candidates) > 1:
            raise TokenError("Several signing certificates found; set 'slot' in config.ini.")
        return candidates[0]

    @property
    def slot_label(self) -> str:
        return self.lib.getTokenInfo(self.slot).label.strip()

    @property
    def signer_name(self) -> str:
        return self.certificate.subject.native.get("common_name", "?")

    @property
    def key_size_bytes(self) -> int:
        return (self.certificate.public_key.bit_size + 7) // 8

    # ---------------------------------------------------------------- PIN state
    def pin_state(self) -> PinState:
        info = self.lib.getTokenInfo(self.slot)
        flags = info.flags
        keys, pins = _pkcs15_info(dict(os.environ))
        label, tries = "Digital Signature PIN", None
        auth_id = keys.get(self.cert_id.hex())
        if auth_id and auth_id in pins:
            label, tries = pins[auth_id]
        return PinState(
            label=label,
            tries_left=tries,
            full=self.full_tries,
            locked=bool(flags & PyKCS11.CKF_USER_PIN_LOCKED) or tries == 0,
            final_try=bool(flags & PyKCS11.CKF_USER_PIN_FINAL_TRY) or tries == 1,
            count_low=bool(flags & PyKCS11.CKF_USER_PIN_COUNT_LOW)
                      or (tries is not None and tries < self.full_tries),
        )

    def check_login_allowed(self, stored_pin: bool, allow_final_try: bool = False) -> PinState:
        st = self.pin_state()
        if st.locked:
            raise PinSafetyError(f"{st.label} is LOCKED. Only the PUK/issuer can unblock it.")
        if self.lib.getTokenInfo(self.slot).flags & PyKCS11.CKF_PROTECTED_AUTHENTICATION_PATH:
            raise PinSafetyError("OpenSC is in PIN-pad mode (OPENSC_CONF override not active) - refusing.")
        if stored_pin:
            if st.tries_left is None:
                raise PinSafetyError("Cannot read the retry counter - refusing to use the stored "
                                     "PIN/password. Type it manually instead.")
            if st.count_low or st.final_try:
                raise PinSafetyError(
                    f"{st.describe()} - a previous attempt failed. The stored PIN/password is only "
                    f"used while the counter is full. Type it manually (a correct one resets it).")
        elif st.final_try and not allow_final_try:
            raise PinSafetyError(f"{st.describe()} - ONLY ONE TRY LEFT; a wrong PIN/password locks the key "
                                 f"permanently. Refusing (override deliberately with --allow-final-try).")
        return st

    # ---------------------------------------------------------------- login/sign
    @property
    def secret_length_limits(self) -> tuple[int, int]:
        ti = self.lib.getTokenInfo(self.slot)
        lo, hi = int(ti.ulMinPinLen or 4), int(ti.ulMaxPinLen or 16)
        return lo, hi

    def login(self, pin: str, stored_pin: bool, allow_final_try: bool = False,
              secret_type: str = "password") -> None:
        """`pin` is the PKCS#11 PIN: a numeric PIN or an alphanumeric password."""
        if self._login_attempted:
            raise PinSafetyError("Only one login attempt per run is allowed.")
        validate_secret(pin, secret_type, *self.secret_length_limits)
        self.check_login_allowed(stored_pin, allow_final_try)
        self._login_attempted = True
        self.session = self.lib.openSession(self.slot, PyKCS11.CKF_SERIAL_SESSION)
        try:
            self.session.login(pin, PyKCS11.CKU_USER)
        except PyKCS11Error as e:
            if e.value == PyKCS11.CKR_USER_ALREADY_LOGGED_IN:
                pass
            elif e.value in (PyKCS11.CKR_PIN_INCORRECT, PyKCS11.CKR_PIN_LOCKED):
                record_pin_failure(f"{e} (stored PIN: {stored_pin})")
                st = self.pin_state()
                raise WrongPinError(f"The token REJECTED the PIN/password. {st.describe()}.") from None
            else:
                raise TokenError(f"Login failed: {e}") from None
        self._pin = pin
        keys = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                                         (PyKCS11.CKA_ID, self.cert_id)])
        if len(keys) != 1:
            raise TokenError(f"Expected one private key with id {self.cert_id.hex()}, found {len(keys)}.")
        self._key = keys[0]
        try:
            (aa,) = self.session.getAttributeValue(self._key, [PyKCS11.CKA_ALWAYS_AUTHENTICATE])
            self._always_auth = bool(aa)
        except PyKCS11Error:
            self._always_auth = False

    def sign(self, data: bytes, digest_algorithm: str) -> bytes:
        if self._key is None:
            raise TokenError("Not logged in.")
        try:
            mech = PyKCS11.Mechanism(_MECH_BY_DIGEST[digest_algorithm.lower()], None)
        except KeyError:
            raise TokenError(f"Unsupported digest {digest_algorithm}") from None
        native = mech.to_native()  # keep a reference alive during the C calls
        ll, h = self.session.lib, self.session.session
        rv = ll.C_SignInit(h, native, self._key)
        if rv != PyKCS11.CKR_OK:
            raise TokenError(f"C_SignInit: {PyKCS11Error(rv)}")
        if self._always_auth:
            # Qualified keys may demand a fresh PIN per signature (CKU_CONTEXT_SPECIFIC).
            # OpenSC marks IDPrime signature-PIN keys "user consent". Same secret that just
            # succeeded, so this cannot burn a try.
            rv = ll.C_Login(h, PyKCS11.CKU_CONTEXT_SPECIFIC, PyKCS11.ckbytelist(self._pin))
            if rv in (PyKCS11.CKR_PIN_INCORRECT, PyKCS11.CKR_PIN_LOCKED):
                record_pin_failure(f"context-specific login: {PyKCS11Error(rv)}")
                raise WrongPinError("Token rejected the PIN/password on context-specific login.")
            if rv != PyKCS11.CKR_OK:
                raise TokenError(f"Context-specific login: {PyKCS11Error(rv)}")
        buf, sig = PyKCS11.ckbytelist(data), PyKCS11.ckbytelist()
        for _ in range(2):  # 1st call returns the length, 2nd the signature
            rv = ll.C_Sign(h, buf, sig)
            if rv != PyKCS11.CKR_OK:
                raise TokenError(f"C_Sign: {PyKCS11Error(rv)}")
        return bytes(sig)

    def close(self) -> None:
        self._pin = None
        if self.session is not None:
            try:
                self.session.logout()
            except PyKCS11Error:
                pass
            try:
                self.session.closeSession()
            except PyKCS11Error:
                pass
            self.session = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
