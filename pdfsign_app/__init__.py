"""User-level PDF signing with a PKCS#11 hardware token (OpenSC, no vendor middleware)."""

import os
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent

# Must be set before the OpenSC PKCS#11 module is loaded anywhere in the process.
# It disables OpenSC's "PIN pad" mode: the TokenME reader advertises a PIN pad it
# does not have, and with it enabled an *empty* PIN would trigger a pad-verify.
os.environ.setdefault("OPENSC_CONF", str(APP_DIR / "opensc-pdfsign.conf"))
