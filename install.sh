#!/usr/bin/env bash
# pdfsign user-level installer (no sudo needed for this script).
#  1. checks the system smart-card stack (pcscd + CCID driver + OpenSC) and tells you
#     the one-time package command if something is missing;
#  2. creates a Python virtualenv in ~/.local/share/pdfsign/venv and installs requirements.txt;
#  3. creates credentials.ini (mode 600, git-ignored) and a desktop menu entry.
set -euo pipefail
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
VENV="${PDFSIGN_VENV:-$HOME/.local/share/pdfsign/venv}"

ok()   { printf '  \e[32m✔\e[0m %s\n' "$*"; }
bad()  { printf '  \e[31m✘\e[0m %s\n' "$*"; MISSING=1; }
MISSING=0

# --- distro specific package names -------------------------------------------------
. /etc/os-release 2>/dev/null || true
case " ${ID:-} ${ID_LIKE:-} " in
  *" debian "*|*" ubuntu "*)
    PKG="sudo apt install pcscd libccid opensc python3-venv python3-pip python3-pyqt5 fonts-noto-core" ;;
  *" fedora "*|*" rhel "*|*" centos "*)
    PKG="sudo dnf install pcsc-lite pcsc-lite-ccid opensc python3-pip python3-qt5 google-noto-sans-fonts" ;;
  *" arch "*)
    PKG="sudo pacman -S pcsclite ccid opensc python-pip python-pyqt5 noto-fonts" ;;
  *" suse "*|*" opensuse "*)
    PKG="sudo zypper install pcsc-lite pcsc-ccid opensc python3-pip python3-qt5 google-noto-sans-fonts" ;;
  *) PKG="install: pcscd (pcsc-lite), CCID driver, OpenSC, python3 venv/pip, PyQt5, Noto Sans font" ;;
esac

echo "Checking system requirements..."
if command -v python3 >/dev/null && python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))'; then
  ok "python3 $(python3 -c 'import platform; print(platform.python_version())')"
else
  bad "python3 >= 3.9 not found"
fi
python3 -c 'import venv, ensurepip' 2>/dev/null && ok "python3 venv" || bad "python3 venv/ensurepip missing"

if systemctl is-active --quiet pcscd.socket 2>/dev/null || systemctl is-active --quiet pcscd 2>/dev/null \
   || pgrep -x pcscd >/dev/null; then
  ok "pcscd (smart-card daemon)"
elif command -v pcscd >/dev/null || [ -x /usr/sbin/pcscd ]; then
  bad "pcscd installed but not running:  sudo systemctl enable --now pcscd.socket"
else
  bad "pcscd not installed"
fi
if compgen -G "/usr/lib*/pcsc/drivers/ifd-ccid.bundle" >/dev/null \
   || compgen -G "/usr/lib/*/pcsc/drivers/ifd-ccid.bundle" >/dev/null; then
  ok "CCID reader driver"
else
  bad "CCID driver (libccid / pcsc-lite-ccid / ccid) not found"
fi
command -v pkcs15-tool >/dev/null && ok "OpenSC tools" || bad "OpenSC (pkcs15-tool) not found"
MOD="$(PYTHONPATH="$HERE" python3 -c 'from pdfsign_app.config import PKCS11_CANDIDATES as C; import os; print(next((p for p in C if os.path.exists(p)), ""))' 2>/dev/null || true)"
if [ -n "$MOD" ]; then ok "OpenSC PKCS#11 module $MOD"
else bad "opensc-pkcs11.so not found (set pkcs11_module in config.ini if it is elsewhere)"; fi

if [ "$MISSING" = 1 ]; then
  echo
  echo "Some system components are missing. Install them once with:"
  echo "    $PKG"
  echo "    sudo systemctl enable --now pcscd.socket"
  echo "then re-run ./install.sh"
  exit 1
fi

# --- Python virtualenv -------------------------------------------------------------
echo "Creating virtualenv in $VENV ..."
python3 -m venv --system-site-packages "$VENV"      # reuses the distro PyQt5 if present
"$VENV/bin/python" -m pip install -q --upgrade pip
"$VENV/bin/python" -m pip install -q -r "$HERE/requirements.txt"
if ! "$VENV/bin/python" -c 'import PyQt5.QtWidgets' 2>/dev/null; then
  echo "System PyQt5 not found - installing PyQt5 from PyPI"
  "$VENV/bin/python" -m pip install -q "PyQt5>=5.15"
fi
"$VENV/bin/python" -c 'import pyhanko, PyKCS11, pymupdf, PyQt5.QtWidgets' && ok "Python packages"

# --- user files ----------------------------------------------------------------------
if [ ! -e "$HERE/credentials.ini" ]; then
  install -m 600 "$HERE/credentials.ini.example" "$HERE/credentials.ini"
  ok "created credentials.ini (mode 600, git-ignored)"
fi
chmod +x "$HERE/pdfsign"

mkdir -p "$HOME/.local/share/applications"
cat > "$HOME/.local/share/applications/pdfsign.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=PDF Sign
Comment=Sign PDF documents with a smart card / USB token
Exec="$HERE/pdfsign" gui %F
Icon=application-pdf
MimeType=application/pdf;
Terminal=false
Categories=Office;
EOF
ok "menu entry 'PDF Sign'"
echo
echo "Done. Plug in the token and run:  $HERE/pdfsign info     (never uses your PIN/password)"
echo "GUI:                              $HERE/pdfsign"
