# pdfsign

Sign PDF documents on Linux with a **smart card / USB crypto token**, with **no vendor middleware**
and **no root**. pdfsign creates PAdES signatures with an RFC 3161 timestamp and long-term
validation data. It has a GUI for placing the visible signature and a CLI for scripting, and it is
careful not to lock your token by using up PIN tries.

Developed and tested with a **Bit4id TokenME EVO v2** (Thales/Gemalto **IDPrime 940** chip) carrying a
Greek **APED/ERMIS qualified signature certificate**. It should work with any token that OpenSC supports.

## Features

* **GUI** (PyQt5): open a PDF, drag a box where the signature goes, or click an existing empty
  signature field, or choose an invisible signature.
* **Auto-location**: put your name and role in `[identities]`, and pdfsign finds where *you* sign.
  It uses the empty signature field next to your name, or proposes a new box on the signature line.
  It handles multi-step forms and documents with several signature places.
* **Batch signing** of many files with one password entry: select several files in the GUI's
  *Open* dialog and click *Sign all files*, or `pdfsign sign 'reports/*.pdf'` on the command line.
* **CLI** for scripting: `pdfsign sign doc.pdf` (auto-located) or `--page 4 --box 225,600,368,655`.
* **PAdES B-T / B-LT / B-LTA**: SHA-256, RSA computed on the token, RFC 3161 timestamp, with the
  certificate chain and OCSP/CRL embedded for long-term validation. The issuer chain is fetched
  automatically via AIA.
* Unlock with a **password** (alphanumeric, e.g. SafeNet's "Token Password") or a **numeric PIN**,
  typed in or stored in a protected `credentials.ini`.
* **Lockout protection** (see below).
* Visible stamp with a Unicode font, so Greek and other scripts work.
* Existing signatures stay valid (incremental update). The original file is never overwritten.

## How it talks to the token

```
pdfsign (Python) ─ PyKCS11 ─ OpenSC opensc-pkcs11.so ─ pcscd ─ CCID driver ─ USB token
```

Most USB tokens are standard **CCID smart-card readers**, so the generic `libccid` driver works.
OpenSC includes drivers for many cards (IDPrime, PIV, CardOS, Estonian/Belgian eID, …).
Vendor middleware such as SafeNet Authentication Client or Bit4id's library is **not** needed.
It doesn't get in the way if installed, since `pcscd` shares the reader.

### How the PIN / password is passed
1. `C_Login(CKU_USER, secret)` on the OpenSC slot that holds the signing key. On an IDPrime 940
   this is the separate *"Digital Signature PIN"* slot.
2. OpenSC sends an ISO 7816 `VERIFY` with the secret's ASCII bytes. On IDPrime they are padded to
   16 bytes with `0x00`. Letters and symbols are sent unchanged, so a "password" works the same as a PIN.
3. If the key requires per-signature consent (`CKA_ALWAYS_AUTHENTICATE`, which OpenSC sets for IDPrime
   signature keys), a context-specific login with the same secret is done before each signature.

### Lockout protection
Qualified signature keys often **lock permanently** after 3 wrong tries. pdfsign:
* reads the retry counter **before** every login. Reading it does not use a try
  (ISO 7816 `VERIFY` without data);
* uses the **stored** secret only while the counter is full. After a failure you must type it yourself;
* refuses a typed secret when **one try is left** (unless you pass `--allow-final-try`);
* makes **one login attempt per run** and never retries automatically;
* writes `.pin_failure.lock` after a rejection, which disables the stored secret until you fix it
  and delete the file;
* checks the format locally (length within the token's limits, ASCII only, digits only in PIN mode,
  never empty);
* disables OpenSC PIN-pad mode (`opensc-pdfsign.conf`). Some tokens falsely advertise a PIN pad,
  which would make an empty PIN start a pad verification.

## Requirements

| Component | Debian / Ubuntu | Fedora | Arch |
|---|---|---|---|
| Smart-card daemon | `pcscd` | `pcsc-lite` | `pcsclite` |
| CCID reader driver | `libccid` | `pcsc-lite-ccid` | `ccid` |
| OpenSC (PKCS#11 + `pkcs15-tool`) | `opensc` | `opensc` | `opensc` |
| Python ≥ 3.9 with venv | `python3-venv python3-pip` | `python3-pip` | `python-pip` |
| PyQt5 (else installed from PyPI) | `python3-pyqt5` | `python3-qt5` | `python-pyqt5` |
| Stamp font (optional) | `fonts-noto-core` | `google-noto-sans-fonts` | `noto-fonts` |

One-time install, e.g. on Ubuntu:
```bash
sudo apt install pcscd libccid opensc python3-venv python3-pip python3-pyqt5 fonts-noto-core
sudo systemctl enable --now pcscd.socket
```
Python packages (`requirements.txt`): pyHanko, pyhanko-certvalidator, PyKCS11, PyMuPDF, requests, aiohttp.
`install.sh` installs them into a virtualenv. **Only the system packages above need root.**

## Install

```bash
git clone https://github.com/deligeohome/pdfsign.git
cd pdfsign
./install.sh        # checks the system packages, creates ~/.local/share/pdfsign/venv,
                    # credentials.ini (mode 600) and a "PDF Sign" menu entry
./pdfsign info      # shows token, certificate and retry counter; never uses the secret
```

## Configure

`config.ini` (no secrets):

| key | default | meaning |
|---|---|---|
| `[token] pkcs11_module` | `auto` | path of `opensc-pkcs11.so` (common locations are searched) |
| `[token] secret_type` | `password` | `password` (any printable ASCII) or `pin` (digits) |
| `[token] full_tries` | `3` | tries of a fresh signing PIN on your card |
| `[token] slot` | `auto` | slot holding the non-repudiation certificate, or a token label |
| `[tsa] url` | APED qualified TSA | any RFC 3161 server, e.g. `http://timestamp.digicert.com` |
| `[signature] level` | `B-LT` | `B-T`, `B-LT` or `B-LTA` |
| `[signature] stamp_text` | … | `%(signer)s` and `%(ts)s` placeholders |
| `[signature] font` | `auto` | TTF/OTF with **1000 units/em** (e.g. Noto Sans) |
| `[signature] stamp_border` | `auto` | frame around the stamp: only for new boxes (`auto`), `yes`, `no` |
| `[signature] stamp_padding` | `5` | space (pt) between frame and text; proposed boxes shrink to fit the stamp |
| `[signature] output_suffix` | `auto` | signed file name suffix: `_<initials>` from the certificate, or fixed text |
| `[autolocate] field_radius` | `120` | max distance (pt) between your name and its signature field |
| `[autolocate] box_width/height` | `160` / `50` | size of a proposed new box |
| `[autolocate] merge_gap` | `200` | side-by-side places closer than this share one signature (0 = off) |

`credentials.ini` (git-ignored; must be `chmod 600`; or point `$PDFSIGN_CREDENTIALS` elsewhere):
```ini
[token]
signature_password = My#Pass9
signature_pin =
```
Fill in `signature_password` for `secret_type = password`, or `signature_pin` (digits) for
`secret_type = pin`. Leave both empty to be asked every time. Storing the secret is a
convenience/security trade-off: anyone who can read the file and has the token can sign.

## Auto-location of the signature place

Add the text that identifies you to `credentials.ini`:
```ini
[identities]
names = Jane Doe
    DOE JANE
roles = Project Coordinator
```
pdfsign searches the PDF for these entries. Matching ignores case, accents and punctuation (Greek
included), and multi-word entries must be adjacent words. Names also match in any word order and
with initials (`Jane Doe` finds `DOE JANE`, `J. Doe` and `Doe J.`). For each place where you are found:

| what is next to your name (within `field_radius`) | action |
|---|---|
| an **empty signature field** | sign into that field |
| a **signed** field | already done, skipped |
| an **empty box drawn** in the page (form frame without a field) | sign exactly into that box, without an extra frame |
| nothing | propose a **new box** above / right / below / left of the name, fitted between the surrounding text and table lines |

A field or box only belongs to your text if it is **beside** it or **above/below** it, never diagonal.
A diagonal box is typically the slot of the next label, e.g. the director's box under the requester's.

* `names` are primary, **per page**. On a page showing your name, a role only counts when it sits
  right next to that name, so a role shared with other signers (e.g. "Member") is not mistaken for yours.
  On a page without your name, the role itself marks the place, e.g. a form that only says
  "THE REQUESTING PERSON IN CHARGE:" next to the signature field.
* A bare mention of your name (e.g. in a member list or a "NAME: …" line) is ignored when the
  document has a better candidate: a nearby signature field, a signature line / "Signature" label,
  or a name standing alone with free signing space above it (a typical signature block).
* **Side-by-side places** (your name on the same line under two neighbouring roles, e.g. traveller and
  project supervisor, with only blank space between) get **one** signature centred between them,
  unless each already has its own empty field. `[autolocate] merge_gap` (default 200 pt; 0 = off).
* If several unsigned places remain, you are asked whether to sign the **first** one or **all** of them
  (GUI dialog, CLI prompt, or `--first` / `--all`). "All" uses one login and adds one signature per place.
* **Multi-step forms**: each run signs the next unsigned step. Already-signed steps are recognised
  by their signed field, including boxes pdfsign created itself.

Check the result without the token: `./pdfsign locate doc.pdf`. In the GUI the proposals are shown
in orange, and *Auto-locate* is preselected on the page of the first unsigned place. Tune with
`[autolocate] field_radius, box_width, box_height` in `config.ini`.

## Use

**GUI:** `./pdfsign` or `./pdfsign gui file.pdf …`. Existing signature fields are outlined (blue = empty,
green = signed) and auto-located places are orange. Keep *Auto-locate*, click a field, or drag a new
box, then click *Sign PDF…*. After signing, *Load here (next step)* opens the result for the next step.

Select **several files** in *Open…* (Ctrl/Shift-click) and a file list appears showing what is left
to sign in each one. Click a file to inspect it, or *Sign all files (auto-locate)…* to sign them all
with one password entry. Signed copies are saved next to the originals as `<name>_<initials>.pdf`.

**CLI:**
```bash
./pdfsign fields doc.pdf                                  # list signature fields
./pdfsign locate doc.pdf                                  # where [identities] would sign (no token)
./pdfsign sign doc.pdf                                    # auto-locate; asks first/all if several
./pdfsign sign doc.pdf --all                              # sign every unsigned identity place
./pdfsign sign doc.pdf --field Signature1                 # fill an existing empty field
./pdfsign sign doc.pdf --page 1 --box 350,50,560,120 --reason "Approved" --location "Heraklion"
./pdfsign sign doc.pdf --invisible --ask                  # ignore stored secret, prompt
./pdfsign sign doc.pdf --invisible --secret-type pin      # unlock with a numeric PIN this time
./pdfsign verify doc_MP.pdf

# batch: files, folders and patterns; one password entry for all
./pdfsign sign 'reports/*Mission*.pdf'                    # every matching file
./pdfsign sign reports/ --pattern '*2026*.pdf' --all -y   # folder + filter, no questions
./pdfsign sign a.pdf b.pdf --outdir signed/               # write the signed copies elsewhere
```
In batch mode each file is auto-located, files with nothing left to sign are skipped, and outputs
of earlier runs (`*_<initials>.pdf`) found through a folder or pattern are ignored. You are asked
once whether to sign the first or all places (unless `--first`/`--all`) and to confirm (unless `-y`).
A failure in one file (e.g. timestamp server down) does not stop the others; a summary is printed.
`--box` is `x1,y1,x2,y2` in PDF points, origin bottom-left (A4 = 595 × 842). The output defaults to
`<name>_<initials>.pdf`, with the initials taken from your certificate (e.g. `report_MP.pdf`). A file
that already carries the suffix is not suffixed twice, and existing files get `-2`, `-3`, …
(`[signature] output_suffix`).

## Notes and limitations

* Tested on Ubuntu 24.04, OpenSC 0.25, pyHanko 0.38, with an IDPrime 940 (RSA-2048). Other
  OpenSC-supported cards should work. Check `./pdfsign info` first and set `full_tries` for your card.
* Non-ASCII passwords are refused, because the byte encoding used when the password was set is unknown.
* pyHanko 0.38 mis-scales glyph widths of fonts whose units/em is not 1000 (e.g. DejaVu Sans).
  Such fonts are rejected, and the built-in Latin font is used instead.
* B-LT/B-LTA need the TSA and the signer's CA to be reachable (OCSP/CRL) at signing time.
* Encrypted PDFs are not supported.

## Files

| | |
|---|---|
| `pdfsign` | launcher (uses the virtualenv) |
| `install.sh` | requirement check and user-level install |
| `requirements.txt` | Python dependencies |
| `config.ini` | settings |
| `credentials.ini.example` | template for the git-ignored `credentials.ini` |
| `opensc-pdfsign.conf` | OpenSC override (PIN pad off), used only by pdfsign |
| `pdfsign_app/token.py` | PKCS#11 access and lockout protection |
| `pdfsign_app/signing.py` | PAdES signing, TSA, LTV, verification (pyHanko) |
| `pdfsign_app/autolocate.py` | signature place detection from `[identities]` |
| `pdfsign_app/workflow.py`, `cli.py`, `gui.py` | sign flow and user interfaces |

## License

MIT, see [LICENSE](LICENSE). Use at your own risk. You are responsible for the legal validity of the
signatures you create and for protecting your token and its secret.
