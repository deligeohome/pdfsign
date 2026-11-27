"""PDF (PAdES) signing with pyHanko: visible/invisible fields, RFC 3161 timestamp, LTV."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import requests
from asn1crypto import x509 as asn1_x509
from pyhanko.pdf_utils.font.opentype import GlyphAccumulatorFactory
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils import layout
from pyhanko.pdf_utils.text import DEFAULT_BOX_LAYOUT, TextBoxStyle
from pyhanko.sign import fields, signers, timestamps
from pyhanko.sign.fields import SigFieldSpec, SigSeedSubFilter
from pyhanko.sign.signers.pdf_cms import Signer
from pyhanko.stamp import TextStampStyle
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.registry import SimpleCertificateStore

from .config import CERT_CACHE, Settings


# ------------------------------------------------------------------ certificates
def _load_cert(data: bytes) -> asn1_x509.Certificate:
    if data.lstrip().startswith(b"-----BEGIN"):
        from asn1crypto import pem
        _, _, data = pem.unarmor(data)
    return asn1_x509.Certificate.load(data)


def fetch_chain(cert: asn1_x509.Certificate, log: Callable[[str], None] = print) -> list:
    """Follow AIA 'CA Issuers' URLs up to a self-signed root; cache in ./certs."""
    CERT_CACHE.mkdir(exist_ok=True)
    chain, cur = [], cert
    for _ in range(6):
        if cur.self_signed in ("maybe", "yes"):
            break
        aia = cur.authority_information_access_value
        urls = [u for u in (aia.native if aia else []) if u["access_method"] == "ca_issuers"]
        if not urls:
            break
        url = urls[0]["access_location"]
        cache = CERT_CACHE / Path(url).name
        if not cache.exists():
            log(f"Downloading issuer certificate {url}")
            r = requests.get(url, timeout=20)
            r.raise_for_status()
            cache.write_bytes(r.content)
        cur = _load_cert(cache.read_bytes())
        chain.append(cur)
    return chain


def validation_context(chain: list, extra_roots=()) -> ValidationContext:
    roots = [c for c in chain if c.self_signed in ("maybe", "yes")] + list(extra_roots)
    others = [c for c in chain if c not in roots]
    return ValidationContext(trust_roots=roots, other_certs=others, allow_fetching=True)


# ------------------------------------------------------------------ output name
def initials(cert: asn1_x509.Certificate) -> str:
    """GN + SN initials from the certificate subject (MARIA PAPADOPOULOU -> MP)."""
    subj = cert.subject.native
    parts = [subj.get("given_name"), subj.get("surname")]
    if not all(parts):
        parts = str(subj.get("common_name", "")).split()
    letters = "".join(p.strip()[0] for p in parts if p and p.strip())
    return letters.upper() or "SIGNED"


def output_suffix(settings: Settings, cert: asn1_x509.Certificate | None) -> str:
    s = (settings.output_suffix or "").strip()
    if s.lower() == "auto":
        return f"_{initials(cert)}" if cert is not None else "_signed"
    return s or "_signed"


def default_output(input_pdf: str, suffix: str) -> str:
    """<stem><suffix>.pdf next to the input; never the input itself, never an existing file.
    A file that already ends with the suffix (next step of a form) is not suffixed twice."""
    src = Path(input_pdf)
    stem = src.stem if src.stem.endswith(suffix) else src.stem + suffix
    cand, n = src.with_name(stem + ".pdf"), 2
    while cand.exists() or cand.resolve() == src.resolve():
        cand, n = src.with_name(f"{stem}-{n}.pdf"), n + 1
    return str(cand)


# ------------------------------------------------------------------ signer
class TokenSigner(Signer):
    """pyHanko Signer whose raw RSA operation happens on the hardware token."""

    def __init__(self, token, chain: list):
        super().__init__(
            signing_cert=token.certificate,
            cert_registry=SimpleCertificateStore.from_certs(chain),
            prefer_pss=False,
        )
        self.token = token

    async def async_sign_raw(self, data: bytes, digest_algorithm: str, dry_run=False) -> bytes:
        if dry_run:
            return bytes(self.token.key_size_bytes)
        return self.token.sign(data, digest_algorithm)


# ------------------------------------------------------------------ fields
@dataclass
class SigField:
    name: str
    filled: bool


def list_signature_fields(pdf_path: str) -> list[SigField]:
    with open(pdf_path, "rb") as f:
        r = PdfFileReader(f, strict=False)
        return [SigField(name, value is not None)
                for name, value, _ref in fields.enumerate_sig_fields(r)]


def _unique_field_name(pdf_path: str, base: str = "Signature") -> str:
    existing = {f.name for f in list_signature_fields(pdf_path)}
    i = 1
    while f"{base}{i}" in existing:
        i += 1
    return f"{base}{i}"


# ------------------------------------------------------------------ signing
@dataclass
class Placement:
    """Where one signature goes: an existing field, or a new box (None box = invisible)."""
    field_name: str | None
    page: int = 0
    box: tuple | None = None
    frame: bool = True       # draw a frame around a NEW box (False: the page already draws one)
    fit: str | None = None   # shrink a NEW box to the stamp, keeping this edge (bottom/top/left/right/center)


def _border(settings: Settings, new_field, frame: bool | None = None) -> int:
    """auto: frame only for new boxes, not for existing fields or boxes the page already draws."""
    mode = getattr(settings, "stamp_border", "auto")
    if mode in ("yes", "true", "1", "on"):
        return 1
    if mode in ("no", "false", "0", "off"):
        return 0
    return 1 if new_field is not None and frame is not False else 0


def _stamp_size(style: TextStampStyle, signer_name: str) -> tuple[float, float]:
    """Natural size of the stamp (text + padding) in points."""
    from pyhanko.pdf_utils.writer import PdfFileWriter
    from pyhanko.stamp import TextStamp
    st = TextStamp(PdfFileWriter(), style, text_params={"signer": signer_name})
    st.render()
    return st.box.width, st.box.height


def _fit_box(box: tuple, size: tuple[float, float], edge: str) -> tuple:
    """Shrink box (x1, y1, x2, y2, PDF y-up) to size, keeping the given edge; never grow it."""
    x1, y1, x2, y2 = box
    w, h = min(size[0] + 2, x2 - x1), min(size[1] + 2, y2 - y1)   # +2: room for the frame line
    cx, cy = (x1 + x2) / 2, (y1 + y2) / 2
    nx1 = x1 if edge == "left" else x2 - w if edge == "right" else cx - w / 2
    ny1 = y1 if edge == "bottom" else y2 - h if edge == "top" else cy - h / 2
    return (nx1, ny1, nx1 + w, ny1 + h)


def _font_usable(path: str, log) -> bool:
    if not os.path.exists(path):
        log(f"Stamp font not found: {path}")
        return False
    from fontTools import ttLib
    upem = ttLib.TTFont(path, lazy=True)["head"].unitsPerEm
    if upem != 1000:
        # pyHanko writes /W widths in font units, which is only correct for 1000 units/em.
        log(f"Stamp font {Path(path).name} has {upem} units/em (needs 1000; would render spaced out).")
        return False
    return True


@dataclass
class SignRequest:
    input_pdf: str
    output_pdf: str
    field_name: str | None = None          # existing empty field, or name for the new one
    page: int = 0                          # 0-based page for a NEW field
    box: tuple | None = None               # (x1, y1, x2, y2) PDF user-space points; None = invisible
    frame: bool | None = None              # frame around a new box (None = default)
    fit: str | None = None                 # shrink the new box to the stamp (see Placement.fit)
    reason: str = ""
    location: str = ""
    contact: str = ""
    level: str = "B-LT"


def sign_pdf(req: SignRequest, signer: Signer, settings: Settings, chain: list,
             extra_roots=(), log: Callable[[str], None] = print) -> str:
    inp, out = Path(req.input_pdf).resolve(), Path(req.output_pdf).resolve()
    if inp == out:
        raise ValueError("Output must differ from input (the original is never overwritten).")

    # space between the frame and the text (pyHanko's default is 10 pt)
    padding = DEFAULT_BOX_LAYOUT.substitute_margins(layout.Margins.uniform(settings.stamp_padding))
    text_style = TextBoxStyle(box_layout_rule=padding)
    if settings.font:
        if _font_usable(settings.font, log):
            text_style = TextBoxStyle(font=GlyphAccumulatorFactory(settings.font, settings.font_size),
                                      font_size=settings.font_size, box_layout_rule=padding)
        else:
            log("Using the built-in stamp font (Latin only).")
    existing = {f.name: f for f in list_signature_fields(str(inp))}
    new_field = None
    if req.field_name and req.field_name in existing:
        if existing[req.field_name].filled:
            raise ValueError(f"Field {req.field_name!r} is already signed.")
        field_name = req.field_name
    else:
        field_name = req.field_name or _unique_field_name(str(inp))
        new_field = SigFieldSpec(sig_field_name=field_name, on_page=req.page,
                                 box=tuple(req.box) if req.box else None)
    style = TextStampStyle(stamp_text=settings.stamp_text,
                           timestamp_format=settings.timestamp_format,
                           text_box_style=text_style, border_width=_border(settings, new_field, req.frame))
    if new_field is not None and req.box and req.fit:
        # proposed box: hug the stamp so the frame sits close to the text
        box = _fit_box(tuple(req.box), _stamp_size(style, signer.subject_name or ""), req.fit)
        new_field = SigFieldSpec(sig_field_name=field_name, on_page=req.page, box=box)
    lt = req.level in ("B-LT", "B-LTA")
    meta = signers.PdfSignatureMetadata(
        field_name=field_name,
        md_algorithm="sha256",
        subfilter=SigSeedSubFilter.PADES,
        reason=req.reason or None,
        location=req.location or None,
        contact_info=req.contact or None,
        embed_validation_info=lt,
        use_pades_lta=req.level == "B-LTA",
        validation_context=validation_context(chain, extra_roots) if lt else None,
    )
    tsa = timestamps.HTTPTimeStamper(settings.tsa_url, timeout=30)
    pdf_signer = signers.PdfSigner(meta, signer=signer, timestamper=tsa,
                                   stamp_style=style, new_field_spec=new_field)

    log(f"Signing into field {field_name!r} ({req.level}, TSA {settings.tsa_url}) ...")
    out.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".pdfsign-", suffix=".pdf", dir=out.parent)
    try:
        with open(inp, "rb") as fin, os.fdopen(fd, "wb") as fout:
            w = IncrementalPdfFileWriter(fin, strict=False)
            pdf_signer.sign_pdf(w, output=fout)
        umask = os.umask(0)
        os.umask(umask)
        os.chmod(tmp, 0o666 & ~umask)   # mkstemp creates 0600; give normal file permissions
        os.replace(tmp, out)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    log(f"Signed PDF written to {out}")
    return str(out)


# ------------------------------------------------------------------ verification
def verify_pdf(pdf_path: str, chain: list, extra_roots=()) -> list[str]:
    from pyhanko.sign.validation import validate_pdf_signature, validate_pdf_timestamp

    report = []
    with open(pdf_path, "rb") as f:
        r = PdfFileReader(f, strict=False)
        if not r.embedded_signatures:
            return ["No signatures found."]
        for sig in r.embedded_signatures:
            vc = validation_context(chain, extra_roots)
            if sig.sig_object_type == "/DocTimeStamp":
                st = validate_pdf_timestamp(sig, validation_context=vc)
                kind = "document timestamp"
            else:
                st = validate_pdf_signature(sig, vc)
                kind = "signature"
            report.append(f"--- {kind} field {sig.field_name}\n{st.pretty_print_details()}")
    return report
