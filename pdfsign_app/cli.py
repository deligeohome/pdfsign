"""Command-line interface.  Run without arguments to start the GUI."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from .autolocate import LocateOptions, find_locations, select
from .config import FAILURE_MARKER, ConfigError, load_settings, read_identities
from .signing import (SignRequest, default_output, fetch_chain, list_signature_fields,
                      output_suffix, verify_pdf)
from .token import PinState, Token, TokenError
from .workflow import Cancelled, Job, sign_batch


def _make_prompt(word: str):
    def _prompt(state: PinState, note: str | None) -> str | None:
        if note:
            print(f"[!] {note}", file=sys.stderr)
        print(f"[i] {state.describe()}", file=sys.stderr)
        if state.count_low:
            print(f"[!] WARNING: previous wrong attempts recorded. Another wrong {word} brings the "
                  "key closer to PERMANENT lock.", file=sys.stderr)
            if input("    Type YES to continue: ").strip() != "YES":
                return None
        return getpass.getpass(f"Digital Signature {word} (hidden): ") or None
    return _prompt


def cmd_info(args, s):
    t = Token.from_settings(s)
    c = t.certificate
    print(f"Slot        : {t.slot}  [{t.slot_label}]")
    print(f"Signer      : {c.subject.human_friendly}")
    print(f"Issuer      : {c.issuer.human_friendly}")
    print(f"Valid       : {c['tbs_certificate']['validity']['not_before'].native} -> "
          f"{c['tbs_certificate']['validity']['not_after'].native}")
    print(f"Key         : RSA {t.key_size_bytes * 8}")
    lo, hi = t.secret_length_limits
    print(f"Unlock with : {s.secret_word} ({lo}-{hi} chars)  [secret_type in config.ini]")
    print(f"Retries     : {t.pin_state().describe()}  (full = {t.full_tries})")
    print(f"Fail marker : {'PRESENT - stored secret disabled' if FAILURE_MARKER.exists() else 'none'}")
    print("(no PIN/password was used)")


def cmd_fields(args, s):
    if not Path(args.pdf).is_file():
        sys.exit(f"File not found: {args.pdf}")
    fs = list_signature_fields(args.pdf)
    if not fs:
        print("No signature fields.")
    for f in fs:
        print(f"{f.name:30s} {'signed' if f.filled else 'EMPTY'}")


def _print_locations(locs):
    for l in locs:
        mark = "->" if l.unsigned else "  "
        print(f" {mark} #{l.order} {l.describe()}")


def cmd_locate(args, s):
    ids = read_identities()
    if ids.empty:
        sys.exit("No [identities] in credentials.ini - nothing to look for.")
    locs = find_locations(args.pdf, ids, LocateOptions.from_settings(s))
    if not locs:
        print("None of the identities was found in the document.")
    _print_locations(locs)


def expand_inputs(items: list[str], pattern: str = "*.pdf", suffix: str | None = None) -> list[Path]:
    """Files, directories (-> files matching `pattern`) and glob patterns -> PDF list.
    Outputs of earlier runs (<name><suffix>.pdf, <name><suffix>-2.pdf) found through a folder or
    pattern are skipped; a file named explicitly is always used (e.g. the next step of a form)."""
    import glob
    import re
    found: list[tuple[Path, bool]] = []          # (path, named explicitly)
    for it in items:
        p = Path(it).expanduser()
        if p.is_dir():
            found += [(q, False) for q in sorted(p.glob(pattern)) if q.is_file()]
        elif p.is_file():
            found.append((p, True))
        elif any(ch in it for ch in "*?["):
            found += [(Path(q), False) for q in sorted(glob.glob(str(p))) if Path(q).is_file()]
        else:
            sys.exit(f"File not found: {it}")
    output_name = re.compile(re.escape(suffix) + r"(-\d+)?$") if suffix else None
    seen, res = set(), []
    for q, explicit in found:
        if q.resolve() in seen or q.suffix.lower() != ".pdf":
            continue
        seen.add(q.resolve())
        if not explicit and output_name and output_name.search(q.stem):
            print(f"  skip {q.name}  (signed output of an earlier run)")
            continue
        res.append(q)
    return res


def _auto_placements(pdf, args, s, ids, mode=None, batch=False):
    """Placements for one file; returns None when there is nothing to sign."""
    locs = find_locations(str(pdf), ids, LocateOptions.from_settings(s))
    if not batch:
        print("Identity locations:" if locs else "Identities not found in the document.")
        _print_locations(locs)
    unsigned = [l for l in locs if l.unsigned]
    if not unsigned:
        if not batch:
            sys.exit("No unsigned location for your identities (all signed or not found). "
                     "Use --field, --page/--box, --invisible or the GUI.")
        return None
    mode = mode or ("all" if args.all else "first" if (args.first or len(unsigned) == 1) else None)
    if mode is None:
        ans = input(f"{len(unsigned)} unsigned locations. Sign [f]irst one (#{unsigned[0].order}), "
                    f"[a]ll {len(unsigned)}, or [c]ancel? ").strip().lower()
        mode = {"f": "first", "a": "all"}.get(ans[:1])
        if mode is None:
            raise Cancelled("Cancelled - nothing was signed.")
    chosen = select(locs, mode)
    where = ", ".join(f"#{l.order} (page {l.page + 1})" for l in chosen)
    print(f"  {pdf.name}: {where}" if batch else "Signing at: " + where)
    return [l.placement() for l in chosen]


def cmd_sign(args, s):
    auto = args.auto or not (args.field or args.box or args.invisible)
    box = tuple(float(v) for v in args.box.split(",")) if args.box else None
    if box and len(box) != 4:
        sys.exit("--box needs x1,y1,x2,y2 (PDF points, origin bottom-left)")
    try:
        cert = Token.from_settings(s).certificate      # public data only, no PIN
    except TokenError:
        cert = None
    suffix = output_suffix(s, cert)
    files = expand_inputs(args.pdf, args.pattern, suffix)
    if not files:
        sys.exit("No PDF matches.")
    batch = len(files) > 1 or len(args.pdf) > 1 or not Path(args.pdf[0]).is_file()
    if args.output and batch:
        sys.exit("-o/--output works with a single file; use --outdir for several.")
    if args.secret_type:
        s.secret_type = args.secret_type
    ids = read_identities() if auto else None
    if auto and ids.empty:
        sys.exit("No [identities] in credentials.ini: give --field, --page/--box or --invisible.")

    mode = "all" if args.all else "first" if args.first else None
    if batch:
        print(f"{len(files)} file(s):")
    if batch and auto and mode is None:
        multi = [f.name for f in files
                 if sum(l.unsigned for l in find_locations(str(f), ids, LocateOptions.from_settings(s))) > 1]
        if multi:
            ans = input(f"{len(multi)} of {len(files)} files have several unsigned places. In those, "
                        "sign the [f]irst, [a]ll, or [c]ancel? ").strip().lower()
            mode = {"f": "first", "a": "all"}.get(ans[:1])
            if mode is None:
                raise Cancelled("Cancelled - nothing was signed.")
        mode = mode or "first"

    jobs, skipped = [], []
    for f in files:
        if args.output:
            out = args.output
        else:
            out = default_output(str(f), suffix, args.outdir)
        req = SignRequest(str(f), out, field_name=args.field, page=args.page - 1,
                          box=None if args.invisible else box,
                          reason=args.reason if args.reason is not None else s.reason,
                          location=args.location if args.location is not None else s.location,
                          contact=s.contact, level=(args.level or s.level).upper())
        placements = None
        if auto:
            placements = _auto_placements(f, args, s, ids, mode, batch)
            if placements is None:
                print(f"  {f.name}: nothing to sign (already signed or identity not found) - skipped")
                skipped.append(f)
                continue
        jobs.append(Job(req, placements))
        if not batch:
            print(f"Output: {out}")
    if not jobs:
        sys.exit("Nothing to sign.")
    if batch and not args.yes and input(f"Sign {len(jobs)} file(s) now? [y/N] ").strip().lower()[:1] != "y":
        raise Cancelled("Cancelled - nothing was signed.")
    results = sign_batch(jobs, s, _make_prompt(s.secret_word), allow_final_try=args.allow_final_try,
                         use_stored_pin=not args.ask, stop_on_error=not batch)
    if batch:
        print("\nSummary:")
        for r in results:
            print(f"  {'OK    ' if r.output else 'FAILED'} {Path(r.job.req.input_pdf).name}"
                  f" -> {Path(r.output).name if r.output else r.error}")
        for f in skipped:
            print(f"  skip   {f.name}")
        if any(r.error for r in results):
            sys.exit(1)


def cmd_verify(args, s):
    t = Token.from_settings(s) if not args.no_token else None
    chain = fetch_chain(t.certificate) if t else []
    print("\n".join(verify_pdf(args.pdf, chain)))


def main(argv=None):
    p = argparse.ArgumentParser(prog="pdfsign", description="Sign PDFs with the hardware token.")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("gui", help="graphical interface (default)").add_argument("pdf", nargs="*")
    sub.add_parser("info", help="token / certificate / retry-counter status (never uses the secret)")
    a = sub.add_parser("fields", help="list signature fields of a PDF")
    a.add_argument("pdf")
    a = sub.add_parser("locate", help="show where your [identities] would place signatures")
    a.add_argument("pdf")
    a = sub.add_parser("sign", help="sign PDFs (auto-located from [identities] by default)")
    a.add_argument("pdf", nargs="+",
                   help="PDF file(s), folder(s) or glob pattern(s), e.g. 'reports/*Mission*.pdf'")
    a.add_argument("--pattern", default="*.pdf", help="file filter inside a folder (default *.pdf)")
    a.add_argument("-o", "--output", help="output file (single input only)")
    a.add_argument("--outdir", help="write signed files to this folder (default: next to each input)")
    a.add_argument("-y", "--yes", action="store_true", help="batch: do not ask for confirmation")
    a.add_argument("--field", help="existing empty field to fill, or name of the new field")
    a.add_argument("--page", type=int, default=1, help="1-based page for a new visible field")
    a.add_argument("--box", help="x1,y1,x2,y2 in PDF points (origin bottom-left)")
    a.add_argument("--invisible", action="store_true")
    a.add_argument("--auto", action="store_true",
                   help="locate the place from [identities] (default when no placement is given)")
    g = a.add_mutually_exclusive_group()
    g.add_argument("--first", action="store_true", help="auto: sign the first unsigned location")
    g.add_argument("--all", action="store_true", help="auto: sign every unsigned location")
    a.add_argument("--level", choices=["B-T", "B-LT", "B-LTA", "b-t", "b-lt", "b-lta"])
    a.add_argument("--reason")
    a.add_argument("--location")
    a.add_argument("--ask", "--ask-password", "--ask-pin", dest="ask", action="store_true",
                   help="ignore credentials.ini, prompt for the password/PIN")
    a.add_argument("--secret-type", choices=["password", "pin"],
                   help="override config.ini: unlock with a password (default) or a numeric PIN")
    a.add_argument("--allow-final-try", action="store_true",
                   help="permit a typed secret when only ONE try is left (dangerous)")
    a = sub.add_parser("verify", help="validate signatures in a PDF")
    a.add_argument("pdf")
    a.add_argument("--no-token", action="store_true", help="don't read the CA chain via the token")
    args = p.parse_args(argv)

    if args.cmd in (None, "gui"):
        from .gui import run_gui
        return run_gui(getattr(args, "pdf", None) or None)
    try:
        s = load_settings()
        {"info": cmd_info, "fields": cmd_fields, "locate": cmd_locate, "sign": cmd_sign,
         "verify": cmd_verify}[args.cmd](args, s)
    except (Cancelled, ConfigError, TokenError, ValueError) as e:
        sys.exit(f"Error: {e}")


if __name__ == "__main__":
    main()
