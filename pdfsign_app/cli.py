"""Command-line interface.  Run without arguments to start the GUI."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from .autolocate import LocateOptions, find_locations, select
from .config import FAILURE_MARKER, ConfigError, load_settings, read_identities
from .signing import SignRequest, fetch_chain, list_signature_fields, verify_pdf
from .token import PinState, Token, TokenError
from .workflow import Cancelled, sign_with_token


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


def _auto_placements(args, s):
    ids = read_identities()
    if ids.empty:
        sys.exit("No [identities] in credentials.ini: give --field, --page/--box or --invisible.")
    locs = find_locations(args.pdf, ids, LocateOptions.from_settings(s))
    print("Identity locations:" if locs else "Identities not found in the document.")
    _print_locations(locs)
    unsigned = [l for l in locs if l.unsigned]
    if not unsigned:
        sys.exit("No unsigned location for your identities (all signed or not found). "
                 "Use --field, --page/--box, --invisible or the GUI.")
    mode = "all" if args.all else "first" if (args.first or len(unsigned) == 1) else None
    if mode is None:
        ans = input(f"{len(unsigned)} unsigned locations. Sign [f]irst one (#{unsigned[0].order}), "
                    f"[a]ll {len(unsigned)}, or [c]ancel? ").strip().lower()
        mode = {"f": "first", "a": "all"}.get(ans[:1])
        if mode is None:
            raise Cancelled("Cancelled - nothing was signed.")
    chosen = select(locs, mode)
    print("Signing at: " + ", ".join(f"#{l.order} (page {l.page + 1})" for l in chosen))
    return [l.placement() for l in chosen]


def cmd_sign(args, s):
    auto = args.auto or not (args.field or args.box or args.invisible)
    box = tuple(float(v) for v in args.box.split(",")) if args.box else None
    if box and len(box) != 4:
        sys.exit("--box needs x1,y1,x2,y2 (PDF points, origin bottom-left)")
    out = args.output or str(Path(args.pdf).with_name(Path(args.pdf).stem + "_signed.pdf"))
    req = SignRequest(args.pdf, out, field_name=args.field, page=args.page - 1,
                      box=None if args.invisible else box,
                      reason=args.reason if args.reason is not None else s.reason,
                      location=args.location if args.location is not None else s.location,
                      contact=s.contact, level=(args.level or s.level).upper())
    if args.secret_type:
        s.secret_type = args.secret_type
    placements = _auto_placements(args, s) if auto else None
    sign_with_token(req, s, _make_prompt(s.secret_word), allow_final_try=args.allow_final_try,
                    use_stored_pin=not args.ask, placements=placements)


def cmd_verify(args, s):
    t = Token.from_settings(s) if not args.no_token else None
    chain = fetch_chain(t.certificate) if t else []
    print("\n".join(verify_pdf(args.pdf, chain)))


def main(argv=None):
    p = argparse.ArgumentParser(prog="pdfsign", description="Sign PDFs with the hardware token.")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("gui", help="graphical interface (default)").add_argument("pdf", nargs="?")
    sub.add_parser("info", help="token / certificate / retry-counter status (never uses the secret)")
    a = sub.add_parser("fields", help="list signature fields of a PDF")
    a.add_argument("pdf")
    a = sub.add_parser("locate", help="show where your [identities] would place signatures")
    a.add_argument("pdf")
    a = sub.add_parser("sign", help="sign a PDF (auto-located from [identities] by default)")
    a.add_argument("pdf")
    a.add_argument("-o", "--output")
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
        return run_gui(getattr(args, "pdf", None))
    try:
        s = load_settings()
        {"info": cmd_info, "fields": cmd_fields, "locate": cmd_locate, "sign": cmd_sign,
         "verify": cmd_verify}[args.cmd](args, s)
    except (Cancelled, ConfigError, TokenError, ValueError) as e:
        sys.exit(f"Error: {e}")


if __name__ == "__main__":
    main()
