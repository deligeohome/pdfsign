"""The sign workflow shared by GUI and CLI: token -> safety checks -> one login -> sign."""

from __future__ import annotations

import os
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Callable

from .config import ConfigError, Settings, read_stored_secret
from .signing import Placement, SignRequest, TokenSigner, fetch_chain, sign_pdf
from .token import PinSafetyError, PinState, Token


class Cancelled(Exception):
    pass


# get_pin(state, reason_stored_secret_not_used) -> PIN/password string, or None to cancel
PinProvider = Callable[[PinState, "str | None"], "str | None"]


def sign_with_token(req: SignRequest, settings: Settings, get_pin: PinProvider,
                    log: Callable[[str], None] = print,
                    allow_final_try: bool = False, use_stored_pin: bool = True,
                    placements: list[Placement] | None = None) -> str:
    """Sign req.input_pdf -> req.output_pdf. With `placements`, one signature per placement
    is applied in order (one login, chained incremental updates); otherwise req's own
    field/page/box is used."""
    with Token.from_settings(settings) as tok:
        log(f"Token: {tok.signer_name}  [{tok.slot_label}]")
        chain = fetch_chain(tok.certificate, log)
        state = tok.pin_state()
        log(state.describe())

        pin, stored, note = None, False, None
        if use_stored_pin:
            try:
                pin = read_stored_secret(settings.secret_type)
                if pin is not None:
                    tok.check_login_allowed(stored_pin=True)
                    stored = True
                    log(f"Using {settings.secret_word} from credentials.ini")
                else:
                    note = f"No {settings.secret_word} stored in credentials.ini."
            except (ConfigError, PinSafetyError) as e:
                pin, note = None, str(e)
                log(f"Stored {settings.secret_word} not used: {e}")
        if pin is None:
            pin = get_pin(state, note)
            if not pin:
                raise Cancelled(f"Signing cancelled - no {settings.secret_word} was sent to the token.")

        tok.login(pin, stored_pin=stored, allow_final_try=allow_final_try,
                  secret_type=settings.secret_type)
        del pin
        log("Token unlocked.")
        signer = TokenSigner(tok, chain)
        if not placements:
            return sign_pdf(req, signer, settings, chain, log=log)
        return _sign_chain(req, placements, signer, settings, chain, log)


def _sign_chain(req: SignRequest, placements: list[Placement], signer, settings, chain, log) -> str:
    out_dir = Path(req.output_pdf).resolve().parent
    out_dir.mkdir(parents=True, exist_ok=True)
    temps, src = [], req.input_pdf
    try:
        for i, p in enumerate(placements, 1):
            last = i == len(placements)
            if last:
                dst = req.output_pdf
            else:
                fd, dst = tempfile.mkstemp(prefix=".pdfsign-step-", suffix=".pdf", dir=out_dir)
                os.close(fd)
                temps.append(dst)
            log(f"--- signature {i}/{len(placements)} (page {p.page + 1})")
            sign_pdf(replace(req, input_pdf=src, output_pdf=dst, field_name=p.field_name,
                             page=p.page, box=p.box, frame=p.frame, fit=p.fit), signer, settings, chain, log=log)
            src = dst
    finally:
        for t in temps:
            if os.path.exists(t):
                os.unlink(t)
    return req.output_pdf
