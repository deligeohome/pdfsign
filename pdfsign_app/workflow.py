"""The sign workflow shared by GUI and CLI: token -> safety checks -> one login -> sign."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable

from .config import ConfigError, Settings, read_stored_secret
from .signing import Placement, SignRequest, TokenSigner, fetch_chain, sign_pdf
from .token import PinSafetyError, PinState, Token, TokenError


class Cancelled(Exception):
    pass


# get_pin(state, reason_stored_secret_not_used) -> PIN/password string, or None to cancel
PinProvider = Callable[[PinState, "str | None"], "str | None"]


@dataclass
class Job:
    """One file to sign: the request plus where (placements) - None = req's own field/box."""
    req: SignRequest
    placements: list[Placement] | None = None


@dataclass
class JobResult:
    job: Job
    output: str | None = None
    error: str | None = None


def sign_with_token(req: SignRequest, settings: Settings, get_pin: PinProvider,
                    log: Callable[[str], None] = print,
                    allow_final_try: bool = False, use_stored_pin: bool = True,
                    placements: list[Placement] | None = None) -> str:
    """Sign req.input_pdf -> req.output_pdf. With `placements`, one signature per placement
    is applied in order (one login, chained incremental updates); otherwise req's own
    field/page/box is used."""
    res = sign_batch([Job(req, placements)], settings, get_pin, log, allow_final_try,
                     use_stored_pin, stop_on_error=True)[0]
    return res.output


def sign_batch(jobs: list[Job], settings: Settings, get_pin: PinProvider,
               log: Callable[[str], None] = print, allow_final_try: bool = False,
               use_stored_pin: bool = True, stop_on_error: bool = False) -> list[JobResult]:
    """Sign several files with ONE token login. A failure in one file (e.g. TSA down) is
    recorded and the next file is tried, unless stop_on_error. Login failures always stop."""
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
        results = []
        for n, job in enumerate(jobs, 1):
            if len(jobs) > 1:
                log(f"=== file {n}/{len(jobs)}: {Path(job.req.input_pdf).name}")
            try:
                if job.placements:
                    out = _sign_chain(job.req, job.placements, signer, settings, chain, log)
                else:
                    out = sign_pdf(job.req, signer, settings, chain, log=log)
                results.append(JobResult(job, output=out))
            except Exception as e:                       # noqa: BLE001 - reported per file
                if stop_on_error or isinstance(e, TokenError):   # token problems stop the batch
                    raise
                log(f"FAILED {Path(job.req.input_pdf).name}: {e}")
                results.append(JobResult(job, error=str(e)))
        return results


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
