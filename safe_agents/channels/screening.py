"""channels.screening — the typed injection-screen seam (sa#43).

See channels/SCREENING.md for the normative contract; this module is the
typed encoding. The screen is the one model-judged gate in the airlock
(channels/ADAPTERS.md gate 7): a verdict may refuse or pass, never bless — a
pass is deliberately contentless, so no downstream code can mistake a
screen's silence for an endorsement of anything in the payload.
"""

from typing import Final

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from safe_agents.channels.schemas.event_trigger import require_tz_aware
from safe_agents.channels.trust_map import IDENTITY_DIGEST_RE, MACHINE_CODE_RE, digest_identity

# The two base-reserved reason codes (SCREENING.md §ScreenVerdict). The seam's
# fail-closed backstop: an escaped screen error must refuse, never pass
# silently. And the canonical suspicion verdict a conformant screen returns.
SCREEN_ERROR: Final = "screen_error"
INJECTION_SUSPECTED: Final = "injection_suspected"


class ScreenVerdict(BaseModel):
    """The screen's judgment on one envelope: refuse or pass, never bless.

    `passed=True` is deliberately contentless — `reason` must be None, so a
    pass carries no model-derived text for downstream code to interpret as
    an endorsement. `passed=False` requires a `reason` machine code, drawn
    from the same closed vocabulary as `DropRecord.detail` — never free text
    derived from the screened content.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    passed: bool
    reason: str | None = None

    @field_validator("reason")
    @classmethod
    def reason_is_machine_code(cls, v: str | None) -> str | None:
        if v is not None and not MACHINE_CODE_RE.match(v):
            raise ValueError(f"reason must be a machine code matching {MACHINE_CODE_RE.pattern!r}: {v!r}")
        return v

    @model_validator(mode="after")
    def _pass_is_contentless(self) -> "ScreenVerdict":
        if self.passed and self.reason is not None:
            raise ValueError("a passing ScreenVerdict must not carry a reason")
        if not self.passed and self.reason is None:
            raise ValueError("a refusing ScreenVerdict requires a reason machine code")
        return self

    def __bool__(self) -> bool:
        """Truthiness mirrors `passed`, so a verdict is drop-in where a bool screen was expected."""
        return self.passed

    @classmethod
    def passing(cls) -> "ScreenVerdict":
        return cls(passed=True)

    @classmethod
    def refusing(cls, reason: str) -> "ScreenVerdict":
        return cls(passed=False, reason=reason)


class ScreenRecord(BaseModel):
    """A PII-safe record of one screen invocation — same discipline as `DropRecord`.

    Carries a digest of the channel identity, never the raw value. Written
    for both pass and refuse when the caller opts into a verdict sink
    (`dispatch.dispatch`'s `verdicts` param); the sink ships OFF by default.

    `chain_verified`/`signer_key_id` are evidence-of-check (sa#161 Phase A1,
    the `sig:pass` provenance-hop precedent in `channels/SIGNING.md`): they
    let an off-path watchdog attribute this screen verdict at the
    authentication strength the airlock actually verified. `signer_key_id`
    may only be set alongside `chain_verified=True` — same discipline as
    `DropRecord`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    channel_type: str
    identity_digest: str
    event_id: str
    passed: bool
    reason: str | None
    ts: str
    chain_verified: bool = False
    signer_key_id: str | None = None

    @field_validator("identity_digest")
    @classmethod
    def digest_format(cls, v: str) -> str:
        if not IDENTITY_DIGEST_RE.match(v):
            raise ValueError(f"identity_digest must match 'sha256:<64-hex>': {v!r}")
        return v

    @field_validator("reason")
    @classmethod
    def reason_is_machine_code(cls, v: str | None) -> str | None:
        if v is not None and not MACHINE_CODE_RE.match(v):
            raise ValueError(f"reason must be a machine code matching {MACHINE_CODE_RE.pattern!r}: {v!r}")
        return v

    @field_validator("ts")
    @classmethod
    def ts_is_tz_aware(cls, v: str) -> str:
        return require_tz_aware(v, "ScreenRecord.ts")

    @model_validator(mode="after")
    def _signer_requires_verified_chain(self) -> "ScreenRecord":
        if self.signer_key_id is not None and not self.chain_verified:
            raise ValueError("signer_key_id may only be set when chain_verified is True")
        return self


def make_screen_record(
    channel_type: str,
    channel_identity: str,
    event_id: str,
    passed: bool,
    reason: str | None,
    ts: str,
    *,
    chain_verified: bool = False,
    signer_key_id: str | None = None,
) -> ScreenRecord:
    """Build a `ScreenRecord`, digesting `channel_identity` so no caller stores it raw."""
    return ScreenRecord(
        channel_type=channel_type,
        identity_digest=digest_identity(channel_identity),
        event_id=event_id,
        passed=passed,
        reason=reason,
        ts=ts,
        chain_verified=chain_verified,
        signer_key_id=signer_key_id,
    )
