"""The receipt of an approved grant (hard rule 14.10).

A grant is signed by the key of the recovery phrase, and the signature alone does not say that a person tapped. The
receipt does: this bootloader's own key signs that a paired phone's IDENTITY key approved this grant's card here. It
goes out beside the grant, travels with it, and is checked offline against the bootloader's pinned key.

The receipt names the grant by the digest of what the grant signs, so it fits that grant's words and no other's.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable

from recto.capability.jwt import parse_jws
from recto.capability.types import CapabilityClaims, CapabilityClause, CapabilityScope

# THE DOMAIN TAG: the one action the receipt allows. Nothing else this bootloader's key signs carries it.
GRANT_RECEIPT_ACTION = "recto:grant-receipt-v1"
GRANT_RECEIPT_PURPOSE = "grant approved here"
CLOCK_SKEW_SECONDS = 60
OWNER_SLOTS = ("primary", "recovery")


@dataclass(frozen=True)
class GrantReceiptScope(CapabilityScope):
    """The scope of a receipt, and of nothing a phone signs. ``approved_slot`` is the slot of the phone that approved;
    ``device_class`` what the registry holds of it (hard rule 14.8); ``act_class`` whether this approval carried its
    App Attest assertion: ``asserted``, ``missing``, or ``none`` for a phone that keeps no such key."""

    approved_slot: str | None = None
    device_class: str | None = None
    act_class: str | None = None
    # A member's approval alone: the opaque handle of the member, at the consumer the card was for (hard rule 14.12).
    subject: str | None = None


class ReceiptRefused(ValueError):
    """A named refusal. ``name`` is stable; ``detail`` may change."""

    def __init__(self, name: str, detail: str = "") -> None:
        super().__init__(f"{name}: {detail}" if detail else name)
        self.name = name


def grant_digest_hex(grant_jws: str) -> str:
    """SHA-256, lowercase hex, of the grant's signing input: its first two parts and the dot between, as they travel."""
    return hashlib.sha256(grant_jws.strip().rsplit(".", 1)[0].encode("ascii")).hexdigest()


def receipt_claims(grant_jws: str, grant: CapabilityClaims, *, bootloader_id: str, now: int, approved_slot: str,
                   device_class: str, act_class: str, subject: str | None = None) -> CapabilityClaims:
    digest = grant_digest_hex(grant_jws)
    return CapabilityClaims(
        iss=f"bootloader:{bootloader_id}",
        sub=f"grant:{grant.jti}",
        aud=list(grant.aud),
        iat=now,
        nbf=now - CLOCK_SKEW_SECONDS,
        exp=int(grant.exp),
        jti=f"receipt-{digest}",
        cap=CapabilityClause(
            tier=0,
            registry_version=grant.cap.registry_version,
            scope=GrantReceiptScope(payload_sha256=digest, approved_slot=approved_slot, device_class=device_class,
                                    act_class=act_class, subject=subject),
            allow_actions=[GRANT_RECEIPT_ACTION],
        ),
        purpose=GRANT_RECEIPT_PURPOSE,
    )


def verify_grant_receipt(receipt: Any, grant_jws: str, *, pins: Iterable[bytes], bootloader_id: str | None,
                         audience: str, now: int, standing: bool = False,
                         member: str | None = None) -> dict[str, Any]:
    """The receipt's payload when it is this grant's, or ReceiptRefused. The grant's own checks are the caller's and come
    first. ``pins``: the bootloader's public keys (64 bytes X || Y) held from before, never read beside the receipt.
    ``standing``: a grant already redeemed is looked at again - every check but the window. ``member``: the handle of the
    one member whose own act this door takes, and then an owner's approval does not stand in for it; None (an operator's
    door) takes an owner's alone."""
    if not receipt:
        raise ReceiptRefused("receipt_missing")
    if not isinstance(receipt, str):
        raise ReceiptRefused("receipt_shape", "not a string")
    try:
        header, payload, signature, signing_input = parse_jws(receipt)
    except ValueError as exc:
        raise ReceiptRefused("receipt_shape", str(exc)) from None
    if header.get("alg") != "ES256K" or header.get("typ") != "JWT" or len(signature) != 64:
        raise ReceiptRefused("receipt_shape", "not an ES256K JWT")
    if not any(_signed_by(pin, signing_input, signature) for pin in pins):
        raise ReceiptRefused("receipt_signature", "not signed by a pinned bootloader key")
    cap = payload.get("cap") if isinstance(payload.get("cap"), dict) else {}
    scope = cap.get("scope") if isinstance(cap.get("scope"), dict) else {}
    if cap.get("allow_actions") != [GRANT_RECEIPT_ACTION]:
        raise ReceiptRefused("receipt_action", "this is another thing the bootloader signed")
    if bootloader_id is not None and payload.get("iss") != f"bootloader:{bootloader_id}":
        raise ReceiptRefused("receipt_issuer", "another bootloader's")
    digest = grant_digest_hex(grant_jws)
    if scope.get("payload_sha256") != digest or payload.get("jti") != f"receipt-{digest}":
        raise ReceiptRefused("receipt_other_grant", "it names another grant")
    aud = payload.get("aud")
    if not isinstance(aud, list) or audience not in aud:
        raise ReceiptRefused("receipt_audience", "it names another audience")
    slot = scope.get("approved_slot")
    if not (slot in OWNER_SLOTS if member is None else bool(member) and slot == "member" and scope.get("subject") == member):
        raise ReceiptRefused("receipt_slot", "the phone that approved is not one this door takes")
    if not standing:
        nbf, exp = payload.get("nbf"), payload.get("exp")
        if not all(isinstance(x, int) and not isinstance(x, bool) for x in (nbf, exp)) or not nbf <= now + CLOCK_SKEW_SECONDS \
                or now - CLOCK_SKEW_SECONDS >= exp:
            raise ReceiptRefused("receipt_window", "outside its window")
    return payload


def _signed_by(pin: bytes, signing_input: bytes, signature: bytes) -> bool:
    from recto.ethereum import recover_public_key
    digest = hashlib.sha256(signing_input).digest()
    for rec_id in (0, 1):
        try:
            if recover_public_key(digest, signature + bytes([27 + rec_id])) == bytes(pin):
                return True
        except Exception:    # noqa: BLE001 - a signature that recovers to no key is not the pin's
            continue
    return False
