"""Hard rule 14.10: the receipt beside an approved grant, and the vectors any verifier answers."""

from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("cryptography")

from recto.bootloader.server import BootloaderHandler  # noqa: E402
from recto.bootloader.state import PendingRequest  # noqa: E402
from recto.capability.grant_receipt import (  # noqa: E402
    GRANT_RECEIPT_ACTION,
    ReceiptRefused,
    grant_digest_hex,
    verify_grant_receipt,
)
from recto.capability.jwt import build_signing_input, verify_jws  # noqa: E402
from recto.capability.signing import public_key_hex  # noqa: E402
from tests import test_approval_evidence as acts  # noqa: E402
from tests import test_grant_approved_here as grants  # noqa: E402
from tests.device_evidence_builder import APP_ID, AppleVendor  # noqa: E402
from tests.test_bootloader_owner_slots import AGENT_ID, AGENT_TOKEN, CONSUMER, _member_challenge, _subject, serving  # noqa: E402
from tests.test_bootloader_slots import Phone, _http  # noqa: E402
from tests.test_device_evidence_register import HwPhone  # noqa: E402

DOC = json.loads((Path(__file__).parent / "grant_receipt_vectors.json").read_text(encoding="utf-8"))
KEY = secrets.token_bytes(32)
PIN = bytes.fromhex(public_key_hex(KEY))
AGENT = {"X-Recto-Agent-Id": AGENT_ID, "X-Recto-Agent-Token": AGENT_TOKEN}


@pytest.mark.parametrize("row", DOC["vectors"], ids=lambda r: r["name"])
def test_a_vector(row) -> None:
    def verify() -> Any:
        return verify_grant_receipt(
            DOC["receipts"].get(row["receipt"], row["receipt"]), DOC["grants"][row["grant"]],
            pins=[bytes.fromhex(DOC["keys"][k]["hex128"]) for k in row["pins"]], bootloader_id=row["bootloader_id"],
            audience=row["audience"], now=row["now"], standing=row["standing"], member=row.get("member"))
    if row["expect"] == "ok":
        assert verify()["cap"]["allow_actions"] == [GRANT_RECEIPT_ACTION]
    else:
        with pytest.raises(ReceiptRefused) as e:
            verify()
        assert e.value.name == row["expect"]


def test_the_grants_of_the_vectors_are_good_grants() -> None:
    """What is refused in a vector is refused for its receipt."""
    pub = bytes.fromhex(DOC["keys"]["grant"]["hex128"])
    for name, jws in DOC["grants"].items():
        try:
            verify_jws(jws.strip(), expected_pubkey=pub, now=1800000030)
        except ValueError:
            assert [r["name"] for r in DOC["vectors"] if r["grant"] == name] == ["the grant re-encoded with other white space"]


def test_a_verifier_with_no_pin_never_passes() -> None:
    good = next(r for r in DOC["vectors"] if r["expect"] == "ok")
    with pytest.raises(ReceiptRefused, match="receipt_signature"):
        verify_grant_receipt(DOC["receipts"][good["receipt"]], DOC["grants"][good["grant"]], pins=[], bootloader_id=None,
                             audience=good["audience"], now=good["now"])


@pytest.mark.parametrize("bad", [5, ["x"], {"a": 1}, "a.b", "é.é.é", "....", "e30.e30.e30"])
def test_anything_else_is_a_named_refusal(bad) -> None:
    with pytest.raises(ReceiptRefused) as e:
        verify_grant_receipt(bad, DOC["grants"]["g1"], pins=[PIN], bootloader_id=None, audience="x", now=0)
    assert e.value.name == "receipt_shape"


# --- what the bootloader mints --------------------------------------------


@pytest.fixture
def ctx(tmp_path):
    with serving(tmp_path, capability_operator_pubkey=grants.PUB, devices_pair_signing_key=KEY) as c:
        yield {**c, "dir": tmp_path}


def _owner(ctx, slot: str = "primary") -> Phone:
    p = Phone(slot)
    assert p.register(ctx, slot)[0] == 201
    return p


def _grant(**over: Any) -> Any:
    return replace(grants._starter_claims(), aud=["consumer-app"], jti="g-" + secrets.token_hex(4), **over)


def _answer(ctx, phone: Phone, claims: Any, **kw: Any) -> dict[str, Any]:
    rid = grants._card(ctx, phone, claims)
    status, body = grants._tap(ctx, phone, rid, **kw)
    assert status == 200, body
    return _http("GET", f"{ctx['base_url']}/v0.4/capability/result/{rid}", headers=AGENT)[1]


def _check(answer: dict[str, Any], **kw: Any) -> dict[str, Any]:
    return verify_grant_receipt(answer["grant_receipt"], answer["capability_jws"], pins=[PIN],
                                bootloader_id=BootloaderHandler.config.bootloader_id, audience="consumer-app",
                                now=int(time.time()), **kw)


def test_an_approved_grant_carries_its_receipt(ctx) -> None:
    claims = _grant()
    answer = _answer(ctx, _owner(ctx), claims)
    payload = _check(answer)
    now = int(time.time())
    assert payload["exp"] == claims.exp and payload["nbf"] == payload["iat"] - 60 and abs(payload["iat"] - now) < 10
    assert payload["sub"] == f"grant:{claims.jti}" and payload["jti"] == "receipt-" + grant_digest_hex(answer["capability_jws"])
    assert payload["aud"] == claims.aud and "max_uses" not in payload and payload["purpose"] == "grant approved here"
    assert payload["cap"]["scope"] == {"env": [], "services": [], "repos": [], "payload_sha256": grant_digest_hex(answer["capability_jws"]),
                                       "approved_slot": "primary", "device_class": "unverified", "act_class": "none"}


def test_it_fits_no_other_grant(ctx) -> None:
    owner = _owner(ctx)
    one, two = _answer(ctx, owner, _grant()), _answer(ctx, owner, _grant())
    with pytest.raises(ReceiptRefused, match="receipt_other_grant"):
        _check({**one, "grant_receipt": two["grant_receipt"]})


def test_the_slot_it_names_is_the_approvers(ctx) -> None:
    _, recovery = _owner(ctx), Phone("recovery")
    ctx["state"].register_phone(acts_registration(recovery, "recovery"))
    assert _check(_answer(ctx, recovery, _grant()))["cap"]["scope"]["approved_slot"] == "recovery"
    member = Phone("member")
    assert member.register(ctx, challenge=_member_challenge(ctx, "m"))[0] == 201
    claims = _grant()
    digest, header, payload = build_signing_input(claims)
    req = PendingRequest.new_capability_request(
        service="s", secret="capability", phone_id=member.ref, operation_description="x", payload_hash_b64u=grants._b64u(digest),
        child_pid=0, child_argv0="t", cap_header_b64=header, cap_payload_b64=payload, cap_agent_id=AGENT_ID)
    ctx["state"].note_member_key(member.ref, CONSUMER, _subject("m"), grants.PUB.hex())
    req = replace(req, member_consumer=CONSUMER, member_subject=_subject("m"), member_key_hex=grants.PUB.hex())
    ctx["state"].add_pending(req)
    assert grants._tap(ctx, member, req.request_id)[0] == 200
    answer = _http("GET", f"{ctx['base_url']}/v0.4/capability/result/{req.request_id}", headers=AGENT)[1]
    with pytest.raises(ReceiptRefused, match="receipt_slot"):
        _check(answer)
    scope = _check(answer, member=_subject("m"))["cap"]["scope"]
    assert (scope["approved_slot"], scope["subject"]) == ("member", _subject("m"))
    for other in (_subject("n"), "", None):
        with pytest.raises(ReceiptRefused, match="receipt_slot"):
            _check(answer, member=other)


def acts_registration(p: Phone, slot: str) -> Any:
    from recto.bootloader.state import PhoneRegistration
    return PhoneRegistration.new(device_label=p.label, public_key_b64u=p.pub, supported_algorithms=("ed25519",),
                                 poll_public_key_b64u=p.poll_pub, slot=slot)


def test_a_denial_and_a_wrong_tap_have_none(ctx) -> None:
    owner = _owner(ctx)
    rid = grants._card(ctx, owner, _grant())
    assert grants._tap(ctx, owner, rid, identity=Phone("thief").identity)[0] == 400
    assert "grant_receipt" not in _http("GET", f"{ctx['base_url']}/v0.4/capability/result/{rid}", headers=AGENT)[1]
    card = ctx["state"].peek_pending(rid)
    path = f"/v0.4/respond/{rid}"
    from recto.bootloader.server import POLL_SIG_HEADER, POLL_SIG_PREFIX, POLL_SIG_TS_HEADER
    ts = str(int(time.time()))
    sig = owner.poll.sign(f"{POLL_SIG_PREFIX}|{owner.ref}|{ts}|{path}".encode())
    assert _http("POST", f"{ctx['base_url']}{path}", {"decision": "denied"},
                 headers={POLL_SIG_HEADER: grants._b64u(sig), POLL_SIG_TS_HEADER: ts})[0] == 200 and card is not None
    answer = _http("GET", f"{ctx['base_url']}/v0.4/capability/result/{rid}", headers=AGENT)[1]
    assert answer["status"] == "denied" and "grant_receipt" not in answer


def test_a_card_whose_hash_is_not_the_grants_has_none(ctx) -> None:
    owner = _owner(ctx)
    digest, header, payload = build_signing_input(_grant())
    req = PendingRequest.new_capability_request(
        service="s", secret="capability", phone_id=owner.ref, operation_description="x", payload_hash_b64u=grants._b64u(b"h" * 32),
        child_pid=0, child_argv0="t", cap_header_b64=header, cap_payload_b64=payload, cap_agent_id=AGENT_ID)
    ctx["state"].add_pending(req)
    assert _http("POST", f"{ctx['base_url']}/v0.4/respond/{req.request_id}", {
        "decision": "approved", "signature_b64u": grants._b64u(owner.identity.sign(b"h" * 32)),
        "cap_signature_b64u": grants._signed(header, payload, digest)})[0] == 200
    assert "grant_receipt" not in _http("GET", f"{ctx['base_url']}/v0.4/capability/result/{req.request_id}", headers=AGENT)[1]


def test_a_bootloader_with_no_key_answers_as_before(tmp_path) -> None:
    with serving(tmp_path, capability_operator_pubkey=grants.PUB) as c:
        answer = _answer(c, _owner(c), _grant())
        assert set(answer) == {"status", "capability_jws"}


@pytest.mark.parametrize("sent", [True, False])
def test_it_says_whether_the_approval_was_asserted(tmp_path, sent) -> None:
    apple = AppleVendor()
    with serving(tmp_path, capability_operator_pubkey=grants.PUB, devices_pair_signing_key=KEY,
                 device_policy=acts._policy(apple, "record")) as c:
        phone = acts.IPhone(HwPhone(), apple)
        assert phone.enrol(c)[0] == 201
        for _ in range(2):      # the class of THIS approval, not of one before it
            rid = grants._card(c, phone, _grant())
            card = c["state"].peek_pending(rid)
            raw = card.payload_hash_b64u
            digest = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
            assert _http("POST", f"{c['base_url']}/v0.4/respond/{rid}", {
                "decision": "approved", "signature_b64u": grants._b64u(phone.identity.sign(digest)),
                "cap_signature_b64u": grants._signed(card.cap_header_b64, card.cap_payload_b64, digest),
                **({"device_assertion": phone.for_card(card)} if sent else {})})[0] == 200
            scope = _check(_http("GET", f"{c['base_url']}/v0.4/capability/result/{rid}", headers=AGENT)[1])["cap"]["scope"]
            assert (scope["device_class"], scope["act_class"]) == ("attested", "asserted" if sent else "missing")
            sent = not sent


def test_it_names_no_phone_and_nothing_of_the_evidence(tmp_path) -> None:
    apple = AppleVendor()
    with serving(tmp_path, capability_operator_pubkey=grants.PUB, devices_pair_signing_key=KEY,
                 device_policy=acts._policy(apple, "record")) as c:
        phone = acts.IPhone(HwPhone(), apple)
        assert phone.enrol(c)[0] == 201
        payload = _check(_answer(c, phone, _grant()))
        held = c["state"].get_phone(phone.ref)
        text = json.dumps(payload)
        for word in (phone.ref, phone.pub, held.device_label, held.app_attest_key_id, held.app_attest_public_key_b64u, APP_ID, AGENT_ID):
            assert word and word not in text
        assert set(payload["cap"]["scope"]) == {"env", "services", "repos", "payload_sha256", "approved_slot", "device_class", "act_class"}
