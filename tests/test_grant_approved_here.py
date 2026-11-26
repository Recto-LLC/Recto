"""Hard rule 14.9: a grant redeemed at this bootloader was approved here, by an owner phone's identity key.

The operator's key is derived from the recovery phrase. Whoever holds the phrase signs any grant, so the two routes that
take a grant as their only authority - ``/v0.4/secrets/read`` and ``/v0.4/connections/act`` - also ask that its card was
approved here: the identity key, its biometric, over this very grant.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import replace
from typing import Any

import pytest

pytest.importorskip("cryptography")

from recto.bootloader.server import BootloaderHandler  # noqa: E402
from recto.bootloader.state import PendingRequest, StateStore  # noqa: E402
from recto.capability.jwt import _claims_to_dict, build_signing_input, signing_input_digest  # noqa: E402
from tests import test_bootloader_connections_act as act  # noqa: E402
from tests.test_bootloader_capability_gate import _mint_jws, _starter_claims, template_manifest  # noqa: E402, F401
from tests.test_bootloader_owner_slots import AGENT_ID, AGENT_TOKEN, CONSUMER, _member_challenge, _subject, serving  # noqa: E402
from tests.test_bootloader_slots import Phone, _http  # noqa: E402

REAL_GRANT_APPROVAL = True
AGENT = {"X-Recto-Agent-Id": AGENT_ID, "X-Recto-Agent-Token": AGENT_TOKEN}
SECRET = "value-of-the-secret-5b21"
PRIV, PUB = act._keypair()


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _serve(state_dir: Any, manifest: Any, vault: Any):
    return serving(state_dir, capability_operator_pubkey=PUB, capability_manifest=manifest,
                   capability_vault_secrets={("app", "KEY"): SECRET}, connections_path=str(state_dir / "connections.json"),
                   connections_agent_services={AGENT_ID: act.SERVICE}, capability_operator_token="op",
                   connections_secret_source_factory=vault.factory)


@pytest.fixture
def ctx(tmp_path, template_manifest):  # noqa: F811
    vault = act._MemoryVault()
    with _serve(tmp_path, template_manifest, vault) as c:
        c = {**c, "dir": tmp_path, "owner": Phone("owner"), "vault": vault, "manifest": template_manifest}
        assert c["owner"].register(c)[0] == 201
        assert _http("POST", f"{c['base_url']}/v0.4/connections", {"service": act.SERVICE, "key": "alpha", "secret": "v"},
                     headers={"X-Recto-Operator-Token": "op"})[0] == 200
        yield c


def _record(verb: str = "disable") -> Any:
    return act._record(verb, bootloader_id=BootloaderHandler.config.bootloader_id)


def _claims(record: Any, **over: Any) -> Any:
    return act._claims(record, aud=[BootloaderHandler.config.bootloader_id], **over)


def _card(ctx, phone: Phone, claims: Any, record: Any = None) -> str:
    status, body = _http("POST", f"{ctx['base_url']}/v0.4/capability/request", {
        "phone_id": phone.ref, "claims": _claims_to_dict(claims),
        **({"connections_act": record.to_dict()} if record is not None else {})}, headers=AGENT)
    assert status in (200, 201, 202), body
    return body["request_id"]


def _tap(ctx, phone: Phone, request_id: str, *, identity: Any = None, decision: str = "approved") -> tuple[int, dict[str, Any]]:
    card = ctx["state"].peek_pending(request_id)
    raw = card.payload_hash_b64u
    digest = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    return _http("POST", f"{ctx['base_url']}/v0.4/respond/{request_id}", {
        "decision": decision, "signature_b64u": _b64u((identity or phone.identity).sign(digest)),
        "cap_signature_b64u": _signed(card.cap_header_b64, card.cap_payload_b64, digest)})


def _signed(header: str, payload: str, digest: bytes) -> str:
    """The phrase's key over a digest, by the mint helper's own arithmetic."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    r, s = utils.decode_dss_signature(ec.derive_private_key(PRIV, ec.SECP256K1()).sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()))))
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    return _b64u(r.to_bytes(32, "big") + min(s, n - s).to_bytes(32, "big"))


def _granted(ctx, phone: Phone, claims: Any, record: Any = None) -> str:
    rid = _card(ctx, phone, claims, record)
    status, body = _tap(ctx, phone, rid)
    assert status == 200, body
    status, body = _http("GET", f"{ctx['base_url']}/v0.4/capability/result/{rid}", headers=AGENT)
    assert status == 200 and body["status"] == "approved", body
    return body["capability_jws"]


def _act(ctx, record: Any, jws: str) -> tuple[int, dict[str, Any]]:
    return _http("POST", f"{ctx['base_url']}/v0.4/connections/act", {"jws": jws, "record": record.to_dict()})


def _read(ctx, jws: str) -> tuple[int, dict[str, Any]]:
    return _http("POST", f"{ctx['base_url']}/v0.4/secrets/read", {"capability_jws": jws, "service": "app", "secret_name": "KEY"})


def _enabled(ctx) -> bool:
    rows = json.loads((ctx["dir"] / "connections.json").read_text(encoding="utf-8"))["connections"]
    return bool(rows[0]["enabled"])


# --- accepted -------------------------------------------------------------


def test_a_carded_and_approved_act_lands_once(ctx) -> None:
    record = _record()
    jws = _granted(ctx, ctx["owner"], _claims(record), record)
    status, body = _act(ctx, record, jws)
    assert status == 200 and body["connection"]["enabled"] is False, body
    assert _act(ctx, record, jws)[1]["error"] == "grant_replayed"


def test_an_approved_secret_read(ctx) -> None:
    jws = _granted(ctx, ctx["owner"], _starter_claims())
    assert [_read(ctx, jws)[1].get("value") for _ in range(2)] == [SECRET, SECRET], "a reusable grant stays reusable"
    once = _granted(ctx, ctx["owner"], replace(_starter_claims(), jti="once", max_uses=1))
    assert _read(ctx, once)[0] == 200 and _read(ctx, once)[1]["error"] == "capability_revoked"


def test_another_signature_over_the_approved_grant_is_the_same_grant(ctx) -> None:
    record = _record()
    claims = _claims(record)
    first = _granted(ctx, ctx["owner"], claims, record)
    second = act._mint(claims, PRIV)
    assert first.rsplit(".", 1)[0] == second.rsplit(".", 1)[0] and first != second
    assert _act(ctx, record, second)[0] == 200 and _act(ctx, record, first)[1]["error"] == "grant_replayed"


def test_the_approval_outlives_a_restart_and_not_its_exp(ctx, tmp_path, monkeypatch) -> None:
    jws = _granted(ctx, ctx["owner"], _starter_claims())
    digest = signing_input_digest(jws)
    again = StateStore(state_dir=tmp_path)
    assert again.grant_was_approved(digest) and not again.grant_was_approved(digest[:-1] + "A" * 2)
    now = time.time()
    monkeypatch.setattr("recto.bootloader.state.time.time", lambda: now + 86400)
    assert not again.grant_was_approved(digest)
    again.note_approved_grant("other", int(now) + 2 * 86400)
    assert list(json.loads((tmp_path / "approved_grants.json").read_text())["approved_grants"]) == ["other"]


# --- refused --------------------------------------------------------------

REFUSED = (403, "grant_not_approved_here")


def test_a_grant_the_phrase_signed_with_no_card_opens_nothing(ctx) -> None:
    record = _record()
    claims = _claims(record)
    status, body = _act(ctx, record, act._mint(claims, PRIV))
    assert (status, body["error"]) == REFUSED and _enabled(ctx) and not ctx["state"].is_revoked(claims.jti)
    status, body = _read(ctx, _mint_jws(_starter_claims(), PRIV))
    assert (status, body["error"]) == REFUSED and SECRET not in json.dumps(body)


def test_an_approved_grants_jti_on_other_words_opens_nothing_and_spends_nothing(ctx) -> None:
    record = _record("disable")
    claims = _claims(record)
    good = _granted(ctx, ctx["owner"], claims, record)
    other = act._record("delete", bootloader_id=record.bootloader_id, not_after=record.not_after)
    forged = act._mint(replace(act._claims(other, aud=claims.aud), jti=claims.jti, iat=claims.iat, nbf=claims.nbf), PRIV)
    status, body = _act(ctx, other, forged)
    assert (status, body["error"]) == REFUSED
    assert _act(ctx, record, good)[0] == 200, "the approved one is still the person's"


def test_a_card_denied_or_answered_by_another_key_approves_nothing(ctx) -> None:
    record = _record()
    claims = _claims(record)
    rid = _card(ctx, ctx["owner"], claims, record)
    assert _tap(ctx, ctx["owner"], rid, identity=Phone("thief").identity)[0] == 400
    assert _act(ctx, record, act._mint(claims, PRIV))[1]["error"] == REFUSED[1]
    ctx["state"].take_pending(rid)
    assert _act(ctx, record, act._mint(claims, PRIV))[1]["error"] == REFUSED[1]


def test_a_members_phone_approves_nothing_of_the_owners(ctx) -> None:
    """The phrase, and an identity key that is genuine but a member's."""
    member = Phone("member")
    assert member.register(ctx, challenge=_member_challenge(ctx, "m"))[0] == 201
    for claims, record in ((_claims(r := _record()), r), (_starter_claims(), None)):
        digest, header, payload = build_signing_input(claims)
        req = PendingRequest.new_capability_request(
            service="s", secret="capability", phone_id=member.ref, operation_description="x", payload_hash_b64u=_b64u(digest),
            child_pid=0, child_argv0="t", cap_header_b64=header, cap_payload_b64=payload, cap_agent_id=AGENT_ID)
        ctx["state"].note_member_key(member.ref, CONSUMER, _subject("m"), PUB.hex())
        req = replace(req, member_consumer=CONSUMER, member_subject=_subject("m"), member_key_hex=PUB.hex())
        ctx["state"].add_pending(req)
        assert _tap(ctx, member, req.request_id)[0] == 200
        jws = f"{header}.{payload}.{_signed(header, payload, digest)}"
        status, body = _act(ctx, record, jws) if record is not None else _read(ctx, jws)
        assert (status, body["error"]) == REFUSED
    assert not (ctx["dir"] / "approved_grants.json").exists()


def test_a_card_whose_hash_is_not_the_grants_approves_nothing(ctx) -> None:
    claims = _starter_claims()
    digest, header, payload = build_signing_input(claims)
    req = PendingRequest.new_capability_request(
        service="s", secret="capability", phone_id=ctx["owner"].ref, operation_description="x", payload_hash_b64u=_b64u(b"h" * 32),
        child_pid=0, child_argv0="t", cap_header_b64=header, cap_payload_b64=payload, cap_agent_id=AGENT_ID)
    ctx["state"].add_pending(req)
    sig = _signed(header, payload, digest)
    assert _http("POST", f"{ctx['base_url']}/v0.4/respond/{req.request_id}", {
        "decision": "approved", "signature_b64u": _b64u(ctx["owner"].identity.sign(b"h" * 32)), "cap_signature_b64u": sig})[0] == 200
    assert _read(ctx, f"{header}.{payload}.{sig}")[1]["error"] == REFUSED[1]


def test_another_bootloaders_approval_is_not_this_ones(ctx, tmp_path) -> None:
    jws = _granted(ctx, ctx["owner"], _starter_claims())
    other = tmp_path / "other"
    with _serve(other, ctx["manifest"], act._MemoryVault()) as elsewhere:
        assert _read(elsewhere, jws)[1]["error"] == REFUSED[1]


def test_a_store_that_cannot_note_it_hands_out_no_grant(ctx, monkeypatch) -> None:
    def broken(*a: Any) -> None:
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(ctx["state"], "note_approved_grant", broken)
    claims = _starter_claims()
    rid = _card(ctx, ctx["owner"], claims)
    assert _tap(ctx, ctx["owner"], rid)[0] == 500
    body = _http("GET", f"{ctx['base_url']}/v0.4/capability/result/{rid}", headers=AGENT)[1]
    assert "capability_jws" not in body or not body["capability_jws"]


# --- what is kept ---------------------------------------------------------


def test_only_a_digest_and_an_exp_are_kept_and_only_of_a_grant_redeemed_here(ctx) -> None:
    _granted(ctx, ctx["owner"], replace(_starter_claims(), aud=["consumer-app"], jti="elsewhere"))
    path = ctx["dir"] / "approved_grants.json"
    assert not path.exists()
    claims = _starter_claims()
    jws = _granted(ctx, ctx["owner"], claims)
    assert json.loads(path.read_text(encoding="utf-8")) == {"approved_grants": {signing_input_digest(jws): claims.exp}}


def test_every_route_that_takes_a_grant_says_what_else_it_needs() -> None:
    """Each verify_jws in the server: the approval of a card (the identity signature is its gate), the pairing relay
    (its own record, the consumer's one-time code), and the two routes that ask the approval."""
    import recto.bootloader.server as server
    source = open(server.__file__, encoding="utf-8").read()
    handlers = [part.split("(", 1)[0] for part in source.split("\n    def ")[1:] if "_verify_jws(\n" in part]
    assert handlers == ["_handle_respond", "_handle_devices_pair", "_handle_secret_read", "_handle_connections_act"]
    for name in ("_handle_secret_read", "_handle_connections_act"):
        body = source[source.index(f"def {name}("):]
        body = body[:body.index("\n    def ")]
        assert body.index("_verify_jws(\n") < body.index("grant_was_approved(") < min(
            body.index(x) for x in ("consume_single_use_capability(", "add_revocation(") if x in body)
