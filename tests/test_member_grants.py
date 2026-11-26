"""Hard rule 14.12: a member approves for itself alone, from its own phone, against its own key."""

from __future__ import annotations

import base64
import json
import secrets
import threading
import time
from dataclasses import replace
from http.server import HTTPServer
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("cryptography")

from recto.bootloader.server import BootloaderHandler  # noqa: E402
from recto.bootloader.state import PhoneRegistration, StateStore, member_grant_key  # noqa: E402
from recto.capability.grant_receipt import ReceiptRefused, verify_grant_receipt  # noqa: E402
from recto.capability.jwt import _dict_to_claims, signing_input_digest, verify_jws  # noqa: E402
from recto.capability.member_grant import MEMBER_ISSUER, member_claims_refusal, member_policies  # noqa: E402
from recto.capability.pair_record import PairRecord, pair_payload  # noqa: E402
from recto.capability.signing import public_key_hex  # noqa: E402
from tests import test_bootloader_devices_pair as pair  # noqa: E402
from tests import test_grant_approved_here as grants  # noqa: E402
from tests.test_bootloader_owner_slots import AGENT_ID, AGENT_TOKEN, BRIDGE_ID, BRIDGE_TOKEN, _subject, serving  # noqa: E402
from tests.test_bootloader_slots import Phone, _http  # noqa: E402

REAL_GRANT_APPROVAL = True
KEY = secrets.token_bytes(32)
PIN = bytes.fromhex(public_key_hex(KEY))
AGENT = {"X-Recto-Agent-Id": AGENT_ID, "X-Recto-Agent-Token": AGENT_TOKEN}
POLICY = {"actions": ["thrupost:rename", "consent:parental"], "audiences": ["consumer-app"]}
A, B = _subject("a"), _subject("b")


@pytest.fixture(scope="module")
def consumers():
    made = []
    for _ in range(2):
        srv = HTTPServer(("127.0.0.1", 0), type("H", (pair._FakeConsumerHandler,), {"received": []}))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        made.append(srv)
    yield [f"http://127.0.0.1:{s.server_address[1]}" for s in made], [s.RequestHandlerClass for s in made]
    for s in made:
        s.shutdown()
        s.server_close()


@pytest.fixture
def ctx(tmp_path, consumers):
    urls, handlers = consumers
    for h in handlers:
        h.received, h.response_status, h.response_body, h.response_is_json = [], 200, {"status": "paired"}, True
    with serving(tmp_path, capability_operator_pubkey=grants.PUB, devices_pair_signing_key=KEY,
                 devices_pair_consumer_webhook_tokens={u: "t" for u in urls}, member_code_consumers={AGENT_ID: list(urls)},
                 member_grants={AGENT_ID: POLICY}) as c:
        owner = Phone("owner")
        assert owner.register(c)[0] == 201
        yield {**c, "dir": tmp_path, "one": urls[0], "two": urls[1], "owner": owner, "handlers": handlers}


def _enrol(ctx, subject: str, consumer: str | None = None, phone: Phone | None = None) -> Phone:
    status, minted = _http("POST", f"{ctx['base_url']}/v0.4/pairing/code",
                           {"member_of": {"consumer": consumer or ctx["one"], "subject": subject}}, headers=AGENT)
    assert status == 200, minted
    status, chal = _http("GET", f"{ctx['base_url']}/v0.4/registration_challenge?code={minted['code']}")
    phone = phone or Phone("member")
    status, body = phone.register(ctx, challenge=chal["challenge_b64u"])
    assert status == 201, body
    return phone


class Member:
    """A phone, its phrase's key, and the services it pairs."""

    def __init__(self, ctx, subject: str, consumer: str | None = None, phone: Phone | None = None, paired: bool = True) -> None:
        self.ctx, self.subject, self.consumer = ctx, subject, consumer or ctx["one"]
        self.phone = _enrol(ctx, subject, self.consumer, phone)
        self.priv, self.pub = pair._keypair()
        if paired:
            assert self.pair()[0] == 200

    def pair(self, *, signer: Any = None, phone_id: str | None = None, priv: int | None = None, pub: str | None = None,
             sign: bool = True, sig: Any = None) -> tuple[int, dict[str, Any]]:
        bid = BootloaderHandler.config.bootloader_id
        record = PairRecord(bootloader_id=bid, subject=self.subject, phone_pubkey=pub or self.pub, code=secrets.token_hex(4).upper(),
                            not_after=int(time.time()) + 600)
        grant = pair._grant({"priv": priv or self.priv, "pub": pub or self.pub}, record, jti=secrets.token_hex(6))
        from tests.test_device_evidence_kept_nowhere import _regrant
        grant = _regrant(pair, grant, priv or self.priv, bid)
        body = {"consumer_base_url": self.consumer, "record": record.to_dict(), "user_jws": grant}
        if sign:
            payload = pair_payload(bid, self.phone.ref, signing_input_digest(grant))
            body.update(phone_id=phone_id or self.phone.ref,
                        identity_signature_b64u=sig if sig is not None else grants._b64u((signer or self.phone).identity.sign(payload)))
        return _http("POST", f"{self.ctx['base_url']}/v0.4/devices/pair", body)

    def held(self) -> str | None:
        p = self.ctx["state"].get_phone(self.phone.ref)
        return member_grant_key(p, self.consumer, self.subject) if p is not None else None

    def claims(self, **over: Any) -> dict[str, Any]:
        t = int(time.time())
        cap = {"tier": 2, "registry_version": "1", "groups": [], "scope": {"env": [], "services": [], "repos": []},
               "allow_actions": ["thrupost:rename"], "deny_actions": [], "limits": {"per_hour": {}, "per_day": {}, "per_session": {}}}
        for k in [k for k in over if k.startswith("cap_")]:
            cap[k[4:]] = over.pop(k)
        for k in [k for k in over if k.startswith("scope_")]:
            cap["scope"][k[6:]] = over.pop(k)
        return {"iss": MEMBER_ISSUER, "sub": self.subject, "aud": ["consumer-app"], "iat": t, "nbf": t, "exp": t + 300, "jti": "m-" + secrets.token_hex(6),
                "purpose": "rename a post", "max_uses": 1, "cap": cap, **over}

    def ask(self, claims: dict[str, Any] | None = None, *, phone: Phone | None = None, member_of: Any = None, headers: Any = None,
            **body: Any) -> tuple[int, dict[str, Any]]:
        return _http("POST", f"{self.ctx['base_url']}/v0.4/capability/request", {
            "phone_id": (phone or self.phone).ref, "claims": claims or self.claims(),
            "member_of": member_of or {"consumer": self.consumer, "subject": self.subject}, **body}, headers=headers or AGENT)

    def tap(self, rid: str, *, priv: int | None = None, identity: Any = None) -> tuple[int, dict[str, Any]]:
        card = self.ctx["state"].peek_pending(rid)
        raw = card.payload_hash_b64u
        digest = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        payload = json.loads(base64.urlsafe_b64decode(card.cap_payload_b64 + "=" * (-len(card.cap_payload_b64) % 4)))
        sig = pair._mint(_dict_to_claims(payload), priv or self.priv).split(".")[2]
        return _http("POST", f"{self.ctx['base_url']}/v0.4/respond/{rid}", {
            "decision": "approved", "signature_b64u": grants._b64u((identity or self.phone.identity).sign(digest)), "cap_signature_b64u": sig})

    def answer(self, rid: str) -> dict[str, Any]:
        return _http("GET", f"{self.ctx['base_url']}/v0.4/capability/result/{rid}", headers=AGENT)[1]

    def approve(self, claims: dict[str, Any] | None = None) -> dict[str, Any]:
        status, body = self.ask(claims)
        assert status == 201, body
        assert self.tap(body["request_id"])[0] == 200
        return self.answer(body["request_id"])


def _refused(got: tuple[int, dict[str, Any]], name: str, member: Member | None = None) -> None:
    assert (got[0], got[1].get("error")) == (403, name), got
    if member is not None:
        assert member.ctx["state"].list_pending_for_phone(member.phone.ref) == [], "nothing was carded"


# --- what works -----------------------------------------------------------


def test_a_member_approves_from_its_own_phone(ctx) -> None:
    m = Member(ctx, A)
    assert m.held() == m.pub
    answer = m.approve()
    assert answer["status"] == "approved"
    verify_jws(answer["capability_jws"], expected_pubkey=bytes.fromhex(m.pub), expected_aud="consumer-app")
    scope = verify_grant_receipt(answer["grant_receipt"], answer["capability_jws"], pins=[PIN], bootloader_id=None,
                                 audience="consumer-app", now=int(time.time()), member=A)["cap"]["scope"]
    assert (scope["approved_slot"], scope["subject"]) == ("member", A)
    assert m.phone.ref not in json.dumps(scope) and m.pub not in json.dumps(scope)


@pytest.mark.parametrize("sub", ["agent:persona@user:{}", "agent:0000@user:{}"])
def test_an_agent_of_the_members_asks_in_its_own_name(ctx, sub) -> None:
    m = Member(ctx, A)
    assert m.approve(m.claims(sub=sub.format(A)))["status"] == "approved"


def test_the_bootloader_says_that_it_can(ctx, tmp_path) -> None:
    assert _http("GET", f"{ctx['base_url']}/v0.4/health")[1]["member_grants"] is True


def test_one_with_no_list_says_nothing_and_asks_no_member(tmp_path, consumers) -> None:
    urls, _ = consumers
    with serving(tmp_path, capability_operator_pubkey=grants.PUB, devices_pair_signing_key=KEY,
                 devices_pair_consumer_webhook_tokens={u: "t" for u in urls}, member_code_consumers={AGENT_ID: list(urls)}) as c:
        c = {**c, "one": urls[0], "dir": tmp_path}
        assert Phone("owner").register(c)[0] == 201
        assert "member_grants" not in _http("GET", f"{c['base_url']}/v0.4/health")[1]
        m = Member(c, A)
        _refused(m.ask(), "member_grants_off", m)


def test_the_owner_is_carded_and_checked_as_before(ctx) -> None:
    claims = replace(grants._starter_claims(), aud=["consumer-app"])
    rid = grants._card(ctx, ctx["owner"], claims)
    assert grants._tap(ctx, ctx["owner"], rid)[0] == 200
    m = Member(ctx, A)
    rid = grants._card(ctx, ctx["owner"], replace(claims, jti="j2"))
    assert m.ctx["state"].peek_pending(rid).member_key_hex is None
    card = ctx["state"].peek_pending(rid)
    digest = base64.urlsafe_b64decode(card.payload_hash_b64u + "==")
    payload = json.loads(base64.urlsafe_b64decode(card.cap_payload_b64 + "=="))
    sig = pair._mint(_dict_to_claims(payload), m.priv).split(".")[2]
    status, _ = _http("POST", f"{ctx['base_url']}/v0.4/respond/{rid}", {
        "decision": "approved", "signature_b64u": grants._b64u(ctx["owner"].identity.sign(digest)), "cap_signature_b64u": sig})
    assert status == 400, "a member's key approves nothing on the owner's phone"


# --- the attacks ----------------------------------------------------------


def test_a_members_key_is_never_the_operators_and_the_operators_never_a_members(ctx) -> None:
    m = Member(ctx, A)
    rid = m.ask()[1]["request_id"]
    assert m.tap(rid, priv=grants.PRIV)[0] == 400, "the operator's phrase on a member's phone"
    assert m.answer(rid)["status"] == "signature_error"


ASKS: dict[str, tuple[str, dict[str, Any]]] = {
    "another member": ("member_subject_mismatch", {"sub": B}),
    "another member's agent": ("member_subject_mismatch", {"sub": f"agent:x@user:{B}"}),
    "both at once": ("member_subject_mismatch", {"sub": f"agent:x@user:{B}@user:{A}"}),
    "a name with the handle inside": ("member_subject_mismatch", {"sub": f"operator@user:{A}"}),
    "the operator's issuer": ("member_issuer", {"iss": "phone:operator:enclave"}),
    "the bootloader": ("member_audience_denied", {"aud": ["@bid"]}),
    "the bootloader beside its own": ("member_audience_denied", {"aud": ["consumer-app", "@bid"]}),
    "the vault": ("member_audience_denied", {"aud": ["recto:vault"]}),
    "a repository": ("member_audience_denied", {"aud": ["repo:owner-x/repo-y"]}),
    "no audience": ("member_audience_denied", {"aud": []}),
    "another service": ("member_audience_denied", {"aud": ["other-app"]}),
    "an unlisted act": ("member_action_denied", {"cap_allow_actions": ["thrupost:delete"]}),
    "a listed act and another": ("member_action_denied", {"cap_allow_actions": ["thrupost:rename", "connections:set"]}),
    "a deployment": ("member_action_denied", {"cap_allow_actions": ["deploy-push"]}),
    "no act": ("member_action_denied", {"cap_allow_actions": []}),
    "a group": ("member_groups_denied", {"cap_groups": ["everything"]}),
    "another owner's agent": ("member_scope_denied", {"scope_create_for_owner": "x"}),
    "another user": ("member_scope_denied", {"scope_target_user_id": "x"}),
    "a parent grant": ("member_parent_denied", {"parent_cap": "x"}),
    "a profile's grant": ("member_parent_denied", {"parent_profile": "x"}),
    "many uses": ("member_max_uses", {"max_uses": 2}),
    "any number of uses": ("member_max_uses", {"max_uses": None}),
    "two days": ("member_window", {"exp": int(time.time()) + 2 * 86400}),
    "a window that closed": ("member_window", {"exp": int(time.time()) - 5}),
}


@pytest.mark.parametrize("name", ASKS)
def test_what_a_member_is_never_asked(ctx, name) -> None:
    """Refused by name when the card is ASKED for, whatever the platform wants."""
    error, over = ASKS[name]
    over = {k: [x.replace("@bid", BootloaderHandler.config.bootloader_id) for x in v] if k == "aud" else v for k, v in over.items()}
    m = Member(ctx, A)
    _refused(m.ask(m.claims(**over)), error, m)


def test_a_connection_act_is_never_a_members(ctx) -> None:
    m = Member(ctx, A)
    _refused(m.ask(connections_act={"verb": "set"}), "member_action_denied", m)


def test_another_members_card_never_rings_this_phone(ctx) -> None:
    a, b = Member(ctx, A), Member(ctx, B)
    _refused(b.ask(phone=a.phone, member_of={"consumer": ctx["one"], "subject": B}), "member_binding_mismatch", a)
    _refused(b.ask(b.claims(), phone=a.phone, member_of={"consumer": ctx["one"], "subject": A}), "member_subject_mismatch", a)


def test_one_member_cannot_answer_anothers_card(ctx) -> None:
    a, b = Member(ctx, A), Member(ctx, B)
    rid = a.ask()[1]["request_id"]
    assert a.tap(rid, identity=b.phone.identity, priv=b.priv)[0] == 400
    assert ctx["state"].peek_pending(rid) is not None, "still a's to answer"
    assert a.tap(rid, priv=b.priv)[0] == 400, "a's phone with b's phrase"
    assert a.answer(rid)["status"] == "signature_error"


def test_a_stolen_phrase_with_no_phone_approves_nothing(ctx) -> None:
    m = Member(ctx, A)
    rid = m.ask()[1]["request_id"]
    assert m.tap(rid, identity=Phone("thief").identity)[0] == 400
    assert ctx["state"].peek_pending(rid) is not None and not (ctx["dir"] / "approved_grants.json").exists()


def test_a_member_unpaired_between_the_ask_and_the_tap(ctx) -> None:
    m = Member(ctx, A)
    rid = m.ask()[1]["request_id"]
    jws = pair._mint(replace(grants._starter_claims(), aud=["consumer-app"], jti="u1"), m.priv)
    assert _http("POST", f"{ctx['base_url']}/v0.4/devices/unpair", {
        "consumer_base_url": ctx["one"], "user_pubkey_hex": "0x04" + m.pub.upper(), "user_jws": jws})[0] == 200
    assert m.held() is None
    _refused(m.tap(rid), "member_binding_changed")
    assert m.answer(rid)["status"] == "signature_error"
    _refused(m.ask(), "member_key_missing", m)


def test_an_unpairing_the_service_refused_drops_nothing(ctx) -> None:
    m = Member(ctx, A)
    ctx["handlers"][0].response_status = 404
    jws = pair._mint(replace(grants._starter_claims(), aud=["consumer-app"], jti="u1"), m.priv)
    _http("POST", f"{ctx['base_url']}/v0.4/devices/unpair", {"consumer_base_url": ctx["one"], "user_pubkey_hex": m.pub, "user_jws": jws})
    assert m.held() == m.pub


def test_one_service_unpaired_leaves_the_other(ctx) -> None:
    m = Member(ctx, A)
    other = Member.__new__(Member)
    other.ctx, other.subject, other.consumer, other.priv, other.pub = ctx, A, ctx["two"], m.priv, m.pub
    other.phone = _enrol(ctx, A, ctx["two"], m.phone)
    assert other.pair()[0] == 200 and m.held() == other.held() == m.pub
    jws = pair._mint(replace(grants._starter_claims(), aud=["consumer-app"], jti="u1"), m.priv)
    _http("POST", f"{ctx['base_url']}/v0.4/devices/unpair", {"consumer_base_url": ctx["one"], "user_pubkey_hex": m.pub, "user_jws": jws})
    assert m.held() is None and other.held() == m.pub


def test_a_phone_revoked_between_the_ask_and_the_tap(ctx) -> None:
    """A barred member: the owner removes the phone."""
    m = Member(ctx, A)
    rid = m.ask()[1]["request_id"]
    card = ctx["state"].peek_pending(rid)
    ctx["state"].revoke_phone(m.phone.ref)
    assert ctx["state"].peek_pending(rid) is None, "its queue went with it"
    ctx["state"].add_pending(card)
    assert m.tap(rid)[0] in (400, 404)
    assert _http("POST", f"{ctx['base_url']}/v0.4/capability/request", {"phone_id": m.phone.ref, "claims": m.claims()}, headers=AGENT)[0] in (400, 404)


def test_a_phone_moved_to_another_account_takes_no_key_with_it(ctx) -> None:
    m = Member(ctx, A)
    rid = m.ask()[1]["request_id"]
    phone = ctx["state"].get_phone(m.phone.ref)
    ctx["state"].register_phone(replace(phone, member_bindings=((ctx["one"], B),)))
    held = ctx["state"].get_phone(m.phone.ref)
    assert held.member_grant_keys == () and member_grant_key(held, ctx["one"], B) is None
    _refused(m.tap(rid), "member_binding_changed")
    moved = Member.__new__(Member)
    moved.ctx, moved.subject, moved.consumer, moved.priv, moved.pub, moved.phone = ctx, B, ctx["one"], m.priv, m.pub, m.phone
    _refused(moved.ask(), "member_key_missing", moved)
    _refused(m.ask(), "member_binding_mismatch", m)


def test_a_phone_that_becomes_the_owners_between_the_ask_and_the_tap(ctx) -> None:
    m = Member(ctx, A)
    rid = m.ask()[1]["request_id"]
    phone = ctx["state"].get_phone(m.phone.ref)
    ctx["state"].register_phone(replace(phone, slot="recovery"))
    _refused(m.tap(rid, priv=grants.PRIV), "member_binding_changed")


def test_a_replay_across_services(ctx) -> None:
    """The same phone, the same phrase, two services: a card and a grant are one service's."""
    m = Member(ctx, A)
    two = Member.__new__(Member)
    two.ctx, two.subject, two.consumer, two.priv, two.pub = ctx, B, ctx["two"], m.priv, m.pub
    two.phone = _enrol(ctx, B, ctx["two"], m.phone)
    _refused(two.ask(), "member_key_missing", two)      # paired at one service, not at two
    assert two.pair()[0] == 200
    answer = m.approve()
    with pytest.raises(ReceiptRefused, match="receipt_slot"):
        verify_grant_receipt(answer["grant_receipt"], answer["capability_jws"], pins=[PIN], bootloader_id=None,
                             audience="consumer-app", now=int(time.time()), member=B)
    _refused(m.ask(m.claims(sub=B)), "member_subject_mismatch", m)
    _refused(m.ask(m.claims(sub=B), member_of={"consumer": ctx["one"], "subject": B}), "member_binding_mismatch", m)
    two_answer = two.approve()
    assert two_answer["status"] == "approved"


def test_two_members_on_one_phone_at_one_service(ctx) -> None:
    m = Member(ctx, A)
    status, minted = _http("POST", f"{ctx['base_url']}/v0.4/pairing/code", {"member_of": {"consumer": ctx["one"], "subject": B}}, headers=AGENT)
    chal = _http("GET", f"{ctx['base_url']}/v0.4/registration_challenge?code={minted['code']}")[1]["challenge_b64u"]
    status, body = m.phone.register(ctx, challenge=chal)
    held = ctx["state"].get_phone(m.phone.ref)
    subjects = [s for c, s in held.member_bindings if c == ctx["one"]]
    assert len(subjects) == 1, (status, body)
    keys = [x for x in held.member_grant_keys if x[0] == ctx["one"]]
    assert [x[1] for x in keys] in ([], subjects), "a key is never another member's"


def test_a_child_is_asked_only_as_itself(ctx) -> None:
    """The bootloader's half: a child's phone can be asked the parent's act only in the child's own name, which the
    consumer's consent row does not hold."""
    child = Member(ctx, B)
    answer = child.approve(child.claims(cap_allow_actions=["consent:parental"]))
    with pytest.raises(ReceiptRefused, match="receipt_slot"):
        verify_grant_receipt(answer["grant_receipt"], answer["capability_jws"], pins=[PIN], bootloader_id=None,
                             audience="consumer-app", now=int(time.time()), member=A)
    _refused(child.ask(child.claims(sub=A, cap_allow_actions=["consent:parental"])), "member_subject_mismatch", child)


def test_nothing_of_a_members_is_redeemed_here(ctx) -> None:
    Member(ctx, A).approve()
    assert not (ctx["dir"] / "approved_grants.json").exists()


# --- the key --------------------------------------------------------------


def test_a_key_swapped_at_pairing_is_not_kept(ctx) -> None:
    m = Member(ctx, A, paired=False)
    _refused(m.ask(), "member_key_missing", m)
    thief, (priv, pub) = Phone("thief"), pair._keypair()
    assert m.pair(sign=False, priv=priv, pub=pub)[0] == 200 and m.held() is None, "no identity signature: no key"
    assert m.pair(signer=thief, phone_id=thief.ref, priv=priv, pub=pub)[0] == 200 and m.held() is None, "another phone's"
    for kw in ({"signer": thief}, {"sig": "AA"}, {"sig": 5}, {"sig": ""}):
        _refused(m.pair(priv=priv, pub=pub, **kw), "pair_identity_invalid")
        assert m.held() is None
    assert m.pair()[0] == 200 and m.held() == m.pub
    assert m.pair(sign=False, priv=priv, pub=pub)[0] == 200 and m.held() == m.pub, "a pairing that is not the phone's moves nothing"


def test_a_signature_over_another_pairing_is_wrong(ctx) -> None:
    m = Member(ctx, A, paired=False)
    other = grants._b64u(m.phone.identity.sign(pair_payload(BootloaderHandler.config.bootloader_id, m.phone.ref, "x")))
    _refused(m.pair(sig=other), "pair_identity_invalid")


def test_a_pairing_the_service_refused_keeps_no_key(ctx) -> None:
    m = Member(ctx, A, paired=False)
    ctx["handlers"][0].response_status = 409
    m.pair()
    assert m.held() is None


def test_a_new_phrase_paired_by_the_phone_replaces_the_key_and_closes_the_card(ctx) -> None:
    m = Member(ctx, A)
    rid = m.ask()[1]["request_id"]
    old = m.priv
    m.priv, m.pub = pair._keypair()
    assert m.pair()[0] == 200 and m.held() == m.pub
    _refused(m.tap(rid, priv=old), "member_binding_changed")
    assert m.approve()["status"] == "approved"


def test_the_owners_phone_is_never_given_a_members_key(ctx) -> None:
    """The owner's own phone scanned a member code: its slot decides, and its grants stay the operator's."""
    _enrol(ctx, A, phone=ctx["owner"])
    m = Member.__new__(Member)
    m.ctx, m.subject, m.consumer, m.phone = ctx, A, ctx["one"], ctx["owner"]
    m.priv, m.pub = pair._keypair()
    assert m.pair()[0] == 200 and m.held() is None
    rid = grants._card(ctx, ctx["owner"], replace(grants._starter_claims(), aud=["consumer-app"]))
    assert grants._tap(ctx, ctx["owner"], rid)[0] == 200


def test_the_key_outlives_a_restart_and_a_re_registration_and_not_its_binding(ctx, tmp_path) -> None:
    m = Member(ctx, A)
    again = StateStore(state_dir=tmp_path).get_phone(m.phone.ref)
    assert member_grant_key(again, ctx["one"], A) == m.pub
    ctx["state"].register_phone(replace(again, member_grant_keys=((ctx["one"], A, "ff" * 64),)))
    assert m.held() == m.pub, "a registration carries no key in"
    ctx["state"].register_phone(replace(again, member_bindings=()))
    assert m.held() is None and ctx["state"].get_phone(m.phone.ref).member_grant_keys == ()
    assert not ctx["state"].note_member_key(m.phone.ref, ctx["one"], A, m.pub), "no binding, no key"
    assert not ctx["state"].note_member_key("pk_gone", ctx["one"], A, m.pub)


def test_a_store_no_member_used_reads_on_an_older_bootloader(ctx, tmp_path) -> None:
    Member(ctx, A, paired=False)
    text = (tmp_path / "phones.json").read_text(encoding="utf-8")
    assert "member_grant_keys" not in text
    Member(ctx, B)
    assert "member_grant_keys" in (tmp_path / "phones.json").read_text(encoding="utf-8")


@pytest.mark.parametrize("bad", [[["c", "s"]], [["c", "s", "zz" * 64]], [["c", "s", "AB" * 64]], [["", "s", "ab" * 64]], ["x"], [[1, "s", "ab" * 64]]])
def test_a_stored_key_that_does_not_read_refuses_the_start(ctx, tmp_path, bad) -> None:
    path: Path = tmp_path / "phones.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["phones"][0]["member_grant_keys"] = bad
    other = tmp_path / "copy"
    other.mkdir()
    (other / "phones.json").write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ValueError):
        StateStore(state_dir=other)


# --- the list -------------------------------------------------------------

GOOD = {"actions": ["thrupost:rename"], "audiences": ["consumer-app"]}


def test_the_list_is_the_operators_over_a_floor() -> None:
    assert member_policies(None) == {} and member_policies({"a": GOOD})["a"].actions == {"thrupost:rename"}
    assert member_policies({"a": {**GOOD, "actions": ["devices:sign_in"]}}), "a member's own sign-in pairs nothing"
    for bad in ({"actions": []}, {"audiences": []}, {"actions": "x"}, {"actions": [""]}, {"actions": [" x"]}, {"actions": [5]}, {"more": 1}):
        with pytest.raises(ValueError):
            member_policies({"a": {**GOOD, **bad}})
    with pytest.raises(ValueError):
        member_policies({"a": {"actions": ["x"]}})
    for action in ("deploy-push", "Deploy-Act", "connections:set", "secret:read", "devices:pair", "devices:pairing_revoke", "devices:unpair_result", "profile_create", "profile:x", "owner-slot:x",
                   "top-plane:x", "recto:grant-receipt-v1", "bootloader:attest", "capability:mint", "vault:read", "user-vault:grant", "x:*"):
        with pytest.raises(ValueError, match="no member approves"):
            member_policies({"a": {**GOOD, "actions": ["thrupost:rename", action]}})
    for aud in ("recto:vault", "recto-phone", "repo:o/r", "bootloader:x", "RB1-abc"):
        with pytest.raises(ValueError, match="no member approves"):
            member_policies({"a": {**GOOD, "audiences": ["consumer-app", aud]}})


def test_a_bad_list_refuses_the_start(tmp_path) -> None:
    with pytest.raises(ValueError, match="no member approves"):
        with serving(tmp_path, member_grants={AGENT_ID: {"actions": ["deploy-push"], "audiences": ["x"]}}):
            pass


def test_the_floor_holds_even_under_a_list_that_slipped_past_it() -> None:
    from recto.capability.member_grant import MemberPolicy
    policy = MemberPolicy(frozenset({"deploy-push", "a:b"}), frozenset({"recto:vault", "rb", "app"}))
    t = int(time.time())
    base = {"iss": MEMBER_ISSUER, "sub": A, "aud": ["app"], "iat": t, "nbf": t, "exp": t + 60, "jti": "j", "purpose": "p", "max_uses": 1,
            "cap": {"tier": 1, "registry_version": "1", "allow_actions": ["a:b"]}}

    def why(**over: Any) -> str | None:
        got = member_claims_refusal(_dict_to_claims({**base, **over}), subject=A, policy=policy, bootloader_id="rb", now=t)
        return got and got[0]
    assert why() is None
    assert why(aud=["recto:vault"]) == why(aud=["rb"]) == why(aud=["RB"]) == "member_audience_denied"
    assert why(cap={**base["cap"], "allow_actions": ["deploy-push"]}) == "member_action_denied"


def test_another_agents_list_is_not_this_ones(tmp_path, consumers) -> None:
    urls, _ = consumers
    with serving(tmp_path, capability_operator_pubkey=grants.PUB, devices_pair_signing_key=KEY,
                 devices_pair_consumer_webhook_tokens={u: "t" for u in urls}, member_code_consumers={AGENT_ID: list(urls)},
                 member_grants={"someone-else": POLICY}) as c:
        c = {**c, "one": urls[0], "dir": tmp_path}
        assert Phone("owner").register(c)[0] == 201
        m = Member(c, A)
        _refused(m.ask(), "member_grants_off", m)


def test_a_card_from_before_this_is_refused_by_name(ctx) -> None:
    """A card already on a member's phone when this starts has no key to be checked against."""
    m = Member(ctx, A)
    rid = m.ask()[1]["request_id"]
    card = ctx["state"].take_pending(rid)
    ctx["state"].add_pending(replace(card, member_consumer=None, member_subject=None, member_key_hex=None))
    _refused(m.tap(rid), "member_binding_changed")


def test_the_record_is_the_phones_and_only_these_fields() -> None:
    p = PhoneRegistration.new(device_label="x", public_key_b64u="A" * 86, supported_algorithms=("ecdsa-p256",))
    assert p.member_grant_keys == ()


# --- the planes -----------------------------------------------------------


@pytest.fixture
def two_services(tmp_path, consumers):
    """Two consumers on one bootloader, an agent each, and the operator of none of their members."""
    urls, handlers = consumers
    for h in handlers:
        h.received, h.response_status, h.response_body, h.response_is_json = [], 200, {"status": "paired"}, True
    with serving(tmp_path, capability_operator_pubkey=grants.PUB, devices_pair_signing_key=KEY,
                 devices_pair_consumer_webhook_tokens={u: "t" for u in urls},
                 member_code_consumers={AGENT_ID: [urls[0]], BRIDGE_ID: [urls[1] + "/"]},
                 member_grants={AGENT_ID: POLICY, BRIDGE_ID: {"actions": ["other:act"], "audiences": ["other-app"]}}) as c:
        c = {**c, "one": urls[0], "two": urls[1], "dir": tmp_path}
        owner = Phone("owner")
        assert owner.register(c)[0] == 201
        yield {**c, "owner": owner}


OTHER = {"X-Recto-Agent-Id": BRIDGE_ID, "X-Recto-Agent-Token": BRIDGE_TOKEN}


def _at_two(ctx, m: Member, subject: str, monkeypatch) -> Member:
    monkeypatch.setitem(globals(), "AGENT", OTHER)
    two = Member.__new__(Member)
    two.ctx, two.subject, two.consumer, two.priv, two.pub = ctx, subject, ctx["two"], m.priv, m.pub
    two.phone = _enrol(ctx, subject, ctx["two"], m.phone)
    assert two.pair()[0] == 200
    monkeypatch.setitem(globals(), "AGENT", {"X-Recto-Agent-Id": AGENT_ID, "X-Recto-Agent-Token": AGENT_TOKEN})
    return two


def test_two_consumers_have_their_own_members_and_no_crossing(two_services, monkeypatch) -> None:
    """One phone, one phrase, a member at each service."""
    m = Member(two_services, A)
    two = _at_two(two_services, m, B, monkeypatch)
    mine, its = m.claims(), two.claims(aud=["other-app"], cap_allow_actions=["other:act"])
    _refused(m.ask(mine, headers=OTHER), "member_consumer_not_allowed", m)
    _refused(two.ask(its), "member_consumer_not_allowed", two)
    _refused(two.ask(mine | {"sub": B}, headers=OTHER), "member_audience_denied", two)
    _refused(m.ask(its | {"sub": A}), "member_audience_denied", m)
    _refused(m.ask(mine, member_of={"consumer": two_services["two"], "subject": A}), "member_binding_mismatch", m)
    status, body = two.ask(its, headers=OTHER)
    assert status == 201, body
    assert two.tap(body["request_id"])[0] == 200
    status, seen = _http("GET", f"{two_services['base_url']}/v0.4/capability/result/{body['request_id']}", headers=AGENT)
    assert status in (403, 404) and "capability_jws" not in seen, "an agent reads its own answers"
    assert m.approve()["status"] == "approved"
    # one service's unpairing is that service's
    jws = pair._mint(replace(grants._starter_claims(), aud=["other-app"], jti="x"), m.priv)
    assert _http("POST", f"{two_services['base_url']}/v0.4/devices/unpair", {
        "consumer_base_url": two_services["two"], "user_pubkey_hex": m.pub, "user_jws": jws})[0] == 200
    assert (m.held(), two.held()) == (m.pub, None)


def test_an_owners_phone_is_never_asked_a_members_card(two_services) -> None:
    m, owner = Member(two_services, A), two_services["owner"]
    for over in ({}, {"member_of": {"consumer": two_services["one"], "subject": A}}):
        status, body = _http("POST", f"{two_services['base_url']}/v0.4/capability/request",
                             {"phone_id": owner.ref, "claims": m.claims(), **over}, headers=AGENT)
        assert (status, body["error"]) == (403, "member_phone_required")
    assert two_services["state"].list_pending_for_phone(owner.ref) == []


def test_a_receipt_is_one_planes(two_services) -> None:
    m, owner = Member(two_services, A), two_services["owner"]
    theirs = m.approve()

    def check(answer: dict[str, Any], member: str | None) -> Any:
        return verify_grant_receipt(answer["grant_receipt"], answer["capability_jws"], pins=[PIN], bootloader_id=None,
                                    audience="consumer-app", now=int(time.time()), member=member)
    assert check(theirs, A)
    claims = m.claims(iss="phone:operator:enclave", sub="owner")
    status, body = _http("POST", f"{two_services['base_url']}/v0.4/capability/request", {"phone_id": owner.ref, "claims": claims}, headers=AGENT)
    assert status == 201, body
    assert m.tap(body["request_id"], priv=grants.PRIV, identity=owner.identity)[0] == 200
    owners = m.answer(body["request_id"])
    assert check(owners, None)
    for answer, member in ((theirs, None), (theirs, B), (theirs, ""), (owners, A), (owners, "")):
        with pytest.raises(ReceiptRefused, match="receipt_slot"):
            check(answer, member)


def test_one_members_unpairing_leaves_anothers_key_at_the_same_service(ctx) -> None:
    a, b = Member(ctx, A), Member(ctx, B)
    jws = pair._mint(replace(grants._starter_claims(), aud=["consumer-app"], jti="u1"), a.priv)
    assert _http("POST", f"{ctx['base_url']}/v0.4/devices/unpair", {"consumer_base_url": ctx["one"], "user_pubkey_hex": a.pub, "user_jws": jws})[0] == 200
    assert (a.held(), b.held()) == (None, b.pub)


def test_the_key_is_read_under_its_binding_and_no_other() -> None:
    p = PhoneRegistration.new(device_label="x", public_key_b64u="A" * 86, supported_algorithms=("ecdsa-p256",))
    one, two = "1" * 128, "2" * 128
    p = replace(p, slot="member", member_bindings=(("https://c", A), ("https://c", B)), member_grant_keys=(("https://c", A, one), ("https://c", B, two)))
    assert (member_grant_key(p, "https://c", A), member_grant_key(p, "https://c", B)) == (one, two)
    assert member_grant_key(replace(p, member_bindings=(("https://c", B),)), "https://c", A) is None


def test_the_bytes_a_pairing_signs() -> None:
    assert pair_payload("rb1-x", "pk_y", "d") == b"recto-pair-v1|rb1-x|pk_y|d"
