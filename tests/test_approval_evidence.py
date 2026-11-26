"""Hard rule 14.8, after admission: what an iPhone whose App Attest key is kept adds to each act it signs.

A real bootloader, P-256 phones and a synthetic App Attest root. A wrong assertion is refused in both modes and the act
stays undone; a missing one is accepted and noted under `record` and refused under `require`; a phone with no kept key
is asked nothing.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import re
import threading
import time
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("cryptography")

from recto.bootloader import device_codes as dc  # noqa: E402
from recto.bootloader import device_evidence as de  # noqa: E402
from recto.bootloader.server import (  # noqa: E402
    MEMBER_REBIND_PREFIX,
    POLL_SIG_HEADER,
    POLL_SIG_PREFIX,
    POLL_SIG_TS_HEADER,
    BootloaderHandler,
)
from recto.bootloader.state import PendingRequest, StateStore  # noqa: E402
from tests.device_evidence_builder import APP_ID, AndroidVendor, AppleVendor, b64u, p256  # noqa: E402
from tests.test_bootloader_owner_slots import CONSUMER, _subject, serving  # noqa: E402
from tests.test_bootloader_slots import Phone, _approve_owner_cards, _http  # noqa: E402
from tests.test_device_evidence_register import HwPhone, _member_challenge  # noqa: E402
from tests.test_top_plane_e2e import _approve, _host, _op_key, _reset_code, _seed_chain, _top_cards, tp  # noqa: E402

REAL_DEVICE_DEFAULT = True


class IPhone:
    """A P-256 phone, its App Attest key and that key's counter."""

    def __init__(self, phone: HwPhone, apple: AppleVendor) -> None:
        self.phone, self.apple, self.attest_key, self.counter = phone, apple, p256(), 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self.phone, name)

    def enrol(self, ctx, slot: str = "primary", **kw: Any) -> tuple[int, dict[str, Any]]:
        return self.phone.register(ctx, slot, vendor=self.apple, key=self.attest_key, **kw)

    def assertion(self, act: str, ident: str, payload: bytes, fresh: str, *, counter: int | None = None, key: Any = None,
                  **kw: Any) -> str:
        self.counter = self.counter + 1 if counter is None else counter
        return self.apple.assertion(key or self.attest_key, de.assertion_client_data_hash(act, ident, payload, fresh),
                                    self.counter, **kw)

    def for_card(self, card: PendingRequest, *, decision: str = "approved", **kw: Any) -> str:
        raw = card.payload_hash_b64u
        return self.assertion("approve" if decision == "approved" else "deny", card.request_id,
                              base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)), str(card.requested_at_unix), **kw)

    def poll_headers(self, path: str) -> tuple[dict[str, str], str]:
        ts = str(int(time.time()))
        sig = self.poll.sign(f"{POLL_SIG_PREFIX}|{self.ref}|{ts}|{path}".encode("ascii"))
        return {POLL_SIG_HEADER: b64u(sig), POLL_SIG_TS_HEADER: ts}, ts

    def answer(self, ctx, card: PendingRequest, assertion: str | None, *, decision: str = "approved",
               ) -> tuple[int, dict[str, Any]]:
        path, headers = f"/v0.4/respond/{card.request_id}", None
        body: dict[str, Any] = {"decision": decision}
        if decision == "approved":
            raw = card.payload_hash_b64u
            body["signature_b64u"] = b64u(self.identity.sign(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))))
        else:
            headers, _ = self.poll_headers(path)
        if assertion is not None:
            body["device_assertion"] = assertion
        return _http("POST", f"{ctx['base_url']}{path}", body, headers=headers)


def iphone(phone: HwPhone, apple: AppleVendor) -> IPhone:
    return IPhone(phone, apple)


def queue(ctx, phone: Any, payload: bytes = b"p" * 32) -> PendingRequest:
    card = PendingRequest.new(kind="single_sign", service="svc", secret="key", phone_id=phone.ref,
                              operation_description="x", payload_hash_b64u=b64u(payload), child_pid=1, child_argv0="t")
    ctx["state"].add_pending(card)
    return card


def _open(ctx, card: PendingRequest) -> bool:
    return ctx["state"].peek_pending(card.request_id) is not None


@pytest.fixture
def apple() -> AppleVendor:
    return AppleVendor()


def _policy(apple: AppleVendor, approval: str, mode: str = "require") -> de.DevicePolicy:
    return de.DevicePolicy(mode=mode, approval_mode=approval, ios_app_ids=frozenset({APP_ID}), apple_root_pem=apple.root_pem)


@pytest.fixture(params=["record", "require"])
def ctx(request, tmp_path, apple):
    with serving(tmp_path, device_policy=_policy(apple, request.param)) as c:
        yield {**c, "dir": tmp_path, "mode": request.param}


@pytest.fixture
def phone(ctx, apple) -> IPhone:
    p = IPhone(HwPhone(), apple)
    status, body = p.enrol(ctx)
    assert status == 201 and body["app_attest_kept"] is True and "app_attest_key_id" not in body
    return p


def _held(ctx, phone) -> Any:
    return ctx["state"].get_phone(phone.ref)


# --- the approval ---------------------------------------------------------


def test_an_asserted_approval_lands_and_counts(ctx, phone) -> None:
    for expected in (1, 2, 3):
        card = queue(ctx, phone)
        assert phone.answer(ctx, card, phone.for_card(card)) == (200, {"resolved": True})
        held = _held(ctx, phone)
        assert (held.app_attest_counter, held.act_class) == (expected, "asserted") and held.act_class_at_unix % 86400 == 0
    again = StateStore(state_dir=ctx["dir"]).get_phone(phone.ref)
    assert again.app_attest_counter == 3, "the counter survives a restart"


def test_a_missing_assertion(ctx, phone) -> None:
    card = queue(ctx, phone)
    status, body = phone.answer(ctx, card, None)
    if ctx["mode"] == "record":
        assert status == 200 and _held(ctx, phone).act_class == "missing"
    else:
        assert (status, body["error"]) == (403, "approval_evidence_required") and _open(ctx, card)
        assert phone.answer(ctx, card, phone.for_card(card))[0] == 200, "the card stayed open for the next tap"


WRONG: dict[str, Any] = {
    "another key": ("assertion_signature", lambda p, ctx, c: p.for_card(c, signer=p256())),
    "another phone's": ("assertion_signature", lambda p, ctx, c: p.for_card(c, key=p256())),
    "another card's": ("assertion_signature", lambda p, ctx, c: p.for_card(queue(ctx, p))),
    "a deny's": ("assertion_signature", lambda p, ctx, c: p.for_card(c, decision="denied")),
    "another payload": ("assertion_signature", lambda p, ctx, c: p.assertion("approve", c.request_id, b"q" * 32, str(c.requested_at_unix))),
    "another issue time": ("assertion_signature", lambda p, ctx, c: p.for_card(dataclasses.replace(c, requested_at_unix=c.requested_at_unix - 1))),
    "another App ID": ("app_mismatch", lambda p, ctx, c: p.for_card(c, app_id="OTHER00001.app.example.phone")),
    "a development build": ("app_mismatch", lambda p, ctx, c: p.for_card(c, category=3)),
    "counter zero": ("counter", lambda p, ctx, c: p.for_card(c, counter=0)),
    "bytes after it": ("malformed", lambda p, ctx, c: p.for_card(c, tail=b"\x00")),
    "bytes after its data": ("malformed", lambda p, ctx, c: p.for_card(c, auth_tail=b"\x00")),
    "not an assertion": ("malformed", lambda p, ctx, c: "AAAA"),
    "not a string": ("malformed", lambda p, ctx, c: {"a": 1}),
    "empty": ("malformed", lambda p, ctx, c: ""),
    "its attestation": ("malformed", lambda p, ctx, c: "A" * 4000),
}


@pytest.mark.parametrize("name", WRONG)
def test_a_wrong_assertion_is_refused_in_both_modes_and_the_card_stays(ctx, phone, name) -> None:
    reason, make = WRONG[name]
    card = queue(ctx, phone)
    status, body = phone.answer(ctx, card, make(phone, ctx, card))
    assert (status, body.get("error"), body.get("reason")) == (403, "approval_evidence_invalid", reason), body
    assert _open(ctx, card) and _held(ctx, phone).app_attest_counter == 0
    phone.counter = 10
    assert phone.answer(ctx, card, phone.for_card(card))[0] == 200


def test_a_replayed_assertion_and_one_behind_the_count_are_refused(ctx, phone) -> None:
    card, next_card = queue(ctx, phone), queue(ctx, phone)
    phone.counter = 4
    early = phone.for_card(next_card, counter=4)
    good = phone.for_card(card, counter=5)
    assert phone.answer(ctx, card, good)[0] == 200
    status, body = phone.answer(ctx, next_card, early)
    assert (status, body["reason"]) == (403, "counter") and _open(ctx, next_card)
    # A lost answer: the same card asked again gets a new assertion, with the next count, and never sticks.
    assert phone.answer(ctx, next_card, phone.for_card(next_card, counter=6))[0] == 200


def test_the_same_assertion_racing_opens_one_card_act(ctx, phone, apple) -> None:
    card = queue(ctx, phone)
    assertion = phone.for_card(card)
    got: list[int] = []
    threads = [threading.Thread(target=lambda: got.append(phone.answer(ctx, card, assertion)[0])) for _ in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert got.count(200) == 1, got


def test_the_counter_moves_once_per_value_in_the_store(tmp_path) -> None:
    store = StateStore(state_dir=tmp_path)
    from recto.bootloader.state import PhoneRegistration
    reg = store.register_phone(PhoneRegistration.new(
        device_label="x", public_key_b64u="A" * 86, supported_algorithms=("ecdsa-p256",),
        device=de.DeviceFacts("attested", "ios", 0, app_attest=de.AppAttestKey("kid", "pub"))))

    def note(counter: int | None, key: str = "kid") -> bool:
        return store.note_act(reg.phone_id, key_id=key, counter=counter, act_class="asserted", at_unix=0)
    won: list[bool] = []
    threads = [threading.Thread(target=lambda: won.append(note(7))) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert won.count(True) == 1
    assert not note(7) and not note(6) and not note(8, key="other") and note(8)
    assert not store.note_act("pk_gone", key_id="kid", counter=9, act_class="asserted", at_unix=0)
    # A stale copy written back (a registration that read before its lock) does not turn the count back.
    stale = dataclasses.replace(reg, app_attest_counter=0, act_class=None)
    assert store.register_phone(stale).app_attest_counter == 8
    other = dataclasses.replace(reg, app_attest_key_id="new", app_attest_counter=0)
    assert store.register_phone(other).app_attest_counter == 0, "another key starts its own count"


def test_the_postgres_rule_is_the_same_one() -> None:
    source = (Path(__file__).resolve().parents[1] / "recto" / "bootloader" / "state_postgres.py").read_text(encoding="utf-8")
    body = source[source.index("def note_act"):source.index("def replace_phone")]
    assert "doc->>'app_attest_key_id' = %s" in body
    assert "COALESCE((doc->>'app_attest_counter')::bigint, 0) < %s" in body and body.count("conn.execute") == 1
    # A registration reads, merges and writes a phone under this lock; a count noted between would be lost.
    server = (Path(__file__).resolve().parents[1] / "recto" / "bootloader" / "server.py").read_text(encoding="utf-8")
    under = re.findall(r"with cfg[.]state[.]registry_lock[(][)]:\s+noted = cfg[.]state[.]note_act[(]", server)
    assert len(under) == server.count(".note_act(") == 1


def test_a_phone_with_no_kept_key_is_asked_nothing(tmp_path, apple) -> None:
    android = AndroidVendor()
    policy = dataclasses.replace(_policy(apple, "require", "record"), android_roots=android.roots)
    with serving(tmp_path, device_policy=policy) as c:
        before = HwPhone("enrolled before")
        assert before.register(c)[0] == 201
        assert _held(c, before).app_attest_key_id is None
        card = queue(c, before)
        assert IPhone(before, apple).answer(c, card, None)[0] == 200
        card = queue(c, before)
        assert IPhone(before, apple).answer(c, card, "AAAA")[0] == 200, "an assertion nobody asked for is not read"
        assert _held(c, before).act_class is None
        droid = HwPhone("android")
        assert droid.register(c, challenge=_member_challenge(c, "m"), vendor=android)[0] == 201
        card = queue(c, droid)
        assert IPhone(droid, apple).answer(c, card, None)[0] == 200


def test_with_no_app_id_named_any_more_the_kept_key_still_answers(ctx, phone, apple) -> None:
    BootloaderHandler.config.device_policy = dataclasses.replace(_policy(apple, ctx["mode"]), ios_app_ids=frozenset())
    card = queue(ctx, phone)
    assert phone.answer(ctx, card, phone.for_card(card))[0] == 200


def test_a_store_that_fails_leaves_the_card(ctx, phone, monkeypatch) -> None:
    card = queue(ctx, phone)
    real = ctx["state"].note_act

    def broken(*a: Any, **kw: Any) -> bool:
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(ctx["state"], "note_act", broken)
    assert phone.answer(ctx, card, phone.for_card(card))[0] == 500
    monkeypatch.setattr(ctx["state"], "note_act", real)
    assert _open(ctx, card)
    assert phone.answer(ctx, card, phone.for_card(card))[0] == 200


# --- every other signed act -----------------------------------------------


def _three(ctx, phone: IPhone, send: Any, make: Any, done: Any, removes: bool = False) -> None:
    """wrong -> refused; missing -> by mode, and always accepted where the act only removes authority; good -> done."""
    status, body = send(make(signer=p256()))
    assert (status, body.get("error")) == (403, "approval_evidence_invalid") and not done(), body
    if ctx["mode"] == "require":
        status, body = send(None)
        if removes:
            assert status == 200 and done(), body
            return
        assert (status, body.get("error")) == (403, "approval_evidence_required") and not done(), body
    status, body = send(make())
    assert status in (200, 201), body
    assert done()


def test_a_deny(ctx, phone) -> None:
    card = queue(ctx, phone)
    _three(ctx, phone, lambda a: phone.answer(ctx, card, a, decision="denied"),
           lambda **kw: phone.for_card(card, decision="denied", **kw), lambda: not _open(ctx, card), removes=True)
    if ctx["mode"] == "require":
        assert _held(ctx, phone).act_class == "missing"


def test_the_push_token(ctx, phone) -> None:
    path = "/v0.4/manage/push_token"

    def send(a: Any) -> Any:
        body = {"phone_id": phone.ref, "push_token": "tok", "push_platform": "apns"}
        return _http("POST", f"{ctx['base_url']}{path}", {**body, **({"device_assertion": a} if a else {})}, headers=hdr)
    hdr, ts = phone.poll_headers(path)
    _three(ctx, phone, send, lambda **kw: phone.assertion("push-token", phone.ref, b"tok|apns", ts, **kw),
           lambda: _held(ctx, phone).push_token == "tok")


def test_a_push_token_another_party_put_in_its_place_is_refused(ctx, phone) -> None:
    path = "/v0.4/manage/push_token"
    hdr, ts = phone.poll_headers(path)
    status, body = _http("POST", f"{ctx['base_url']}{path}", {
        "phone_id": phone.ref, "push_token": "theirs", "push_platform": "apns",
        "device_assertion": phone.assertion("push-token", phone.ref, b"tok|apns", ts)}, headers=hdr)
    assert (status, body["reason"]) == (403, "assertion_signature") and _held(ctx, phone).push_token is None


def test_a_revoke(ctx, phone) -> None:
    member = HwPhone("member")
    android = AndroidVendor()
    BootloaderHandler.config.device_policy = dataclasses.replace(BootloaderHandler.config.device_policy, android_roots=android.roots)
    assert member.register(ctx, challenge=_member_challenge(ctx, "m"), vendor=android)[0] == 201

    def send(make: Any) -> Any:
        challenge = _http("GET", f"{ctx['base_url']}/v0.4/registration_challenge")[1]["challenge_b64u"]
        payload = f"{challenge}:{member.ref}".encode()
        a = make(challenge, payload) if make else None
        return _http("POST", f"{ctx['base_url']}/v0.4/manage/phones/revoke", {
            "revoker_phone_id": phone.ref, "target_phone_id": member.ref, "challenge_b64u": challenge,
            "signature_b64u": b64u(phone.identity.sign(payload)), **({"device_assertion": a} if a else {})})
    _three(ctx, phone, send, lambda **kw: lambda c, p: phone.assertion("revoke", c, p, c, **kw),
           lambda: _held(ctx, member) is None, removes=True)


def test_an_owner_slots_approval(ctx, phone) -> None:
    android = AndroidVendor()
    BootloaderHandler.config.device_policy = dataclasses.replace(BootloaderHandler.config.device_policy, android_roots=android.roots)
    second = HwPhone("second")
    assert second.register(ctx, "recovery", vendor=android)[0] == 403
    card = ctx["state"].list_pending_for_phone(phone.ref)[0]
    _three(ctx, phone, lambda a: phone.answer(ctx, card, a), lambda **kw: phone.for_card(card, **kw),
           lambda: [r["state"] for r in ctx["state"].list_owner_enrolls()] == ["approved"])


def _said(out: str) -> dict[str, Any]:
    return json.loads(next(line for line in out.splitlines() if line.strip().startswith("{")))


@pytest.mark.parametrize("mode", ["record", "require"])
def test_the_resets_cancel_and_its_fresh_device(tmp_path, apple, mode) -> None:
    """A top-plane card asks as any card does; and the fresh device's key is seated with it."""
    with serving(tmp_path, device_policy=_policy(apple, mode, "record"), capability_operator_pubkey=_op_key()) as c:
        BootloaderHandler.config.owner_reset_window_seconds = 1
        try:
            r, p = Phone("recovery"), IPhone(HwPhone("primary"), apple)
            assert r.register(c, "recovery")[0] == 201
            assert p.enrol(c)[0] == 403
            _approve_owner_cards(c, r)
            assert p.enrol(c)[0] == 201
            _seed_chain(c["state"], r)
            assert _host(tp.seal_id, c)[0] == 0
            assert _approve(c, r, _top_cards(c, r)[0])[0] == 200

            def start(slot: str, lost: str) -> str:
                return _said(_host(tp.reset_start, c, slot=slot, slot_list=[slot], confirm=lost, window_seconds=1)[1])["intent_id"]
            iid = start("recovery", r.ref)
            card = next(x for x in c["state"].list_pending_for_phone(p.ref) if x.secret.startswith("top-plane:"))
            _three({"mode": mode}, p, lambda a: p.answer(c, card, a), lambda **kw: p.for_card(card, **kw),
                   lambda: c["state"].get_top_plane_record(iid)["state"] == "cancelled", removes=True)

            iid = start("primary", p.ref)
            time.sleep(1.5)
            code = _reset_code(_host(tp.reset_arm, c, arm=iid, slot="primary")[1])
            challenge = _http("GET", f"{c['base_url']}/v0.4/registration_challenge?code={code}")[1]["challenge_b64u"]
            fresh = IPhone(HwPhone("fresh"), apple)
            assert fresh.enrol(c, challenge=challenge)[0] == 202
            assert _host(tp.reset_complete, c, complete=iid, slot="primary")[0] == 0
            held = c["state"].get_phone(fresh.ref)
            assert held.device_class == "attested" and held.app_attest_key_id is not None
            card = queue(c, fresh)
            assert fresh.answer(c, card, fresh.for_card(card))[0] == 200
        finally:
            BootloaderHandler.config.owner_reset_window_seconds = 72 * 3600


def test_a_member_hand_over(ctx, phone, apple) -> None:
    old = IPhone(HwPhone("old"), apple)
    assert old.enrol(ctx, challenge=_member_challenge(ctx, "m"))[0] == 201
    new = HwPhone("new")

    def send(make: Any) -> Any:
        challenge = _member_challenge(ctx, "m")
        payload = f"{MEMBER_REBIND_PREFIX}|{CONSUMER}|{_subject('m')}|{old.ref}|{new.pub}|{challenge}".encode()
        real = HwPhone.register

        def with_assertion(method, url, body=None, headers=None):
            if body and make:
                body = {**body, "member_rebind_assertion": make(challenge, payload)}
            return _http(method, url, body, headers=headers)
        from tests import test_device_evidence_register as module
        keep, module._http = module._http, with_assertion
        try:
            return real(new, ctx, challenge=challenge, vendor=apple, rebind=b64u(old.identity.sign(payload)))
        finally:
            module._http = keep
    _three(ctx, old, send, lambda **kw: lambda c, p: old.assertion("member-rebind", c, p, c, **kw),
           lambda: bool(_held(ctx, new) and _held(ctx, new).member_bindings))


def test_the_vaults_records(tmp_path, apple, monkeypatch) -> None:
    """grant, revoke and stop-all verify the record first; the assertion is over the record's signature."""
    for mode in ("record", "require"):
        with serving(tmp_path / mode, device_policy=_policy(apple, mode), user_vault_path=str(tmp_path / f"{mode}.json")) as c:
            phone = IPhone(HwPhone(), apple)
            assert phone.enrol(c)[0] == 201
            seen: list[str] = []
            for act, route, module, names in (
                ("vault-grant", "grant", "GrantRecord", "verify_grant"), ("vault-revoke", "revoke", "RevokeRecord", "verify_revoke"),
                ("vault-revoke-key", "revoke-key", "RevokeKeyRecord", "verify_revoke_key"),
            ):
                import recto.user_vault.grant_record as gr

                class _Rec:
                    consumer, subject, key, agent_handle, not_after = "c", "s", "k", "a", 2**33

                    @classmethod
                    def from_dict(cls, _d):
                        return cls()

                    def to_dict(self):
                        return {"consumer": "c", "subject": "s", "key": "k", "agent_handle": "a", "not_after": 2**33}
                monkeypatch.setattr(gr, module, _Rec)
                monkeypatch.setattr(gr, names, lambda *a, **kw: f"id-{act}")
                monkeypatch.setattr(BootloaderHandler, "_bound_phone_for", lambda self, consumer, subject: self.config.state.get_phone(phone.ref))

                def send(a: Any) -> Any:
                    return _http("POST", f"{c['base_url']}/v0.4/user-vault/{route}",
                                 {"record": {}, "signature_b64u": "SIG", **({"device_assertion": a} if a else {})})
                status, body = send(phone.assertion(act, phone.ref, b"SIG", "", signer=p256()))
                assert (status, body["error"]) == (403, "approval_evidence_invalid")
                status, body = send(phone.assertion(act, phone.ref, b"OTHER", ""))
                assert (status, body["error"]) == (403, "approval_evidence_invalid"), "another record's"
                if act == "vault-grant" and mode == "require":
                    assert send(None)[1]["error"] == "approval_evidence_required"
                if act != "vault-grant":    # only takes authority back: never kept from it by a missing assertion
                    assert send(None)[1].get("error") not in ("approval_evidence_invalid", "approval_evidence_required")
                status, body = send(phone.assertion(act, phone.ref, b"SIG", ""))
                seen.append(f"{act} {status} {body.get('error')}")
                assert body.get("error") not in ("approval_evidence_invalid", "approval_evidence_required"), body
            assert len(seen) == 3


def test_the_pairing_relay_asks_the_bound_phone_before_the_grant_is_spent(tmp_path, apple, monkeypatch) -> None:
    from tests import test_bootloader_devices_pair as pair
    from tests.test_device_evidence_kept_nowhere import _regrant
    for mode in ("record", "require"):
        with serving(tmp_path / mode, device_policy=_policy(apple, mode), devices_pair_consumer_webhook_tokens={CONSUMER: "t"}) as c:
            phone = IPhone(HwPhone(), apple)
            assert phone.enrol(c, challenge=_member_challenge(c, "user-1"))[0] == 201
            priv, pub = pair._keypair()
            bid = BootloaderHandler.config.bootloader_id
            record = pair._record({"pub": pub}, bootloader_id=bid, subject=_subject("user-1"))
            grant = _regrant(pair, pair._grant({"priv": priv, "pub": pub}, record), priv, bid)

            def send(a: Any) -> Any:
                return _http("POST", f"{c['base_url']}/v0.4/devices/pair", {
                    "consumer_base_url": CONSUMER, "record": record.to_dict(), "user_jws": grant,
                    **({"device_assertion": a} if a else {})})

            def made(**kw: Any) -> str:
                return phone.assertion("pair", record.code, grant.encode(), str(record.not_after), **kw)
            assert send(made(signer=p256()))[1]["error"] == "approval_evidence_invalid"
            if mode == "require":
                assert send(None)[1]["error"] == "approval_evidence_required"
            status, body = send(made())         # past the gate: the consumer is not there to answer
            assert (status, body["error"]) == (502, "consumer_unreachable"), body
            assert send(made())[1]["error"] == "grant_replayed", "spent only by the act that passed"


def test_a_grant_requests_deny(tmp_path, apple) -> None:
    import types
    for mode in ("record", "require"):
        with serving(tmp_path / mode, device_policy=_policy(apple, mode), user_vault_path=str(tmp_path / f"{mode}.json")) as c:
            phone = IPhone(HwPhone(), apple)
            assert phone.enrol(c)[0] == 201
            denied: list[str] = []
            BootloaderHandler.config.user_vault_grant_requests = types.SimpleNamespace(
                get=lambda rid: types.SimpleNamespace(phone_id=phone.ref), deny=lambda rid: denied.append(rid) or True,
                list_for_phone=lambda *_: [], for_phone=lambda *_: [])
            path = "/v0.4/user-vault/grant-request/deny"
            hdr, ts = phone.poll_headers(path)

            def send(a: Any) -> Any:
                return _http("POST", f"{c['base_url']}{path}", {"request_id": "r1", **({"device_assertion": a} if a else {})}, headers=hdr)
            _three({"mode": mode}, phone, send, lambda **kw: phone.assertion("vault-deny", "r1", b"", ts, **kw), lambda: denied == ["r1"],
                   removes=True)


def test_every_act_that_verifies_a_phones_signature_asks() -> None:
    """The list in the notes is the code's: each verified act, and the two that are not one."""
    import recto.bootloader.server as server
    source = Path(server.__file__).read_text(encoding="utf-8")
    acts = (set(re.findall(r'act="([a-z-]+)"', source)) - {"approve"}) | set(re.findall(r'_vault_evidence_ok\(phone, body, "([a-z-]+)"\)', source))
    assert acts == {"push-token", "revoke", "member-rebind", "pair", "vault-grant", "vault-revoke", "vault-revoke-key", "vault-deny"}
    assert source.count("_card_evidence_ok(") == 1 + 4     # defined; owner card, top-plane card, deny, approve


# --- losing the key, and the ways back ------------------------------------


def test_a_re_pair_with_a_fresh_attestation_replaces_the_key(ctx, phone, apple) -> None:
    card = queue(ctx, phone)
    assert phone.answer(ctx, card, phone.for_card(card))[0] == 200
    old_key, phone.attest_key, phone.counter = phone.attest_key, p256(), 0
    status, body = phone.enrol(ctx)
    assert status == 201 and body["app_attest_kept"] is True
    assert _held(ctx, phone).app_attest_counter == 0
    card = queue(ctx, phone)
    assert phone.answer(ctx, card, phone.for_card(card, key=old_key))[0] == 403, "the old key answers nothing"
    phone.counter = 0
    assert phone.answer(ctx, card, phone.for_card(card))[0] == 200


def test_a_re_pair_with_nothing_to_show_is_not_refused_and_keeps_the_key(ctx, phone) -> None:
    """Apple being down never stops a paired phone; nor does leaving the evidence out let the key go."""
    status, body = phone.register(ctx)
    assert status == 201 and "app_attest_kept" not in body
    assert _held(ctx, phone).app_attest_key_id is not None
    card = queue(ctx, phone)
    assert phone.answer(ctx, card, None)[0] == (200 if ctx["mode"] == "record" else 403)
    assert phone.answer(ctx, queue(ctx, phone), phone.for_card(queue(ctx, phone)))[0] == 403


def test_a_re_pair_with_bad_evidence_keeps_the_key(ctx, phone, apple) -> None:
    before = _held(ctx, phone).app_attest_key_id
    status, body = phone.register(ctx, vendor=apple, key=p256(), counter=1)
    assert status == 201 and "app_attest_kept" not in body and _held(ctx, phone).app_attest_key_id == before


def test_the_hosts_code_lets_a_lost_key_go(ctx, phone) -> None:
    status, body = phone.register(ctx, test_code="AAAAA-AAAAA")
    assert status == 201 and _held(ctx, phone).app_attest_key_id is not None, "a wrong code refuses nothing and lets nothing go"
    wrong_plane = dc.issue(ctx["dir"], plane="member", label="lost")[0]
    assert phone.register(ctx, test_code=wrong_plane)[0] == 201 and _held(ctx, phone).app_attest_key_id is not None
    code = dc.issue(ctx["dir"], plane="owner", label="lost key")[0]
    status, body = phone.register(ctx, test_code=code)
    assert status == 201 and body["device_class"] == "test"
    held = _held(ctx, phone)
    assert (held.app_attest_key_id, held.act_class, held.device_test_label) == (None, None, "lost key")
    assert dc.find(ctx["dir"], code, "owner") is None
    card = queue(ctx, phone)
    assert phone.answer(ctx, card, None)[0] == 200


def test_the_second_owner_pass_attests_again_under_require(ctx, phone, apple) -> None:
    second = IPhone(HwPhone("second"), apple)
    assert second.enrol(ctx, "recovery")[0] == 403
    waiting = ctx["state"].list_owner_enrolls()[0]
    assert set(waiting["device"]) == {"class", "platform", "at_unix", "test_label"}, "no key waits with it"
    card = ctx["state"].list_pending_for_phone(phone.ref)[0]
    assert phone.answer(ctx, card, phone.for_card(card))[0] == 200
    status, body = second.register(ctx, "recovery")
    assert (status, body["error"]) == (403, "device_evidence_required"), "stripped on the second pass"
    status, body = second.enrol(ctx, "recovery")
    assert status == 201 and body["app_attest_kept"] is True


def test_the_phone_list_shows_the_class_of_its_acts_and_never_the_key(ctx, phone, apple) -> None:
    member = IPhone(HwPhone("member"), apple)
    assert member.enrol(ctx, challenge=_member_challenge(ctx, "m"))[0] == 201
    card = queue(ctx, member)
    assert member.answer(ctx, card, member.for_card(card))[0] == 200
    hdr, _ = phone.poll_headers("/v0.4/manage/phones")
    status, body = _http("GET", f"{ctx['base_url']}/v0.4/manage/phones?phone_id={phone.ref}", headers=hdr)
    row = body["phones"][0]
    assert row["act_class"] == "asserted" and not [k for k in row if k.startswith("app_attest")]
    assert "app_attest" not in repr(_held(ctx, member))


# --- the policy -----------------------------------------------------------


def test_the_approval_mode_is_its_own_and_records_by_default() -> None:
    assert de.DevicePolicy.from_env({}).approval_mode == "record"
    policy = de.DevicePolicy.from_env({"RECTO_APPROVAL_EVIDENCE_MODE": " Require "})
    assert (policy.approval_mode, policy.mode) == ("require", "require")
    said = "\n".join(policy.describe())
    assert "Approval evidence: require" in said
    assert "Approval evidence: record" in "\n".join(de.DevicePolicy.from_env({}).describe())
    with pytest.raises(ValueError, match="RECTO_APPROVAL_EVIDENCE_MODE"):
        de.DevicePolicy.from_env({"RECTO_APPROVAL_EVIDENCE_MODE": "off"})


def test_every_truncation_and_flip_of_an_assertion_is_the_one_error(apple) -> None:
    key = p256()
    from tests.device_evidence_builder import point
    cdh = de.assertion_client_data_hash("approve", "r", b"p", "1")
    raw = base64.b64decode(apple.assertion(key, cdh, 1))
    call = {"policy": _policy(apple, "record"), "public_key_b64u": b64u(point(key)), "client_data_hash": cdh}
    assert de.verify_assertion(base64.b64encode(raw).decode(), **call) == 1
    for i in range(0, len(raw), 3):
        for bad in (raw[:i], raw[:i] + bytes([raw[i] ^ 0x55]) + raw[i + 1:]):
            with pytest.raises(de.EvidenceInvalid):
                de.verify_assertion(base64.b64encode(bad).decode(), **call)
    with pytest.raises(de.EvidenceInvalid, match="^malformed$"):    # a stored key that is no point of the curve
        de.verify_assertion(base64.b64encode(raw).decode(), **{**call, "public_key_b64u": b64u(bytes([1]) * 64)})


def test_one_spelling_per_act() -> None:
    base = ("approve", "r", b"p", "1")
    seen = {de.assertion_client_data_hash(*base)}
    for i, other in enumerate(("deny", "s", b"q", "2")):
        seen.add(de.assertion_client_data_hash(*[other if j == i else v for j, v in enumerate(base)]))
    assert len(seen) == 5
