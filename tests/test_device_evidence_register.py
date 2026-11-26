"""GATE 2b at the register door (hard rule 14.8): a NEW key enters a slot only with its vendor's evidence, or on a
test-device code from the host. A key the registry holds is never asked, and no read or approval asks at all.

A real bootloader, phones with P-256 keys, and synthetic vendors trusted through the server's ``device_policy``.
"""

from __future__ import annotations

import base64
import json
import logging
import time
from typing import Any

import pytest

pytest.importorskip("cryptography")

from recto.bootloader import device_codes as dc  # noqa: E402
from recto.bootloader import device_evidence as de  # noqa: E402
from recto.bootloader.server import (  # noqa: E402
    MEMBER_REBIND_PREFIX,
    BootloaderHandler,
    poll_key_delegation_payload,
    slot_replace_payload,
)
from recto.bootloader.state import StateStore, phone_ref_of  # noqa: E402
from tests.device_evidence_builder import (  # noqa: E402
    APP_ID,
    AndroidVendor,
    AppleVendor,
    b64u,
    p256,
    point,
    sign_raw,
)
from tests.test_bootloader_owner_slots import AGENT_ID, AGENT_TOKEN, CONSUMER, _subject, serving  # noqa: E402
from tests.test_bootloader_slots import Phone, _approve_owner_cards, _http  # noqa: E402
from tests.test_top_plane_e2e import _approve, _host, _op_key, _seed_chain, _top_cards, tp  # noqa: E402

REAL_DEVICE_DEFAULT = True


class _Signer:
    def __init__(self, key: Any) -> None:
        self.key = key

    def sign(self, payload: bytes) -> bytes:
        raw = sign_raw(self.key, payload)
        return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


class HwPhone(Phone):
    """A phone whose identity key is P-256, so a vendor can attest it."""

    def __init__(self, label: str = "hardware") -> None:
        self.label, self.key, self.poll_key = label, p256(), p256()
        self.identity, self.poll = _Signer(self.key), _Signer(self.poll_key)
        self.pub, self.poll_pub = b64u(point(self.key)), b64u(point(self.poll_key))
        self.ref = phone_ref_of(self.pub)

    def register(self, ctx, slot: str = "primary", *, challenge: str | None = None, replace: str | None = None,
                 vendor: Any = None, evidence: Any = None, test_code: str | None = None, rebind: str | None = None,
                 headers: dict[str, str] | None = None, replace_signer: Any = None, **kw: Any,
                 ) -> tuple[int, dict[str, Any]]:
        if challenge is None:
            challenge = owner_challenge(ctx)
        self.last_challenge = challenge
        body: dict[str, Any] = {
            "device_label": self.label, "public_key_b64u": self.pub, "supported_algorithms": ["ecdsa-p256"],
            "v0_4_protocol": 1, "slot": slot,
            "registration_proof": {"challenge": challenge,
                                   "signature_b64u": b64u(self.identity.sign(challenge.encode("ascii")))},
            "poll_public_key_b64u": self.poll_pub,
            "poll_key_delegation_b64u": b64u(self.identity.sign(poll_key_delegation_payload(self.pub, self.poll_pub))),
        }
        if vendor is not None:
            evidence = (vendor.evidence(self.key, challenge, **kw) if isinstance(vendor, AndroidVendor)
                        else vendor.evidence(challenge, self.pub, self.poll_pub, **kw))
        if evidence is not None:
            body["device_evidence"] = evidence
        if test_code is not None:
            body["test_device_code"] = test_code
        if replace is not None:
            body["slot_replace_b64u"] = b64u(self.identity.sign(slot_replace_payload(slot, replace, self.pub)))
        if rebind is not None:
            body["member_rebind_b64u"] = rebind
        return _http("POST", f"{ctx['base_url']}/v0.4/register", body, headers=headers)


def owner_challenge(ctx) -> str:
    code, _ = ctx["challenges"].issue_pairing_code()
    status, chal = _http("GET", f"{ctx['base_url']}/v0.4/registration_challenge?code={code}")
    assert status == 200, chal
    return chal["challenge_b64u"]


def _member_challenge(ctx, user: str) -> str:
    status, minted = _http("POST", f"{ctx['base_url']}/v0.4/pairing/code",
                           {"member_of": {"consumer": CONSUMER, "subject": _subject(user)}},
                           headers={"X-Recto-Agent-Id": AGENT_ID, "X-Recto-Agent-Token": AGENT_TOKEN})
    assert status == 200, minted
    status, chal = _http("GET", f"{ctx['base_url']}/v0.4/registration_challenge?code={minted['code']}")
    assert status == 200, chal
    return chal["challenge_b64u"]


@pytest.fixture
def android() -> AndroidVendor:
    return AndroidVendor()


@pytest.fixture
def ctx(tmp_path, android):
    with serving(tmp_path, device_policy=android.policy()) as c:
        yield {**c, "dir": tmp_path}


def _held(ctx, phone) -> Any:
    return ctx["state"].get_phone(phone.ref)


def _code(ctx, plane: str, label: str = "emulator-1") -> str:
    return dc.issue(ctx["dir"], plane=plane, label=label)[0]


def _enroll(ctx, android, label="owner", slot="primary") -> HwPhone:
    phone = HwPhone(label)
    status, body = phone.register(ctx, slot, vendor=android)
    assert status == 201 and body["device_class"] == "attested", body
    return phone


# --- what enters ----------------------------------------------------------


def test_an_attested_android_key_enters_and_its_class_is_kept_without_the_chain(ctx, android) -> None:
    phone = _enroll(ctx, android)
    reg = _held(ctx, phone)
    assert (reg.device_class, reg.device_platform, reg.device_test_label) == ("attested", "android", None)
    assert reg.device_class_at_unix % 86400 == 0 and 0 <= time.time() - reg.device_class_at_unix < 2 * 86400
    stored = (ctx["dir"] / "phones.json").read_text(encoding="utf-8")
    assert "device_evidence" not in stored and "chain" not in stored
    again = StateStore(state_dir=ctx["dir"]).get_phone(phone.ref)
    assert again.device_class == "attested", "the class survives a restart"


def test_an_attested_iphone_enters(tmp_path) -> None:
    apple = AppleVendor()
    policy = de.DevicePolicy(mode="require", ios_app_ids=frozenset({APP_ID}), apple_root_pem=apple.root_pem)
    with serving(tmp_path, device_policy=policy) as c:
        phone = HwPhone()
        status, body = phone.register(c, vendor=apple)
        assert status == 201 and body["device_class"] == "attested", body
        assert _held(c, phone).device_platform == "ios"


# --- what does not --------------------------------------------------------


def test_a_software_key_is_refused_by_name_in_every_slot(ctx, android) -> None:
    for phone in (Phone("script"), HwPhone("script")):
        status, body = phone.register(ctx, "primary")
        assert (status, body["error"]) == (403, "device_evidence_required"), body
    _enroll(ctx, android)
    for phone in (Phone("script"), HwPhone("script")):
        status, body = phone.register(ctx, "recovery")
        assert (status, body["error"]) == (403, "device_evidence_required"), body
        status, body = phone.register(ctx, challenge=_member_challenge(ctx, "member-1"))
        assert (status, body["error"]) == (403, "device_evidence_required"), body
    assert len(ctx["state"].list_phones()) == 1


def test_a_server_given_no_policy_requires_evidence(tmp_path) -> None:
    with serving(tmp_path) as c:
        status, body = Phone("script").register(c)
        assert (status, body["error"]) == (403, "device_evidence_required")
        assert c["state"].get_owner_genesis() == "open", "a refused key closes nothing"


@pytest.mark.parametrize(("reason", "kw"), [
    ("security_level", {"level": 0}), ("boot_state", {"locked": b"\x00"}), ("boot_state", {"boot_state": 2}),
])
def test_bad_evidence_is_refused_by_name(ctx, android, reason, kw) -> None:
    status, body = HwPhone().register(ctx, vendor=android, **kw)
    assert (status, body["error"], body["reason"]) == (403, "device_evidence_invalid", reason)


def test_evidence_for_another_key_another_challenge_or_replayed_is_refused(ctx, android) -> None:
    owner = _enroll(ctx, android)
    captured = android.evidence(owner.key, owner.last_challenge)
    thief = HwPhone("thief")
    status, body = thief.register(ctx, challenge=_member_challenge(ctx, "member-1"), evidence=captured)
    assert (status, body["reason"]) == (403, "key_mismatch")
    stale = HwPhone("stale")
    status, body = stale.register(ctx, challenge=_member_challenge(ctx, "member-1"),
                                  evidence=android.evidence(stale.key, "an earlier challenge"))
    assert (status, body["reason"]) == (403, "challenge_mismatch")


def test_evidence_stripped_on_the_way_is_refused_and_the_phone_may_send_it_again(ctx, android) -> None:
    phone, challenge = HwPhone(), owner_challenge(ctx)
    status, body = phone.register(ctx, challenge=challenge)
    assert (status, body["error"]) == (403, "device_evidence_required")
    assert phone.register(ctx, challenge=challenge, vendor=android)[0] == 201


def test_a_stranger_root_and_an_algorithm_swap_are_refused(ctx, android) -> None:
    status, body = HwPhone().register(ctx, vendor=AndroidVendor())
    assert (status, body["reason"]) == (403, "root_unknown")
    script = Phone("script")
    hardware = HwPhone()
    challenge = owner_challenge(ctx)
    script_body_evidence = android.evidence(hardware.key, challenge)
    orig = _http

    def send(method, url, body=None, headers=None):
        return orig(method, url, {**body, "device_evidence": script_body_evidence} if body else body, headers=headers)
    import tests.test_bootloader_slots as slots
    slots._http, keep = send, slots._http
    try:
        status, body = script.register(ctx, challenge=challenge)
    finally:
        slots._http = keep
    assert (status, body["reason"]) == (403, "algorithm")


# --- a key the registry holds is never asked ------------------------------


def test_a_phone_from_before_re_pairs_polls_and_approves_with_no_evidence(tmp_path, android) -> None:
    with serving(tmp_path, device_policy=android.policy(mode="record")) as c:
        owner, member = Phone("owner"), Phone("member")
        assert owner.register(c)[0] == 201
        assert member.register(c, challenge=_member_challenge(c, "member-1"))[0] == 201
    raw = json.loads((tmp_path / "phones.json").read_text(encoding="utf-8"))
    for row in raw["phones"]:       # as an older bootloader wrote it
        for field in ("device_class", "device_platform", "device_class_at_unix", "device_test_label"):
            row.pop(field)
    (tmp_path / "phones.json").write_text(json.dumps(raw), encoding="utf-8")
    with serving(tmp_path, device_policy=android.policy()) as c:
        assert _held(c, owner).device_class == "unverified"
        assert owner.register(c)[0] == 201
        assert member.register(c, challenge=_member_challenge(c, "member-1"))[0] == 201
        assert owner.register(c, challenge=_member_challenge(c, "owner-as-member"))[0] == 201
        assert _held(c, owner).slot == "primary" and _held(c, owner).device_class == "unverified"
        assert owner.read_pending(c)[0] == 200
        second = HwPhone("second")
        assert second.register(c, "recovery", vendor=android)[0] == 403
        _approve_owner_cards(c, owner)      # an unverified owner still approves
        assert second.register(c, "recovery")[0] == 201


def test_a_re_pair_never_lowers_the_class_and_evidence_raises_it(tmp_path, android) -> None:
    with serving(tmp_path, device_policy=android.policy(mode="record")) as c:
        owner = HwPhone()
        assert owner.register(c)[1]["device_class"] == "unverified"
        assert owner.register(c, vendor=android)[1]["device_class"] == "attested"
        assert owner.register(c)[1]["device_class"] == "attested"
        assert owner.register(c, vendor=android, level=0)[1]["device_class"] == "attested"


def test_a_removed_key_is_a_new_key(ctx, android) -> None:
    owner = _enroll(ctx, android)
    member = HwPhone("member")
    assert member.register(ctx, challenge=_member_challenge(ctx, "member-1"), vendor=android)[0] == 201
    ctx["state"].revoke_phone(member.ref)
    status, body = member.register(ctx, challenge=_member_challenge(ctx, "member-1"))
    assert (status, body["error"]) == (403, "device_evidence_required")
    assert _held(ctx, owner) is not None


def test_a_key_revoked_while_it_pairs_is_not_let_in(ctx, android, monkeypatch) -> None:
    """The exemption is read again under the registry lock."""
    _enroll(ctx, android)
    member = Phone("member")
    monkeypatch.setattr(BootloaderHandler, "_device_facts", lambda self, body, **kw: de.DeviceFacts())
    status, body = member.register(ctx, challenge=_member_challenge(ctx, "member-1"))
    assert status == 400 and "left the registry" in body["detail"], body
    assert _held(ctx, member) is None


# --- the owner plane's two passes -----------------------------------------


def test_the_second_pass_rides_the_evidence_of_the_first(ctx, android) -> None:
    owner = _enroll(ctx, android)
    second = HwPhone("second")
    status, body = second.register(ctx, "recovery", vendor=android)
    assert (status, body["error"]) == (403, "owner_approval_required")
    status, body = HwPhone("script").register(ctx, "recovery")
    assert (status, body["error"]) == (403, "device_evidence_required"), "another key does not ride it"
    _approve_owner_cards(ctx, owner)
    status, body = second.register(ctx, "recovery")     # another challenge, the same key
    assert status == 201 and body["device_class"] == "attested", body


def test_replacing_a_slot_asks_the_new_key_only(ctx, android) -> None:
    owner = _enroll(ctx, android)
    script, phone = HwPhone("script"), HwPhone("new")
    status, body = script.register(ctx, replace=owner.ref)
    assert (status, body["error"]) == (403, "device_evidence_required")
    challenge = owner_challenge(ctx)
    assert phone.register(ctx, challenge=challenge, vendor=android)[0] == 409
    status, body = phone.register(ctx, challenge=challenge, vendor=android, replace=owner.ref)
    assert (status, body["error"]) == (403, "owner_approval_required"), body
    _approve_owner_cards(ctx, owner)
    status, body = phone.register(ctx, replace=owner.ref)
    assert status == 201 and body["device_class"] == "attested", body


def test_an_approval_given_to_an_unverified_key_does_not_seat_it_under_require(tmp_path, android) -> None:
    with serving(tmp_path, device_policy=android.policy(mode="record")) as c:
        owner, second = Phone("owner"), Phone("second")
        assert owner.register(c)[0] == 201
        assert second.register(c, "recovery")[0] == 403
        _approve_owner_cards(c, owner)
        BootloaderHandler.config.device_policy = android.policy()
        status, body = second.register(c, "recovery")
        assert (status, body["error"]) == (403, "device_evidence_required"), body


# --- member hand-over -----------------------------------------------------


def test_a_member_hand_over_asks_the_incoming_key(ctx, android) -> None:
    _enroll(ctx, android)
    old, new = HwPhone("old"), HwPhone("new")
    assert old.register(ctx, challenge=_member_challenge(ctx, "member-1"), vendor=android)[0] == 201

    def rebind(phone, challenge):
        return b64u(old.identity.sign(
            f"{MEMBER_REBIND_PREFIX}|{CONSUMER}|{_subject('member-1')}|{old.ref}|{phone.pub}|{challenge}".encode()))
    challenge = _member_challenge(ctx, "member-1")
    status, body = new.register(ctx, challenge=challenge, rebind=rebind(new, challenge))
    assert (status, body["error"]) == (403, "device_evidence_required")
    assert _held(ctx, old).member_bindings
    status, body = new.register(ctx, challenge=challenge, rebind=rebind(new, challenge), vendor=android)
    assert status == 201, body
    assert not _held(ctx, old).member_bindings and _held(ctx, new).device_class == "attested"


# --- record ---------------------------------------------------------------


def test_record_stores_the_class_and_refuses_nothing(tmp_path, android, caplog) -> None:
    caplog.set_level(logging.INFO)
    with serving(tmp_path, device_policy=android.policy(mode="record")) as c:
        script = Phone("script")
        assert script.register(c)[0] == 201
        assert _held(c, script).device_class == "unverified"
        member = HwPhone("member")
        status, body = member.register(c, challenge=_member_challenge(c, "member-1"), vendor=android, locked=b"\x00")
        assert status == 201 and body["device_class"] == "unverified"
        good = HwPhone("good")
        status, body = good.register(c, challenge=_member_challenge(c, "member-2"), vendor=android)
        assert status == 201 and body["device_class"] == "attested"
        other = HwPhone("other")
        status, body = other.register(c, challenge=_member_challenge(c, "member-3"), test_code="AAAAA-AAAAA")
        assert status == 201 and body["device_class"] == "unverified"
    assert "boot_state" in caplog.text and CONSUMER not in caplog.text and _subject("member-1") not in caplog.text


# --- the test-device code -------------------------------------------------


def test_a_test_code_admits_one_member_key_as_test_and_shows(ctx, android) -> None:
    owner = _enroll(ctx, android)
    code = _code(ctx, "member")
    emu = HwPhone("emulator")
    status, body = emu.register(ctx, challenge=_member_challenge(ctx, "member-1"), test_code=code)
    assert status == 201 and body["device_class"] == "test", body
    reg = _held(ctx, emu)
    assert (reg.device_class, reg.device_platform, reg.device_test_label) == ("test", None, "emulator-1")
    assert reg.slot == "member"
    second = HwPhone("second emulator")
    status, body = second.register(ctx, challenge=_member_challenge(ctx, "member-2"), test_code=code)
    assert (status, body["error"]) == (403, "test_device_code_invalid"), body
    assert emu.register(ctx, challenge=_member_challenge(ctx, "member-1"))[1]["device_class"] == "test"
    ts = int(time.time())
    sig = owner.poll.sign(f"recto-poll-v1|{owner.ref}|{ts}|/v0.4/manage/phones".encode("ascii"))
    from recto.bootloader.server import POLL_SIG_HEADER, POLL_SIG_TS_HEADER
    status, body = _http("GET", f"{ctx['base_url']}/v0.4/manage/phones?phone_id={owner.ref}",
                         headers={POLL_SIG_HEADER: b64u(sig), POLL_SIG_TS_HEADER: str(ts)})
    assert status == 200, body
    row = next(p for p in body["phones"] if p["phone_id"] == emu.ref)
    assert (row["device_class"], row["device_test_label"]) == ("test", "emulator-1")


def test_a_test_code_is_for_its_own_plane(ctx, android) -> None:
    owner = _enroll(ctx, android)
    member_code, owner_code = _code(ctx, "member"), _code(ctx, "owner")
    emu = HwPhone("emulator")
    status, body = emu.register(ctx, "recovery", test_code=member_code)
    assert (status, body["error"]) == (403, "test_device_code_invalid")
    status, body = emu.register(ctx, challenge=_member_challenge(ctx, "member-1"), test_code=owner_code)
    assert (status, body["error"]) == (403, "test_device_code_invalid")
    assert dc.find(ctx["dir"], member_code, "member") and dc.find(ctx["dir"], owner_code, "owner"), "neither was spent"
    assert _held(ctx, owner).slot == "primary"


def test_the_break_glass_code_still_needs_every_other_owner_rule(ctx, android) -> None:
    owner = _enroll(ctx, android)
    code = _code(ctx, "owner", "spare")
    body_of = HwPhone("spare")
    status, body = body_of.register(ctx, "recovery", test_code=code)
    assert (status, body["error"]) == (403, "owner_approval_required"), body
    assert dc.find(ctx["dir"], code, "owner") is None, "spent when its approval is asked"
    cards = owner.read_pending(ctx)[1]["requests"]
    assert any("TEST DEVICE" in json.dumps(c) for c in cards)
    assert _held(ctx, body_of) is None
    _approve_owner_cards(ctx, owner)
    status, body = body_of.register(ctx, "recovery")
    assert status == 201 and body["device_class"] == "test", body
    other = HwPhone("other")
    status, body = other.register(ctx, "recovery", test_code=code)
    assert (status, body["error"]) == (403, "test_device_code_invalid")


def test_a_code_admits_the_first_owner_when_no_vendor_will(tmp_path, android) -> None:
    with serving(tmp_path, device_policy=android.policy()) as c:
        ctx = {**c, "dir": tmp_path}
        code, owner = _code(ctx, "owner"), HwPhone("owner")
        challenge = owner_challenge(ctx)
        status, body = owner.register(ctx, challenge=challenge, test_code=code)
        assert status == 201 and body["device_class"] == "test", body
        assert c["state"].get_owner_genesis() == "closed" and dc.find(tmp_path, code, "owner") is None


def test_the_slot_question_does_not_spend_the_code(ctx, android) -> None:
    owner = _enroll(ctx, android)
    code, phone, challenge = _code(ctx, "owner"), HwPhone("new"), owner_challenge(ctx)
    assert phone.register(ctx, challenge=challenge, test_code=code)[0] == 409
    status, body = phone.register(ctx, challenge=challenge, test_code=code, replace=owner.ref)
    assert (status, body["error"]) == (403, "owner_approval_required"), body


def test_valid_evidence_wins_and_leaves_the_code_unspent(ctx, android) -> None:
    code, phone = _code(ctx, "owner"), HwPhone()
    status, body = phone.register(ctx, vendor=android, test_code=code)
    assert status == 201 and body["device_class"] == "attested"
    assert dc.find(ctx["dir"], code, "owner") is not None


def test_two_registrations_racing_for_one_code_let_one_in(ctx, android, monkeypatch) -> None:
    _enroll(ctx, android)
    code = _code(ctx, "member")
    monkeypatch.setattr(BootloaderHandler, "_device_facts",
                        lambda self, body, **kw: de.DeviceFacts("test", None, 1, "emulator-1", test_code=code))
    first = HwPhone("a").register(ctx, challenge=_member_challenge(ctx, "member-1"))
    second = HwPhone("b").register(ctx, challenge=_member_challenge(ctx, "member-2"))
    assert first[0] == 201 and (second[0], second[1]["error"]) == (403, "test_device_code_invalid")


def test_wrong_test_codes_over_the_public_edge_are_counted_and_stopped(ctx, android) -> None:
    _enroll(ctx, android)
    edge = {"CF-Connecting-IP": "203.0.113.9"}
    for _ in range(5):
        status, body = HwPhone().register(ctx, challenge=_member_challenge(ctx, "member-1"), test_code="AAAAA-AAAAA",
                                          headers=edge)
        assert (status, body["error"]) == (403, "test_device_code_invalid")
    good = _code(ctx, "member")
    status, body = HwPhone().register(ctx, challenge=_member_challenge(ctx, "member-1"), test_code=good, headers=edge)
    assert (status, body["error"]) == (429, "too_many_wrong_codes")
    assert dc.find(ctx["dir"], good, "member") is not None
    status, _ = HwPhone().register(ctx, challenge=_member_challenge(ctx, "member-1"), test_code=good)
    assert status == 201, "the operator's private route is not locked"


def test_no_route_issues_a_test_code(ctx) -> None:
    for path in ("/v0.4/test-device", "/v0.4/pairing/test", "/v0.4/manage/test-device"):
        assert _http("POST", f"{ctx['base_url']}{path}", {"plane": "owner", "label": "x"})[0] == 404
    status, body = _http("POST", f"{ctx['base_url']}/v0.4/pairing/code", {"plane": "test", "label": "x"},
                         headers={"X-Recto-Agent-Id": AGENT_ID, "X-Recto-Agent-Token": AGENT_TOKEN})
    assert status == 403, body


# --- the owner reset ------------------------------------------------------


@pytest.mark.parametrize("way", ["evidence", "code"])
def test_an_owner_reset_asks_its_fresh_device(tmp_path, android, way) -> None:
    """The sealed plane's way back in seats a key only with evidence, and the class travels with the seat."""
    op_key = _op_key()
    with serving(tmp_path, device_policy=android.policy(mode="record"), capability_operator_pubkey=op_key) as c:
        BootloaderHandler.config.owner_reset_window_seconds = 1
        try:
            r, p = Phone("recovery"), Phone("primary")
            assert r.register(c, "recovery")[0] == 201
            assert p.register(c, "primary")[0] == 403
            _approve_owner_cards(c, r)
            assert p.register(c, "primary")[0] == 201
            _seed_chain(c["state"], r)
            rc, _, err = _host(tp.seal_id, c)
            assert rc == 0, err
            assert _approve(c, r, _top_cards(c, r)[0])[0] == 200
            BootloaderHandler.config.device_policy = android.policy()
            rc, out, err = _host(tp.reset_start, c, slot="primary", slot_list=["primary"], confirm=p.ref, window_seconds=1)
            assert rc == 0, err
            iid = json.loads(next(line for line in out.splitlines() if line.strip().startswith("{")))["intent_id"]
            time.sleep(1.5)
            rc, out, err = _host(tp.reset_arm, c, arm=iid, slot="primary")
            assert rc == 0, err
            code = json.loads(next(line for line in out.splitlines() if line.strip().startswith("{")))["code"]
            status, chal = _http("GET", f"{c['base_url']}/v0.4/registration_challenge?code={code}")
            assert status == 200, chal
            fresh, challenge = HwPhone("fresh"), chal["challenge_b64u"]
            status, body = fresh.register(c, challenge=challenge)
            assert (status, body["error"]) == (403, "device_evidence_required"), body
            test_code = dc.issue(tmp_path, plane="owner", label="spare")[0]
            shown = {"vendor": android} if way == "evidence" else {"test_code": test_code}
            status, body = fresh.register(c, challenge=challenge, **shown)
            assert status == 202, body
            assert (dc.find(tmp_path, test_code, "owner") is None) == (way == "code")
            rc, out, err = _host(tp.reset_complete, c, complete=iid, slot="primary")
            assert rc == 0, err
            reg = c["state"].get_phone(fresh.ref)
            assert (reg.slot, reg.device_class, reg.device_platform, reg.device_test_label) == (
                ("primary", "attested", "android", None) if way == "evidence" else ("primary", "test", None, "spare"))
        finally:
            BootloaderHandler.config.owner_reset_window_seconds = 72 * 3600


def test_the_startup_lines_are_logged(tmp_path, android, caplog) -> None:
    caplog.set_level(logging.INFO, logger="recto.bootloader.devices")
    with serving(tmp_path, device_policy=android.policy()):
        assert "Device evidence: require" in caplog.text and "NOT CHECKED" in caplog.text


def test_a_state_dir_that_takes_no_key_still_serves(tmp_path, android, monkeypatch) -> None:
    def refuse(_dir):
        raise OSError(30, "Read-only file system")
    monkeypatch.setattr("recto.bootloader.server.ensure_test_code_key", refuse)
    with serving(tmp_path, device_policy=android.policy()) as c:
        assert HwPhone().register(c, vendor=android)[0] == 201
        with pytest.raises(dc.TestCodeRefused):
            dc.issue(tmp_path, plane="member", label="x")
