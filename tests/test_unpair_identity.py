"""Hard rule 14.11: an unpairing the bootloader relays is signed by the phone's identity key too."""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import replace
from typing import Any

import pytest

pytest.importorskip("cryptography")

from recto.bootloader import device_evidence as de  # noqa: E402
from recto.bootloader.server import BootloaderHandler  # noqa: E402
from recto.capability.grant_receipt import grant_digest_hex  # noqa: E402
from recto.capability.jwt import parse_jws, signing_input_digest, verify_jws  # noqa: E402
from recto.capability.pair_record import UNPAIR_RESULT_ACTION, unpair_payload  # noqa: E402
from recto.capability.signing import public_key_hex  # noqa: E402
from tests import test_grant_approved_here as grants  # noqa: E402
from tests.test_bootloader_devices_unpair import _FakeConsumerHandler, fake_consumer  # noqa: E402, F401
from tests.test_bootloader_owner_slots import CONSUMER, _member_challenge, _subject, serving  # noqa: E402
from tests.test_bootloader_slots import Phone, _http  # noqa: E402

KEY = secrets.token_bytes(32)
PIN = bytes.fromhex(public_key_hex(KEY))


def _serve(tmp_path: Any, consumer: Any, mode: str = "record", **kw: Any):
    kw.setdefault("devices_pair_signing_key", KEY)
    kw.setdefault("capability_operator_pubkey", grants.PUB)
    return serving(tmp_path, device_policy=de.DevicePolicy(mode="record", unpair_mode=mode),
                   devices_pair_consumer_webhook_tokens={consumer["base_url"]: "token"}, **kw)


def _grant() -> str:
    claims = replace(grants._starter_claims(), aud=["consumer-app"], jti=secrets.token_hex(4))
    return grants._mint_jws(claims, grants.PRIV)


def _signed(phone: Phone, jws: str, *, signer: Any = None, bid: str | None = None, ref: str | None = None) -> dict[str, str]:
    payload = unpair_payload(bid or BootloaderHandler.config.bootloader_id, ref or phone.ref, signing_input_digest(jws))
    return {"phone_id": phone.ref, "identity_signature_b64u": grants._b64u((signer or phone).identity.sign(payload))}


def _unpair(c: Any, consumer: Any, jws: str, extra: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    return _http("POST", f"{c['base_url']}/v0.4/devices/unpair", {
        "consumer_base_url": consumer["base_url"], "user_pubkey_hex": grants.PUB.hex(), "user_jws": jws, **(extra or {})})


def _relayed(consumer: Any) -> dict[str, Any]:
    return consumer["received"][-1]["body"]


def _word(consumer: Any, jws: str) -> dict[str, Any]:
    told = _relayed(consumer)["bootloaderJws"]
    verify_jws(told, expected_pubkey=PIN, expected_aud="consumer-app")
    payload = parse_jws(told)[1]
    assert payload["cap"]["allow_actions"] == [UNPAIR_RESULT_ACTION] and payload["exp"] - payload["iat"] == 300
    assert payload["cap"]["scope"]["payload_sha256"] == grant_digest_hex(jws) and payload["max_uses"] == 1
    assert payload["iss"] == f"bootloader:{BootloaderHandler.config.bootloader_id}"
    return payload


@pytest.mark.parametrize("mode", ["record", "require"])
def test_an_owners_unpairing_goes_on_with_this_bootloaders_word(tmp_path, fake_consumer, mode) -> None:  # noqa: F811
    with _serve(tmp_path, fake_consumer, mode) as c:
        owner, jws = Phone("owner"), _grant()
        assert owner.register(c)[0] == 201
        assert _unpair(c, fake_consumer, jws, _signed(owner, jws))[0] == 200
        assert set(_relayed(fake_consumer)) == {"masterPubkeyHex", "capabilityJws", "bootloaderJws"}
        payload = _word(fake_consumer, jws)
        assert (payload["sub"], payload["cap"]["scope"]["approved_slot"]) == ("owner", "primary")
        assert owner.ref not in str(payload) and owner.pub not in str(payload)


def test_a_members_unpairing_names_its_subject_here_and_no_other(tmp_path, fake_consumer) -> None:  # noqa: F811
    with _serve(tmp_path, fake_consumer, "require") as c:
        member, jws = Phone("member"), _grant()
        assert member.register(c, challenge=_member_challenge(c, "m"))[0] == 201
        held = c["state"].get_phone(member.ref)
        status, body = _unpair(c, fake_consumer, jws, _signed(member, jws))
        assert (status, body["reason"]) == (403, "unbound"), "bound at another consumer"
        c["state"].register_phone(replace(held, member_bindings=((CONSUMER, _subject("m")), (fake_consumer["base_url"] + "/", _subject("m")))))
        assert _unpair(c, fake_consumer, jws, _signed(member, jws))[0] == 200
        payload = _word(fake_consumer, jws)
        assert (payload["sub"], payload["cap"]["scope"]["approved_slot"]) == (f"user:{_subject('m')}", "member")


@pytest.mark.parametrize("operator", [grants.PUB, None])
def test_an_owners_phone_stands_in_for_no_member(tmp_path, fake_consumer, operator) -> None:  # noqa: F811
    """A member's stolen phrase and the owner's own phone: the owner's word is about the owner's key."""
    with _serve(tmp_path, fake_consumer, "require", capability_operator_pubkey=operator) as c:
        owner = Phone("owner")
        assert owner.register(c)[0] == 201
        priv = grants.act._keypair()[0] if operator else grants.PRIV
        jws = grants._mint_jws(replace(grants._starter_claims(), aud=["consumer-app"], jti="m"), priv)
        status, body = _unpair(c, fake_consumer, jws, _signed(owner, jws))
        assert (status, body["reason"]) == (403, "not_the_owners")
        assert fake_consumer["received"] == []


def _wrong(name: str, owner: Phone, jws: str) -> dict[str, Any]:
    other = Phone("other")
    good = _signed(owner, jws)
    return {
        "missing": {}, "no signature": {"phone_id": owner.ref}, "no phone": {"identity_signature_b64u": good["identity_signature_b64u"]},
        "a stranger's phone": _signed(other, jws), "another key": _signed(owner, jws, signer=other),
        "another unpairing's": _signed(owner, _grant()), "another bootloader's": _signed(owner, jws, bid="rb1-other"),
        "another phone's id signed": _signed(owner, jws, ref=other.ref), "not a string": {"phone_id": owner.ref, "identity_signature_b64u": 5},
        "garbled": {**good, "identity_signature_b64u": "!!!"}, "a list for an id": {**good, "phone_id": [owner.ref]},
    }[name]


NAMES = {"missing": "missing", "no signature": "missing", "no phone": "missing", "a stranger's phone": "unknown_phone", "another key": "signature",
         "another unpairing's": "signature", "another bootloader's": "signature", "another phone's id signed": "signature",
         "not a string": "unknown_phone", "garbled": "signature", "a list for an id": "unknown_phone"}


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("mode", ["off", "record", "require"])
def test_one_that_is_not_the_phones(tmp_path, fake_consumer, caplog, name, mode) -> None:  # noqa: F811
    caplog.set_level(logging.DEBUG)
    with _serve(tmp_path, fake_consumer, mode) as c:
        owner, jws = Phone("owner"), _grant()
        assert owner.register(c)[0] == 201
        extra = _wrong(name, owner, jws)
        status, body = _unpair(c, fake_consumer, jws, extra)
        if mode == "require":
            assert (status, body["error"], body["reason"]) == (403, "unpair_identity_required", NAMES[name]), body
            time.sleep(0.2)     # a relay after the refusal would be under way
            assert fake_consumer["received"] == [], "nothing reached the consumer"
        else:
            assert status == 200 and set(_relayed(fake_consumer)) == {"masterPubkeyHex", "capabilityJws"}, "as it was before"
        said = [r.getMessage() for r in caplog.records if "unpairing is not the phone's" in r.getMessage()]
        assert said == ([] if mode == "off" else [f"an unpairing is not the phone's: {NAMES[name]}"])
        for r in caplog.records:
            assert jws[:40] not in r.getMessage() and fake_consumer["base_url"] not in r.getMessage()


def test_off_looks_at_nothing_even_when_it_is_there(tmp_path, fake_consumer) -> None:  # noqa: F811
    with _serve(tmp_path, fake_consumer, "off") as c:
        owner, jws = Phone("owner"), _grant()
        assert owner.register(c)[0] == 201
        assert _unpair(c, fake_consumer, jws, _signed(owner, jws))[0] == 200
        assert "bootloaderJws" not in _relayed(fake_consumer)


@pytest.mark.parametrize("bad", ["a.b.c", "nope", "é.é.é"])
def test_a_grant_that_does_not_read(tmp_path, fake_consumer, bad) -> None:  # noqa: F811
    with _serve(tmp_path, fake_consumer, "require") as c:
        owner = Phone("owner")
        assert owner.register(c)[0] == 201
        status, body = _unpair(c, fake_consumer, bad, {"phone_id": owner.ref, "identity_signature_b64u": "AA"})
        assert (status, body["reason"]) == (403, "malformed")


def test_a_bootloader_with_no_signing_key_still_asks_and_has_no_word(tmp_path, fake_consumer) -> None:  # noqa: F811
    with _serve(tmp_path, fake_consumer, "require", devices_pair_signing_key=None) as c:
        owner, jws = Phone("owner"), _grant()
        assert owner.register(c)[0] == 201
        assert _unpair(c, fake_consumer, jws)[0] == 403
        assert _unpair(c, fake_consumer, jws, _signed(owner, jws))[0] == 200
        assert "bootloaderJws" not in _relayed(fake_consumer)


def test_a_revoked_phone_signs_nothing_more(tmp_path, fake_consumer) -> None:  # noqa: F811
    with _serve(tmp_path, fake_consumer, "require") as c:
        owner, jws = Phone("owner"), _grant()
        assert owner.register(c)[0] == 201
        c["state"].revoke_phone(owner.ref)
        assert _unpair(c, fake_consumer, jws, _signed(owner, jws))[1]["reason"] == "unknown_phone"


def test_the_mode_is_its_own_and_records_by_default() -> None:
    assert de.DevicePolicy.from_env({}).unpair_mode == "record"
    assert [de.DevicePolicy.from_env({"RECTO_UNPAIR_IDENTITY_MODE": m}).unpair_mode for m in ("off", " Require ", "")] == ["off", "require", "record"]
    with pytest.raises(ValueError, match="RECTO_UNPAIR_IDENTITY_MODE"):
        de.DevicePolicy.from_env({"RECTO_UNPAIR_IDENTITY_MODE": "recrod"})
