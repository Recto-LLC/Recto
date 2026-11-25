"""The card queue's caps: what an agent may put in front of a person.

Open cards are capped per agent and signed subject and per phone, and asks per minute, refused 429 by name; a card has
a life, its fields are text and have lengths, refused 400 by name; a request that asks exactly what an open card asks is
answered with that card; and the app a card names is the authenticated agent's, whatever the request body says. The
bootloader's own cards are never refused by a cap.
"""

from __future__ import annotations

import base64
import json
import threading
import time
import uuid
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from recto.bootloader import server as server_module
from recto.bootloader.server import (
    MAX_CARD_DESCRIPTION_CHARS,
    MAX_CARD_LIST_ITEMS,
    MAX_CARD_PURPOSE_CHARS,
    MAX_CARD_RAISES_PER_MINUTE,
    MAX_CARD_TEXT_CHARS,
    MAX_OPEN_CARDS_PER_AGENT,
    MAX_OPEN_CARDS_PER_PHONE,
    MIN_CARD_LIFE_SECONDS,
    OPEN_CARDS_RESERVE,
    BootloaderHandler,
    ChallengeStore,
    create_server,
)
from recto.bootloader.state import AppContext, PhoneRegistration, StateStore
from recto.capability.types import CapabilityClaims, CapabilityClause, CapabilityLimits, CapabilityScope

AGENTS = {"agent-one": "token-one", "agent-two": "token-two", "vault-only": "token-three"}


class _Wakes:
    def __init__(self) -> None:
        self.sent: list[str] = []

    def notify(self, phone: Any, request_id: str) -> None:
        self.sent.append(request_id)


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _pub(key: Ed25519PrivateKey) -> str:
    return _b64u(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


@pytest.fixture()
def ctx(tmp_path: Path):
    state = StateStore(state_dir=tmp_path)
    poll = Ed25519PrivateKey.generate()
    phones = [state.register_phone(PhoneRegistration.new(
        device_label=f"phone {n}", public_key_b64u=_pub(Ed25519PrivateKey.generate()),
        supported_algorithms=("ed25519",), poll_public_key_b64u=_pub(poll))) for n in (1, 2)]
    wakes = _Wakes()
    server = create_server(
        bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="card-queue-test", challenges=ChallengeStore(),
        ssl_context=None, capability_agent_tokens=AGENTS, capability_agent_auth_only={"vault-only"},
        push_dispatcher=wakes, max_open_cards_per_agent=3, max_open_cards_per_phone=5,
        principal_apps={"agent-one": AppContext(app_id="one", app_name="App One")},
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield {"base": "http://{}:{}".format(*server.server_address), "state": state, "phone": phones[0].phone_id,
               "other": phones[1].phone_id, "poll": poll, "wakes": wakes}
    finally:
        server.shutdown()
        server.server_close()


def _claims(jti: str | None = None, *, exp_in: int = 600, **over: Any) -> dict[str, Any]:
    now = int(time.time())
    claims = CapabilityClaims(
        iss="phone:operator:enclave", sub="agent:one", aud=["consumer-app"], iat=now, nbf=now, exp=now + exp_in,
        jti=jti or f"cap-{uuid.uuid4().hex}",
        cap=CapabilityClause(tier=1, registry_version="v1", scope=CapabilityScope(), allow_actions=["example:act"],
                             limits=CapabilityLimits()),
        purpose="run one act", max_uses=1)
    return asdict(replace(claims, **over))


def _post(ctx, path: str, body: dict[str, Any], *, agent: str = "agent-one",
          headers: dict[str, str] | None = None) -> tuple[int, dict]:
    hdr = {"Content-Type": "application/json"}
    if agent:
        hdr.update({"X-Recto-Agent-Id": agent, "X-Recto-Agent-Token": AGENTS[agent]})
    hdr.update(headers or {})
    req = urlrequest.Request(ctx["base"] + path, data=json.dumps(body).encode(), method="POST", headers=hdr)
    try:
        with urlrequest.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _ask(ctx, claims: dict[str, Any] | None = None, *, agent: str = "agent-one", phone: str | None = None,
         **body: Any) -> tuple[int, dict]:
    return _post(ctx, "/v0.4/capability/request",
                 {"phone_id": phone or ctx["phone"], "claims": claims or _claims(), **body}, agent=agent)


def _pending(ctx, phone: str | None = None) -> list[dict]:
    with urlrequest.urlopen(f"{ctx['base']}/v0.4/pending?phone_id={phone or ctx['phone']}", timeout=10) as r:
        return json.loads(r.read())["requests"]


# ---- the caps ----------------------------------------------------------------------------------------------------

def test_the_shipped_caps_leave_room_for_ordinary_work() -> None:
    assert MAX_OPEN_CARDS_PER_AGENT >= 10
    assert MAX_OPEN_CARDS_PER_PHONE >= 2 * MAX_OPEN_CARDS_PER_AGENT
    assert MAX_CARD_PURPOSE_CHARS >= 900
    assert OPEN_CARDS_RESERVE == 8 and MAX_CARD_RAISES_PER_MINUTE >= 2 * MAX_OPEN_CARDS_PER_AGENT
    assert MIN_CARD_LIFE_SECONDS <= 30   # the shortest grant window a request may declare


def test_an_agent_holds_its_limit_of_open_cards_and_no_more(ctx) -> None:
    ids = []
    for _ in range(3):
        status, body = _ask(ctx)
        assert status == 201, body
        ids.append(body["request_id"])
    status, body = _ask(ctx)
    assert status == 429 and body["error"] == "agent_cards_open_limit", body
    assert (body["open"], body["limit"], body["bound"]) == (3, 3, "agent_subject")
    assert len(_pending(ctx)) == 3 and len(ctx["wakes"].sent) == 3

    # Another agent, and this agent on another phone, are their own counts.
    assert _ask(ctx, agent="agent-two")[0] == 201
    assert _ask(ctx, phone=ctx["other"])[0] == 201

    # One answered card is one more asked.
    ctx["state"].take_pending(ids[0])
    assert _ask(ctx)[0] == 201


def test_the_agents_limit_is_counted_for_each_signed_subject(ctx) -> None:
    """One platform asks for many people and agents under one agent id: one of them at its limit stops no other."""
    for _ in range(3):
        assert _ask(ctx)[0] == 201
    assert _ask(ctx)[0] == 429
    status, body = _ask(ctx, _claims(sub="agent:two@user:one"))
    assert status == 201, body


def test_a_phone_holds_its_limit_of_open_cards_from_every_agent(ctx) -> None:
    for agent in ("agent-one", "agent-one", "agent-one", "agent-two", "agent-two"):
        assert _ask(ctx, agent=agent)[0] == 201
    status, body = _ask(ctx, agent="agent-two")
    assert status == 429 and body["error"] == "phone_cards_open_limit", body
    assert (body["open"], body["limit"], body["bound"]) == (5, 5, "phone")


def test_a_subject_with_no_open_card_is_heard_on_a_full_phone_up_to_the_reserve(ctx) -> None:
    for agent in ("agent-one", "agent-one", "agent-one", "agent-two", "agent-two"):
        assert _ask(ctx, agent=agent)[0] == 201
    for n in range(OPEN_CARDS_RESERVE):
        status, body = _ask(ctx, _claims(sub=f"agent:fresh-{n}"))
        assert status == 201, (n, body)
    status, body = _ask(ctx, _claims(sub="agent:one-more"))
    assert status == 429 and body["error"] == "phone_cards_open_limit", body
    assert (body["open"], body["limit"], body["bound"]) == (13, 13, "phone_reserve")
    # A subject already heard there is held to the total, not the reserve.
    status, body = _ask(ctx, _claims(sub="agent:fresh-0"))
    assert status == 429 and (body["limit"], body["bound"]) == (5, "phone"), body


def test_the_bootloaders_own_cards_are_never_refused(ctx) -> None:
    """An owner's card goes on a full queue: the caps are the agents'."""
    for agent in ("agent-one", "agent-one", "agent-one", "agent-two", "agent-two"):
        assert _ask(ctx, agent=agent)[0] == 201
    handler = BootloaderHandler.__new__(BootloaderHandler)
    cards = handler._card_devices("act-test", "an act", b"0" * 32, [ctx["state"].get_phone(ctx["phone"])])
    assert len(cards) == 1
    assert len(ctx["state"].list_pending_for_phone(ctx["phone"])) == 6


def test_a_card_whose_authority_ran_out_is_not_open(ctx) -> None:
    """The phone may not have polled since; the card is dead all the same."""
    for _ in range(3):
        assert _ask(ctx)[0] == 201
    for p in ctx["state"].list_pending_for_phone(ctx["phone"]):
        claims = json.loads(base64.urlsafe_b64decode(p.cap_payload_b64 + "=" * (-len(p.cap_payload_b64) % 4)))
        claims["exp"] = int(time.time()) - 1
        ctx["state"].add_pending(replace(p, cap_payload_b64=_b64u(json.dumps(claims).encode())))
    assert _ask(ctx)[0] == 201
    assert len(ctx["state"].list_pending_for_phone(ctx["phone"])) == 1   # the lapsed ones left the queue


@pytest.mark.parametrize("exp_in,ttl", [(1, 86400), (MIN_CARD_LIFE_SECONDS - 1, 3600)])
def test_a_card_with_too_little_life_is_refused(ctx, exp_in, ttl) -> None:
    status, body = _ask(ctx, _claims(exp_in=exp_in), ttl_seconds=ttl)
    assert status == 400 and body["error"] == "card_life_too_short", body
    assert body["minimum"] == MIN_CARD_LIFE_SECONDS
    assert ctx["state"].list_pending_for_phone(ctx["phone"]) == [] and ctx["wakes"].sent == []


def test_a_sixty_second_card_and_a_stamped_window_are_admitted(ctx) -> None:
    assert _ask(ctx, _claims(exp_in=60), ttl_seconds=60)[0] == 201
    assert _ask(ctx, _claims(exp_in=MIN_CARD_LIFE_SECONDS + 5))[0] == 201
    assert _ask(ctx, _claims(exp_in=5), grant_ttl_seconds=30)[0] == 201   # the window has not begun


def test_an_agent_asks_for_one_subject_so_often_a_minute(ctx) -> None:
    claims = _claims("cap-loop")
    for n in range(MAX_CARD_RAISES_PER_MINUTE):
        assert _ask(ctx, claims)[0] == 201, n
    status, body = _ask(ctx, claims)
    assert status == 429 and body["error"] == "card_raise_rate_limit", body
    assert (body["limit"], body["bound"]) == (MAX_CARD_RAISES_PER_MINUTE, "agent_subject_minute")
    assert 1 <= body["retry_after_seconds"] <= 60
    assert len(ctx["wakes"].sent) == MAX_CARD_RAISES_PER_MINUTE
    # Another subject, and another agent, are their own counts.
    assert _ask(ctx, _claims(sub="agent:two"))[0] == 201
    assert _ask(ctx, agent="agent-two")[0] == 201


def test_a_minute_later_the_agent_asks_again() -> None:
    from recto.bootloader.server import CardRaises

    now = [1000.0]
    raises = CardRaises(limit=2, clock=lambda: now[0])
    key = ("agent-one", "agent:one")
    raises.note(key)
    now[0] += 30
    raises.note(key)
    assert raises.wait_seconds(key) == 31 and raises.wait_seconds(("agent-one", "agent:two")) == 0
    now[0] += 30
    assert raises.wait_seconds(key) == 0   # the first is a minute old
    raises.note(key)
    assert raises.wait_seconds(key) == 31
    now[0] += 120
    assert raises.wait_seconds(key) == 0 and raises._at == {}


def test_a_refused_ask_is_not_counted(ctx) -> None:
    for _ in range(3):
        assert _ask(ctx)[0] == 201
    for _ in range(MAX_CARD_RAISES_PER_MINUTE + 1):
        assert _ask(ctx)[1]["error"] == "agent_cards_open_limit"


def test_a_queued_card_whose_window_is_stamped_at_open_stays_open(ctx) -> None:
    """grant_ttl_seconds: the queue-time window is a placeholder, so it running out does not free a place."""
    for _ in range(3):
        assert _ask(ctx, grant_ttl_seconds=600)[0] == 201
    for p in ctx["state"].list_pending_for_phone(ctx["phone"]):
        claims = json.loads(base64.urlsafe_b64decode(p.cap_payload_b64 + "=" * (-len(p.cap_payload_b64) % 4)))
        claims["exp"] = int(time.time()) - 1
        ctx["state"].add_pending(replace(p, cap_payload_b64=_b64u(json.dumps(claims).encode())))
    assert _ask(ctx, grant_ttl_seconds=600)[0] == 429


def test_two_requests_at_once_never_pass_the_cap(ctx) -> None:
    results: list[int] = []
    threads = [threading.Thread(target=lambda: results.append(_ask(ctx)[0])) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == [201] * 3 + [429] * 7


@pytest.mark.parametrize("cap", [0, -1, "12", True, None])
def test_a_cap_is_a_whole_number_and_never_off(tmp_path, cap) -> None:
    from recto.bootloader import BootloaderError

    with pytest.raises(BootloaderError, match="max_open_cards_per_agent"):
        create_server(bind_host="127.0.0.1", bind_port=0, state=StateStore(state_dir=tmp_path),
                      bootloader_id="caps", challenges=ChallengeStore(), max_open_cards_per_agent=cap)


# ---- one card for one ask ------------------------------------------------------------------------------------------

def test_an_identical_open_request_is_answered_with_its_card(ctx) -> None:
    claims = _claims("cap-same")
    status, first = _ask(ctx, claims)
    assert status == 201
    status, again = _ask(ctx, claims)
    assert status == 201 and again["status"] == "already_open", again
    assert again["request_id"] == first["request_id"] and "status" not in first
    assert again["result_url"] == first["result_url"] == f"/v0.4/capability/result/{first['request_id']}"
    assert len(_pending(ctx)) == 1
    assert ctx["wakes"].sent == [first["request_id"]] * 2   # the phone may have missed the first


def test_a_card_stamped_at_open_is_still_the_same_ask(ctx) -> None:
    claims = _claims("cap-stamped")
    first = _ask(ctx, claims, grant_ttl_seconds=600)[1]
    _pending(ctx)   # the first read stamps the window
    later = dict(claims, iat=claims["iat"] + 5, nbf=claims["nbf"] + 5, exp=claims["exp"] + 5)
    status, again = _ask(ctx, later, grant_ttl_seconds=600)
    assert status == 201 and again["request_id"] == first["request_id"], again


@pytest.mark.parametrize("change", [
    {"purpose": "run another act"}, {"jti": "cap-other"}, {"max_uses": 2}, {"exp_in": 900},
])
def test_a_request_that_asks_anything_else_is_its_own_card(ctx, change) -> None:
    assert _ask(ctx, _claims("cap-a"))[0] == 201
    change = dict(change)
    jti = change.pop("jti", "cap-a")
    assert _ask(ctx, _claims(jti, **change))[0] == 201
    assert len(_pending(ctx)) == 2


def test_another_agents_identical_request_is_its_own_card(ctx) -> None:
    claims = _claims("cap-shared")
    a = _ask(ctx, claims)[1]
    status, b = _ask(ctx, claims, agent="agent-two")
    assert status == 201 and a["request_id"] != b["request_id"]


def test_an_answered_card_is_asked_again(ctx) -> None:
    claims = _claims("cap-again")
    first = _ask(ctx, claims)[1]
    ctx["state"].take_pending(first["request_id"])
    status, again = _ask(ctx, claims)
    assert status == 201 and again["request_id"] != first["request_id"]


# ---- the text -------------------------------------------------------------------------------------------------------

HALF = "x\ud800y"   # half of a surrogate pair: no UTF-8 spells it, and no phone reads it


@pytest.mark.parametrize("field,claims,body", [
    ("service", {}, {"service": {"a": 1}}),
    ("service", {}, {"service": ["a"]}),
    ("service", {}, {"service": 7}),
    ("service", {}, {"service": None}),
    ("secret", {}, {"secret": 7}),
    ("secret", {}, {"secret": True}),
    ("operation_description", {}, {"operation_description": HALF}),
    ("operation_description", {}, {"operation_description": None}),
    ("service", {}, {"service": HALF}),
    ("actor", {}, {"actor": {"actor_id": "agent:one", "actor_name": HALF}}),
    ("actor", {}, {"actor": {"actor_id": "agent:one", "actor_name": "One", "actor_icon_url": HALF}}),
    ("claims", {"purpose": HALF}, {}),
    ("claims", {"sub": HALF}, {}),
    ("claims", {"aud": ["a", HALF]}, {}),
    ("claims", {"cap": CapabilityClause(1, "v1", limits=CapabilityLimits(per_day={HALF: 1}))}, {}),
])
def test_every_field_that_reaches_the_phone_is_text(ctx, field, claims, body) -> None:
    good = _ask(ctx)[1]["request_id"]
    status, answer = _ask(ctx, _claims(**claims), **body)
    assert status == 400 and answer["error"] == "card_field_not_text", answer
    assert answer["field"] == field
    assert [r["request_id"] for r in _pending(ctx)] == [good]


def test_a_profile_cards_fields_are_text_too(ctx) -> None:
    for path, body in (
        ("/v0.4/profile/create", {"phone_id": ctx["phone"], "candidate_profile_id": "p", "kind": "work",
                                  "display_name": HALF}),
        ("/v0.4/profile/create", {"phone_id": ctx["phone"], "candidate_profile_id": "p", "kind": "work",
                                  "display_name": "Work", "theme_hint": 7}),
        ("/v0.4/profile/p-1/add-device", {"master_phone_id": ctx["phone"], "new_phone_id": ctx["other"],
                                          "service": {}}),
        ("/v0.4/profile/p-1/revoke-device", {"master_phone_id": ctx["phone"], "phone_id_to_revoke": ctx["other"],
                                             "revoker_label": HALF}),
    ):
        status, answer = _post(ctx, path, body)
        assert status == 400 and answer["error"] == "card_field_not_text", (path, answer)


@pytest.mark.parametrize("clause", [
    {"tier": None}, {"registry_version": None}, {"tier": "1"}, {"tier": True}, {"registry_version": 7},
    {"allow_actions": [7]}, {"limits": {"per_day": 3}},
])
def test_claims_the_card_could_not_show_are_refused_before_a_person_sees_them(ctx, clause) -> None:
    claims = _claims()
    claims["cap"] = dict(claims["cap"], **clause)
    status, body = _ask(ctx, claims)
    assert status == 400 and "claims failed" in body["detail"], body
    assert _pending(ctx) == []


@pytest.mark.parametrize("field", ["tier", "registry_version"])
def test_claims_without_a_tier_or_a_registry_version_are_refused(ctx, field) -> None:
    claims = _claims()
    claims["cap"] = {k: v for k, v in claims["cap"].items() if k != field}
    status, body = _ask(ctx, claims)
    assert status == 400 and field in body["detail"], body
    assert _pending(ctx) == []


@pytest.mark.parametrize("cap", [None, "text", ["a"], {"tier": 1, "registry_version": "v1", "scope": None}])
def test_a_clause_of_another_shape_is_refused_by_name(ctx, cap) -> None:
    status, body = _ask(ctx, dict(_claims(), cap=cap))
    assert status == 400 and "claims failed" in body["detail"], body


# ---- the lengths ----------------------------------------------------------------------------------------------------

def test_a_purpose_at_its_length_is_carded_and_past_it_is_refused(ctx) -> None:
    assert _ask(ctx, _claims(purpose="p" * 840))[0] == 201
    assert _ask(ctx, _claims(purpose="p" * MAX_CARD_PURPOSE_CHARS))[0] == 201
    status, body = _ask(ctx, _claims(purpose="p" * (MAX_CARD_PURPOSE_CHARS + 1)))
    assert status == 400 and body["error"] == "card_field_too_long", body
    assert (body["field"], body["limit"]) == ("claims.purpose", MAX_CARD_PURPOSE_CHARS)
    assert len(_pending(ctx)) == 2


_LONG = "x" * (MAX_CARD_TEXT_CHARS + 1)


@pytest.mark.parametrize("field,claims,body", [
    ("claims.sub", {"sub": _LONG}, {}),
    ("claims.jti", {"jti": _LONG}, {}),
    ("claims.aud", {"aud": ["a"] * (MAX_CARD_LIST_ITEMS + 1)}, {}),
    ("claims.aud", {"aud": [_LONG]}, {}),
    ("claims.cap.allow_actions", {"cap": CapabilityClause(1, "v1", allow_actions=["a"] * (MAX_CARD_LIST_ITEMS + 1))}, {}),
    ("claims.cap.scope.services", {"cap": CapabilityClause(1, "v1", scope=CapabilityScope(services=[_LONG]))}, {}),
    ("claims.cap.scope.target_user_id", {"cap": CapabilityClause(1, "v1", scope=CapabilityScope(target_user_id=_LONG))}, {}),
    ("claims.cap.limits.per_day", {"cap": CapabilityClause(1, "v1", limits=CapabilityLimits(per_day={_LONG: 1}))}, {}),
    ("claims.parent_cap", {"parent_cap": _LONG}, {}),
    ("operation_description", {}, {"operation_description": "d" * (MAX_CARD_DESCRIPTION_CHARS + 1)}),
    ("service", {}, {"service": _LONG}),
    ("actor.actor_name", {}, {"actor": {"actor_id": "agent:one", "actor_name": _LONG}}),
])
def test_every_field_of_a_card_has_a_length(ctx, field, claims, body) -> None:
    jti = claims.pop("jti", None) if isinstance(claims.get("jti"), str) else None
    status, answer = _ask(ctx, _claims(jti, **claims), **body)
    assert status == 400 and answer["error"] == "card_field_too_long", answer
    assert answer["field"] == field
    assert _pending(ctx) == []


def test_a_profile_cards_fields_have_lengths_too(ctx) -> None:
    for path, body in (
        ("/v0.4/profile/create", {"phone_id": ctx["phone"], "display_name": _LONG}),
        ("/v0.4/profile/p-1/add-device", {"master_phone_id": ctx["phone"], "new_phone_label": _LONG}),
        ("/v0.4/profile/p-1/revoke-device", {"master_phone_id": ctx["phone"], "revoker_label": _LONG}),
    ):
        status, answer = _post(ctx, path, body)
        assert status == 400 and answer["error"] == "card_field_too_long", (path, answer)


# ---- whose card it is -------------------------------------------------------------------------------------------------

def test_the_app_on_a_card_is_the_authenticated_agents(ctx) -> None:
    """The body's service is the requester's word: it picks no banner."""
    _ask(ctx, service="agent-one")
    _ask(ctx, agent="agent-two", service="agent-one")
    by_agent = {r["context"]["cap_agent_id"]: r["context"].get("app_context") for r in _pending(ctx)}
    assert by_agent["agent-one"]["app_name"] == "App One"
    assert by_agent["agent-two"] is None


def test_an_auth_only_agent_raises_no_card_of_any_kind(ctx) -> None:
    """Hard rule 15.p, at every route an agent's card reaches a phone by."""
    for path, body in (
        ("/v0.4/capability/request", {"phone_id": ctx["phone"], "claims": _claims()}),
        ("/v0.4/profile/create", {"phone_id": ctx["phone"], "candidate_profile_id": "p", "kind": "work",
                                  "display_name": "Work"}),
        ("/v0.4/profile/p-1/add-device", {"master_phone_id": ctx["phone"], "new_phone_id": ctx["other"]}),
        ("/v0.4/profile/p-1/revoke-device", {"master_phone_id": ctx["phone"], "phone_id_to_revoke": ctx["other"]}),
    ):
        status, answer = _post(ctx, path, body, agent="vault-only")
        assert status == 403 and answer["error"] == "agent_auth_only", (path, answer)
    assert _pending(ctx) == []


# ---- the push token -----------------------------------------------------------------------------------------------------

def _poll_headers(ctx, path: str) -> dict[str, str]:
    ts = int(time.time())
    signed = ctx["poll"].sign(f"{server_module.POLL_SIG_PREFIX}|{ctx['phone']}|{ts}|{path}".encode("ascii"))
    return {server_module.POLL_SIG_HEADER: _b64u(signed), server_module.POLL_SIG_TS_HEADER: str(ts)}


def test_the_push_token_moves_only_by_the_phones_own_signature(ctx) -> None:
    path = "/v0.4/manage/push_token"
    body = {"phone_id": ctx["phone"], "push_token": "stranger", "push_platform": "fcm"}
    status, answer = _post(ctx, path, body, agent="")
    assert status == 401 and answer["error"] == "poll_signature_required", answer
    bad = dict(_poll_headers(ctx, "/v0.4/pending"))   # a signature over another path
    status, answer = _post(ctx, path, body, agent="", headers=bad)
    assert status == 401 and answer["error"] == "poll_signature_invalid", answer
    assert ctx["state"].get_phone(ctx["phone"]).push_token is None

    status, answer = _post(ctx, path, dict(body, push_token="mine"), agent="", headers=_poll_headers(ctx, path))
    assert status == 200, answer
    assert ctx["state"].get_phone(ctx["phone"]).push_token == "mine"


# ---- the window is stamped once -----------------------------------------------------------------------------------------

def test_reads_that_arrive_together_are_served_one_window(ctx, monkeypatch) -> None:
    _ask(ctx, grant_ttl_seconds=600)
    card = ctx["state"].list_pending_for_phone(ctx["phone"])[0]
    handler = BootloaderHandler.__new__(BootloaderHandler)
    first = handler._restamp_grant_window(card)
    later = time.time() + 5
    monkeypatch.setattr(server_module.time, "time", lambda: later)
    second = handler._restamp_grant_window(card)   # the same un-stamped read, a moment later
    assert second.cap_payload_b64 == first.cap_payload_b64
    assert ctx["state"].list_pending_for_phone(ctx["phone"])[0].cap_payload_b64 == first.cap_payload_b64


def test_a_card_answered_between_the_read_and_the_stamp_is_not_put_back(ctx) -> None:
    _ask(ctx, grant_ttl_seconds=600)
    card = ctx["state"].list_pending_for_phone(ctx["phone"])[0]
    ctx["state"].take_pending(card.request_id)
    handler = BootloaderHandler.__new__(BootloaderHandler)
    assert handler._restamp_grant_window(card) is None
    assert ctx["state"].list_pending_for_phone(ctx["phone"]) == []


def test_a_card_taken_while_it_is_stamped_is_not_put_back(ctx, monkeypatch) -> None:
    rid = _ask(ctx, grant_ttl_seconds=600)[1]["request_id"]
    stamp = BootloaderHandler._stamp_grant_window

    def answered_meanwhile(self, req):
        ctx["state"].take_pending(req.request_id)
        return stamp(self, req)

    monkeypatch.setattr(BootloaderHandler, "_stamp_grant_window", answered_meanwhile)
    assert rid not in [r["request_id"] for r in _pending(ctx)]
    assert ctx["state"].list_pending_for_phone(ctx["phone"]) == []


def test_an_answer_waits_for_the_queue(ctx) -> None:
    """A card is taken under the lock its window is stamped under."""
    rid = _ask(ctx)[1]["request_id"]
    path = f"/v0.4/respond/{rid}"
    answers: list[int] = []
    deny = threading.Thread(target=lambda: answers.append(_post(
        ctx, path, {"phone_id": ctx["phone"], "decision": "denied"}, agent="", headers=_poll_headers(ctx, path))[0]))
    with BootloaderHandler._CARD_QUEUE_LOCK:
        deny.start()
        deny.join(1.0)
        assert answers == []
        assert [p.request_id for p in ctx["state"].list_pending_for_phone(ctx["phone"])] == [rid]
    deny.join(10.0)
    assert answers == [200]
    assert ctx["state"].list_pending_for_phone(ctx["phone"]) == []


# ---- one stored card is never the queue's ------------------------------------------------------------------------------

def _stored(ctx, request_id: str, payload: str, **over: Any) -> None:
    card = next(p for p in ctx["state"].list_pending_for_phone(ctx["phone"]) if p.request_id == request_id)
    ctx["state"].add_pending(replace(card, cap_payload_b64=_b64u(payload.encode()), **over))


@pytest.mark.parametrize("window", ["Infinity", "-Infinity", "NaN", "1e400", '"soon"', "null", "[]"])
def test_a_stored_window_that_cannot_be_read_fails_no_read_and_no_ask(ctx, window) -> None:
    bad, good = _ask(ctx)[1]["request_id"], _ask(ctx)[1]["request_id"]
    _stored(ctx, bad, '{"sub": "agent:one", "exp": %s}' % window)
    assert good in [r["request_id"] for r in _pending(ctx)]
    assert _ask(ctx)[0] == 201


def test_a_window_that_cannot_be_stamped_refuses_its_card_and_no_other(ctx) -> None:
    bad, good = (_ask(ctx, grant_ttl_seconds=600)[1]["request_id"] for _ in range(2))
    _stored(ctx, bad, '{"sub": "agent:one"}')
    assert [r["request_id"] for r in _pending(ctx)] == [good]
    assert [p.request_id for p in ctx["state"].list_pending_for_phone(ctx["phone"])] == [good]
    result = ctx["state"].get_capability_result(bad)
    assert (result.status, result.reason) == ("denied", "grant_window_unreadable")
    assert _ask(ctx)[0] == 201


@pytest.mark.parametrize("over", [{"requested_at_unix": float("inf")}, {"actor_context": {"actor_id": "agent:one"}},
                                  {"app_context": "text"}])
def test_a_stored_card_that_cannot_be_written_is_left_out_and_the_rest_served(ctx, over) -> None:
    bad, good = _ask(ctx)[1]["request_id"], _ask(ctx)[1]["request_id"]
    card = next(p for p in ctx["state"].list_pending_for_phone(ctx["phone"]) if p.request_id == bad)
    ctx["state"].add_pending(replace(card, **over))
    assert [r["request_id"] for r in _pending(ctx)] == [good]
    assert _ask(ctx)[0] == 201


def test_a_card_that_cannot_be_served_is_said_once_expires_and_holds_no_place(ctx, caplog) -> None:
    ids = [_ask(ctx)[1]["request_id"] for _ in range(3)]
    for card in ctx["state"].list_pending_for_phone(ctx["phone"]):
        ctx["state"].add_pending(replace(card, requested_at_unix=float("inf")))
    with caplog.at_level("WARNING", logger="recto.bootloader.pending"):
        for _ in range(3):
            assert _pending(ctx) == []
    assert sorted(r.args[0] for r in caplog.records if "not served" in r.msg) == sorted(ids)
    assert _ask(ctx)[0] == 201   # the three hold no place in this agent's limit
    lapsed = next(p for p in ctx["state"].list_pending_for_phone(ctx["phone"]) if p.request_id == ids[0])
    ctx["state"].add_pending(replace(lapsed, cap_payload_b64=_b64u(b'{"sub": "agent:one", "exp": 1}')))
    _pending(ctx)
    assert ids[0] not in [p.request_id for p in ctx["state"].list_pending_for_phone(ctx["phone"])]


def test_a_card_is_read_back_from_the_database_with_the_actor_it_was_written_with(ctx) -> None:
    from recto.bootloader.state_postgres import PostgresStateStore

    _ask(ctx, actor={"actor_id": "agent:one", "actor_name": "One"})
    card = ctx["state"].list_pending_for_phone(ctx["phone"])[0]
    read = PostgresStateStore._pending_from_doc(json.loads(json.dumps(asdict(card))))
    handler = BootloaderHandler.__new__(BootloaderHandler)
    assert handler._pending_to_wire(read) == handler._pending_to_wire(card)


@pytest.mark.parametrize("window", [float("inf"), "soon", [], None])
def test_a_window_an_ask_cannot_hold_is_refused_by_name(ctx, window) -> None:
    status, body = _ask(ctx, dict(_claims(), exp=window))
    assert status == 400 and "claims failed" in body["detail"], body


# ---- the phone reads every field this bootloader signs ----------------------------------------------------------------------

def test_the_phones_card_knows_every_field_the_claims_types_sign() -> None:
    """A field added to the claims types and not to the phone's card would be refused on every phone: the card signs
    only what it shows (hard rule 15.x). The two lists move together."""
    import re
    from dataclasses import fields

    source = (Path(__file__).resolve().parents[1] / "phone" / "Recto" / "Recto.Shared" / "Capability"
              / "CapabilityCardPayload.cs")
    if not source.exists():
        pytest.skip("the phone's source is not beside this checkout")
    text = source.read_text(encoding="utf-8")

    def known(block: str) -> set[str]:
        body = text[text.index(f"IReadOnlyDictionary<string, FieldCheck> {block} ="):]
        return set(re.findall(r'\["(\w+)"\] = ', body[:body.index("};")]))

    for block, types in (("PayloadFields", CapabilityClaims), ("CapFields", CapabilityClause),
                         ("ScopeFields", CapabilityScope), ("LimitFields", CapabilityLimits)):
        assert known(block) == {f.name for f in fields(types)}, block
