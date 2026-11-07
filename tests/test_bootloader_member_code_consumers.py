"""A member code is minted only for a consumer the agent's own entry names.

The member plane (2026-09-30) lets a consumer's agent mint a MEMBER pairing code by naming who it is for:
``{"member_of": {"consumer": <base url>, "subject": <opaque handle>}}`` on ``POST /v0.4/pairing/code``. The phone
that code buys is bound to that (consumer, subject) pair (hard rule 15.n), so the consumer half must be the agent's
own: an agent's entry names the consumers it mints member codes for (``member_consumers`` in agents.json), and a
code for any other consumer - or from an agent whose entry names none - is refused by name and never issued.

The consumer is compared as the pair relay compares it: surrounding space and one trailing slash do not matter,
anything else does. The owner's codes (``may_mint_owner_codes``) are untouched.

POSITIVE CONTROL: ``test_an_agent_mints_a_member_code_for_its_own_consumer``.
"""

from __future__ import annotations

import base64
import hashlib
import threading
from typing import Any

import pytest

from recto.bootloader.server import ChallengeStore, create_server

from tests.test_bootloader_slots import _http

AGENT_ID, AGENT_TOKEN = "consumer-agent", "consumer-token-fixture"
OTHER_ID, OTHER_TOKEN = "other-agent", "other-token-fixture"
BARE_ID, BARE_TOKEN = "bare-agent", "bare-token-fixture"
OWNER_ID, OWNER_TOKEN = "owner-console", "owner-token-fixture"
CONSUMER = "https://consumer.example"
OTHER_CONSUMER = "https://other.example"


def _subject(name: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(name.encode()).digest()).rstrip(b"=").decode("ascii")


@pytest.fixture
def ctx(tmp_path):
    from recto.bootloader.state import StateStore

    state = StateStore(state_dir=tmp_path)
    challenges = ChallengeStore(state=state)
    issued: list[Any] = []
    real = challenges.issue_member_pairing_code

    def counted(**kw: Any) -> Any:
        issued.append(kw)
        return real(**kw)

    challenges.issue_member_pairing_code = counted  # type: ignore[method-assign]
    server = create_server(
        bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="member-consumers-test",
        challenges=challenges, ssl_context=None,
        capability_agent_tokens={AGENT_ID: AGENT_TOKEN, OTHER_ID: OTHER_TOKEN, BARE_ID: BARE_TOKEN,
                                 OWNER_ID: OWNER_TOKEN},
        owner_code_minters={OWNER_ID},
        member_code_consumers={AGENT_ID: [CONSUMER + "/"], OTHER_ID: [OTHER_CONSUMER]},
    )
    host, port = server.server_address
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield {"base_url": f"http://{host}:{port}", "issued": issued}
    finally:
        server.shutdown()
        server.server_close()


def _mint(ctx, agent: tuple[str, str], body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    return _http("POST", f"{ctx['base_url']}/v0.4/pairing/code", body,
                 headers={"X-Recto-Agent-Id": agent[0], "X-Recto-Agent-Token": agent[1]})


def _member(consumer: str, user: str = "member-1") -> dict[str, Any]:
    return {"member_of": {"consumer": consumer, "subject": _subject(user)}}


# --------------------------------------------------------------------------
# the route
# --------------------------------------------------------------------------

def test_an_agent_mints_a_member_code_for_its_own_consumer(ctx) -> None:
    """POSITIVE CONTROL - and the entry's trailing slash does not matter."""
    status, body = _mint(ctx, (AGENT_ID, AGENT_TOKEN), _member(CONSUMER))
    assert status == 200, body
    assert body["plane"] == "member" and body["code"]
    assert len(ctx["issued"]) == 1


@pytest.mark.parametrize("spelling", [CONSUMER + "/", "  " + CONSUMER + "  "])
def test_the_consumers_trailing_slash_and_spaces_do_not_matter(ctx, spelling: str) -> None:
    status, body = _mint(ctx, (AGENT_ID, AGENT_TOKEN), _member(spelling))
    assert status == 200, body
    assert body["plane"] == "member"


@pytest.mark.parametrize("consumer", [
    OTHER_CONSUMER,                     # another agent's consumer
    "https://consumer.example.evil",    # a longer host
    "http://consumer.example",          # another scheme
    "https://CONSUMER.example",         # case is part of the name the binding keeps
    CONSUMER + "/path",                 # a path
])
def test_a_member_code_for_another_consumer_is_refused_and_never_issued(ctx, consumer: str) -> None:
    status, body = _mint(ctx, (AGENT_ID, AGENT_TOKEN), _member(consumer))
    assert status == 403, body
    assert body["error"] == "member_consumer_not_allowed"
    assert "code" not in body
    assert ctx["issued"] == [], "a refused mint still issued a code"


def test_the_refusal_names_no_consumer_the_agent_may_use(ctx) -> None:
    status, body = _mint(ctx, (AGENT_ID, AGENT_TOKEN), _member(OTHER_CONSUMER))
    assert status == 403
    assert "consumer.example" not in str(body)


def test_an_agent_whose_entry_names_no_consumer_mints_no_member_code(ctx) -> None:
    status, body = _mint(ctx, (BARE_ID, BARE_TOKEN), _member(CONSUMER))
    assert status == 403, body
    assert body["error"] == "member_consumer_not_allowed"
    assert ctx["issued"] == []


def test_each_agent_is_held_to_its_own_list(ctx) -> None:
    assert _mint(ctx, (OTHER_ID, OTHER_TOKEN), _member(OTHER_CONSUMER))[0] == 200
    assert _mint(ctx, (OTHER_ID, OTHER_TOKEN), _member(CONSUMER))[0] == 403


def test_a_bootloader_with_no_list_mints_no_member_code(tmp_path) -> None:
    """Fail closed: with nothing configured, no agent mints a member code."""
    from recto.bootloader.state import StateStore

    state = StateStore(state_dir=tmp_path)
    server = create_server(bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="no-list",
                           challenges=ChallengeStore(state=state), ssl_context=None,
                           capability_agent_tokens={AGENT_ID: AGENT_TOKEN})
    host, port = server.server_address
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        status, body = _http("POST", f"http://{host}:{port}/v0.4/pairing/code", _member(CONSUMER),
                             headers={"X-Recto-Agent-Id": AGENT_ID, "X-Recto-Agent-Token": AGENT_TOKEN})
        assert status == 403 and body["error"] == "member_consumer_not_allowed", body
    finally:
        server.shutdown()
        server.server_close()


def test_the_owners_code_is_unchanged(ctx) -> None:
    """An owner-flagged agent with no member list still mints the owner's code (no member_of)."""
    status, body = _mint(ctx, (OWNER_ID, OWNER_TOKEN), {})
    assert status == 200, body
    assert "plane" not in body


def test_a_malformed_member_of_is_still_refused_by_its_own_name(ctx) -> None:
    status, body = _mint(ctx, (AGENT_ID, AGENT_TOKEN), {"member_of": {"consumer": CONSUMER, "subject": "short"}})
    assert status == 400 and body["error"] == "subject_invalid", body


def test_create_server_refuses_a_malformed_list(tmp_path) -> None:
    from recto.bootloader.state import StateStore

    for bad in ({AGENT_ID: []}, {AGENT_ID: [""]}, {AGENT_ID: "https://consumer.example"}, {AGENT_ID: [7]}):
        state = StateStore(state_dir=tmp_path)
        with pytest.raises(ValueError, match="member_code_consumers"):
            create_server(bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="bad-list",
                          challenges=ChallengeStore(state=state), ssl_context=None,
                          capability_agent_tokens={AGENT_ID: AGENT_TOKEN}, member_code_consumers=bad)


# --------------------------------------------------------------------------
# the launcher: agents.json's member_consumers, and the single-agent twin
# --------------------------------------------------------------------------

def test_the_manifests_member_consumers_reach_the_server(monkeypatch, tmp_path) -> None:
    from tests.test_capability_consumer_actions import _launcher_kwargs

    rc, kw = _launcher_kwargs(monkeypatch, tmp_path, [
        {"agent_id": "a", "token_env": "POLICY_TEST_TOKEN_A", "member_consumers": [CONSUMER + "/", " " + OTHER_CONSUMER]},
        {"agent_id": "b", "token_env": "POLICY_TEST_TOKEN_B"},
    ])
    assert rc is None, "the launcher stopped before create_server"
    assert kw["member_code_consumers"] == {"a": [CONSUMER, OTHER_CONSUMER]}


@pytest.mark.parametrize("bad", [[], [""], "https://consumer.example", [7]])
def test_a_malformed_member_consumers_stops_startup(monkeypatch, tmp_path, capsys, bad) -> None:
    from tests.test_capability_consumer_actions import _launcher_kwargs

    rc, kw = _launcher_kwargs(monkeypatch, tmp_path, [
        {"agent_id": "a", "token_env": "POLICY_TEST_TOKEN_A", "member_consumers": bad},
    ])
    assert rc == 2 and kw is None
    assert "agent 'a': member_consumers must be" in capsys.readouterr().err


def test_the_single_agent_twin_reaches_the_server(monkeypatch, tmp_path) -> None:
    import tests.test_capability_consumer_actions as tcca
    from tests.test_bootloader_owner_slots import _runner_env

    rbc = _runner_env(monkeypatch, tmp_path, RECTO_AGENT_ID="solo", RECTO_AGENT_TOKEN="c" * 64,
                      RECTO_AGENT_MEMBER_CONSUMERS=f"{CONSUMER}/, {OTHER_CONSUMER}")

    def fake_create_server(**kwargs: Any) -> None:
        raise tcca._CreateServerCalled(kwargs)

    monkeypatch.setattr(rbc, "create_server", fake_create_server)
    with pytest.raises(tcca._CreateServerCalled) as reached:
        rbc.main()
    assert reached.value.kwargs["member_code_consumers"] == {"solo": [CONSUMER, OTHER_CONSUMER]}
