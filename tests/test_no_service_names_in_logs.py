"""Hard rule 15.ab: no log line names a service using Recto, or what it asked.

Owner ruling 2026-11-22: Recto records nothing of what a service asks or which
service asked. These tests capture every log record and all of stdout/stderr
across the paths that used to name one - the per-key ACL (admitted, denied,
audit, and its startup posture), the device pairing relay (an unknown
consumer, a relayed pairing, an unreachable consumer) and pairing-code
minting (owner and member) - and assert that no agent id, key name, service
name or consumer address appears.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path

import pytest

from tests.test_bootloader_connections import (
    AGENT_SERVICES,
    SVC_A_HDR,
    _get,
    _spawn,
    _upsert,
)
from tests.test_bootloader_devices_pair import (  # noqa: F401 - fixtures
    _body,
    _grant,
    _http_post_json,
    _pair_url,
    _record,
    bootloader,
    fake_consumer,
    phone,
)
from tests.test_bootloader_member_code_consumers import (  # noqa: F401 - fixture
    AGENT_ID,
    AGENT_TOKEN,
    CONSUMER,
    OWNER_ID,
    OWNER_TOKEN,
    _member,
    _mint,
    ctx,
)

KEY = "marker-key-omicron"
WILD_AGENT = "service-b-agent"


def _everything(caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]) -> str:
    out = capsys.readouterr()
    return "\n".join([caplog.text, out.out, out.err])


def _assert_names_absent(text: str, names: tuple[str, ...]) -> None:
    for name in names:
        assert name not in text, f"a log names {name!r}"


@pytest.mark.parametrize("enforce", [True, False])
def test_the_key_acl_logs_counts_and_never_the_agent_key_or_service(tmp_path: Path, caplog, capsys,
                                                                    enforce: bool) -> None:
    caplog.set_level(logging.DEBUG)
    ctx_, shutdown = _spawn(
        tmp_path,
        agent_keys={"service-a-agent": [KEY], WILD_AGENT: ["*"]},
        enforce_key_acl=enforce,
    )
    try:
        base = ctx_["base_url"]
        _upsert(base, service="ServiceA", key=KEY, secret="value-one")
        _upsert(base, service="ServiceA", key="marker-unlisted-pi", secret="value-two")
        assert _get(f"{base}/v0.4/connections/secret?key={KEY}", SVC_A_HDR)[0] == 200
        status, _ = _get(f"{base}/v0.4/connections/secret?key=marker-unlisted-pi", SVC_A_HDR)
        assert status == (403 if enforce else 200)
    finally:
        shutdown()
    text = _everything(caplog, capsys)
    assert "connections key ACL: ADMITTED" in text
    if enforce:
        assert "connections key ACL: DENIED" in text
        assert "1 agent(s) carry the '*' allow-all escape hatch" in text
    else:
        assert "reads would be denied under enforcement" in text
    _assert_names_absent(text, (KEY, "marker-unlisted-pi", "service-a-agent", WILD_AGENT,
                                *AGENT_SERVICES.values(), "value-one", "value-two"))


def test_the_pairing_relay_names_no_consumer_address(bootloader, fake_consumer, phone, caplog, capsys) -> None:
    caplog.set_level(logging.DEBUG)
    url = fake_consumer["base_url"]
    ctx_ = bootloader(consumer_tokens={url: "consumer-tok-omega"})
    # The unknown consumer first: the registry lookup precedes the grant's single-use check.
    assert _http_post_json(_pair_url(ctx_), _body(url + "/unregistered", phone))[0] == 404
    rec = _record(phone)   # a jti of its own: the grant is single use process-wide
    status, answer = _http_post_json(_pair_url(ctx_), _body(url, phone, rec, _grant(phone, rec, jti=uuid.uuid4().hex)))
    assert status == 200, answer
    text = _everything(caplog, capsys)
    assert "devices/pair: relayed (status=200)" in text
    assert "devices/pair: unknown consumer - refused" in text
    host_port = url.split("//", 1)[1]
    _assert_names_absent(text, (url, host_port, "unregistered", "consumer-tok-omega"))


def test_an_unreachable_consumer_is_said_without_its_address(bootloader, phone, caplog, capsys) -> None:
    import socket

    probe = bootloader()   # the loopback host the fixtures bind, read rather than written here
    host = probe["base_url"].split("//", 1)[1].rsplit(":", 1)[0]
    with socket.socket() as s:   # a port nothing listens on
        s.bind((host, 0))
        port = s.getsockname()[1]
    url = f"http://{host}:{port}"
    ctx_ = bootloader(consumer_tokens={url: "consumer-tok-omega"})
    _http_post_json(_pair_url(ctx_), _body(url, phone))
    text = _everything(caplog, capsys)
    assert "devices/pair: the consumer is unreachable" in text
    _assert_names_absent(text, (url, f":{port}"))


def test_minting_a_pairing_code_names_no_agent_or_consumer(ctx, caplog, capsys) -> None:
    caplog.set_level(logging.DEBUG)
    assert _mint(ctx, (AGENT_ID, AGENT_TOKEN), _member(CONSUMER))[0] == 200
    assert _mint(ctx, (OWNER_ID, OWNER_TOKEN), {})[0] == 200
    text = _everything(caplog, capsys)
    assert "minted MEMBER pairing code" in text and "minted pairing code" in text
    _assert_names_absent(text, (AGENT_ID, OWNER_ID, CONSUMER, CONSUMER.split("//", 1)[1]))


# --------------------------------------------------------------------------
# The launcher's config errors name an entry by its position (15.ab)
# --------------------------------------------------------------------------

_SECRET_AGENT = "marker-agent-rho"
_SECRET_VAULT = "MarkerVaultSigma"
_SECRET_ENV = "MARKER_TOKEN_ENV_TAU"
_SECRET_URL_PART = "marker-consumer-upsilon"


class _NoVault:
    def __init__(self, _service: str) -> None:
        pass

    def fetch(self, _name: str, _config: dict) -> None:
        raise LookupError("no such entry")


def _launch(monkeypatch, tmp_path, agents, consumers=None) -> int | None:
    from tests.test_capability_consumer_actions import _launcher_kwargs
    import run_bootloader_consumer as rbc

    monkeypatch.setattr(rbc, "DpapiMachineSource", _NoVault)
    if consumers is not None:
        monkeypatch.setattr(rbc, "_resolve_consumers", lambda: consumers)
    rc, _kw = _launcher_kwargs(monkeypatch, tmp_path, agents)
    return rc


@pytest.mark.parametrize("agents, says", [
    ([{"agent_id": "first", "token_env": "POLICY_TEST_TOKEN_A"},
      {"agent_id": _SECRET_AGENT, "token_env": _SECRET_ENV, "vault_service": _SECRET_VAULT}],
     "agent entry 2: no token resolvable"),
    ([{"agent_id": _SECRET_AGENT, "token_env": "POLICY_TEST_TOKEN_A"},
      {"agent_id": _SECRET_AGENT, "token_env": "POLICY_TEST_TOKEN_B"}],
     "agent entry 2: its agent_id repeats an earlier entry's"),
    ([{"agent_id": _SECRET_AGENT, "token_env": "POLICY_TEST_TOKEN_A", "capability_requests": _SECRET_VAULT}],
     "agent entry 1: capability_requests must be true or false"),
    ([{"agent_id": _SECRET_AGENT, "token_env": "POLICY_TEST_TOKEN_A", "may_mint_owner_codes": _SECRET_VAULT}],
     "agent entry 1: may_mint_owner_codes must be true or false"),
    ([{"agent_id": _SECRET_AGENT, "token_env": "POLICY_TEST_TOKEN_A", "requestable_actions": []}],
     "agent entry 1: requestable_actions must be"),
])
def test_a_bad_agent_entry_is_named_by_its_position(monkeypatch, tmp_path, capsys, agents, says) -> None:
    rc = _launch(monkeypatch, tmp_path, agents)
    out = capsys.readouterr()
    text = out.out + out.err
    assert rc == 2 and says in text, text
    _assert_names_absent(text, (_SECRET_AGENT, _SECRET_VAULT, _SECRET_ENV))


@pytest.mark.parametrize("consumers, says", [
    ([{"base_url": _SECRET_URL_PART, "token_env": _SECRET_ENV, "vault_service": _SECRET_VAULT}],
     "consumer entry 1: no webhook token resolvable"),
    ([{"base_url": _SECRET_URL_PART, "token_env": "POLICY_TEST_TOKEN_A"},
      {"base_url": f"{_SECRET_URL_PART}/", "token_env": "POLICY_TEST_TOKEN_B"}],
     "consumer entry 2: its base_url repeats an earlier entry's"),
    ([{"token_env": "POLICY_TEST_TOKEN_A", "vault_service": _SECRET_VAULT}],
     "consumer entry 1: missing base_url"),
])
def test_a_bad_consumer_entry_is_named_by_its_position(monkeypatch, tmp_path, capsys, consumers, says) -> None:
    rc = _launch(monkeypatch, tmp_path, [{"agent_id": "first", "token_env": "POLICY_TEST_TOKEN_A"}], consumers)
    out = capsys.readouterr()
    text = out.out + out.err
    assert rc == 2 and says in text, text
    _assert_names_absent(text, (_SECRET_URL_PART, _SECRET_VAULT, _SECRET_ENV))


def test_a_bad_env_map_entry_is_named_by_its_position(capsys) -> None:
    from tests.test_capability_consumer_actions import _launcher_kwargs  # noqa: F401 - puts examples/ on sys.path
    import run_bootloader_consumer as rbc

    with pytest.raises(SystemExit):
        rbc._parse_connections_agent_keys(f'{{"ok": ["k"], "{_SECRET_AGENT}": 7}}')
    with pytest.raises(SystemExit):
        rbc._parse_connections_agent_keys(f"ok:k,{_SECRET_AGENT}")
    err = capsys.readouterr().err
    assert "entry 2 must be a string or a list of strings" in err and "entry 2 is not" in err, err
    assert _SECRET_AGENT not in err
