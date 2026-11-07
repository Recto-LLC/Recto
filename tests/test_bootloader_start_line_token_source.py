"""The launcher's startup lines name where each token was read from, never any of its characters.

The "Agents:" and "Devices-pair consumers:" lines go to the bootloader's stdout, which a host's log collection
keeps. Each line names the agent (or the consumer) and its token's SOURCE - "env <NAME>", or
"vault <service>/<secret>" when the token came from the dpapi-machine vault - and no part of the value appears
anywhere in the launcher's output.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

import tests.test_capability_consumer_actions as tcca   # puts examples/ on sys.path; the launcher harness
import run_bootloader_consumer as rbc

REPO = Path(__file__).resolve().parents[1]

# Deterministic 64-hex tokens, so a pass is never luck.
TOKEN_A = hashlib.sha256(b"start-line agent one").hexdigest()
TOKEN_B = hashlib.sha256(b"start-line agent two").hexdigest()
TOKEN_V = hashlib.sha256(b"start-line vault agent").hexdigest()
TOKEN_W = hashlib.sha256(b"start-line consumer webhook").hexdigest()


def _windows(token: str, width: int) -> set[str]:
    return {token[i:i + width] for i in range(len(token) - width + 1)}


def _assert_no_token_characters(text: str, tokens: tuple[str, ...], width: int) -> None:
    for token in tokens:
        shown = [w for w in _windows(token, width) if w in text]
        # The failure names a count only: a test's message is a log too.
        assert not shown, f"{len(shown)} {width}-character windows of a token appear in the output"


def _line(out: str, start: str) -> str:
    lines = [ln for ln in out.splitlines() if ln.startswith(start)]
    assert len(lines) == 1, f"expected one line starting {start!r}, got {len(lines)}"
    return lines[0]


def _run_quiet(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
               agents: list[dict[str, Any]], consumers: list[dict[str, Any]] | None = None) -> str:
    """Run the launcher's main() in quiet mode to its serve loop and return stdout + stderr."""
    rc, kwargs = tcca._launcher_kwargs(monkeypatch, tmp_path, agents)   # sets the environment; stops at create_server
    assert rc is None and kwargs is not None, rc
    monkeypatch.setenv("RECTO_BOOTLOADER_QUIET", "1")
    if consumers is not None:
        consumers_file = tmp_path / "devices-pair-consumers.json"
        consumers_file.write_text(json.dumps({"consumers": consumers}), encoding="utf-8")
        monkeypatch.setenv("RECTO_DEVICES_PAIR_CONSUMERS_FILE", str(consumers_file))

    def fake_create_server(**_kwargs: Any) -> Any:
        stub = mock.MagicMock()
        stub.server_address = ("127.0.0.1", 0)
        stub.serve_forever.side_effect = KeyboardInterrupt
        return stub

    monkeypatch.setattr(rbc, "create_server", fake_create_server)
    capsys.readouterr()
    assert rbc.main() == 0
    captured = capsys.readouterr()
    return captured.out + captured.err


def test_each_agent_and_consumer_line_names_its_env_source_and_no_token_characters(monkeypatch, tmp_path,
                                                                                  capsys) -> None:
    monkeypatch.setenv("START_LINE_TOKEN_A", TOKEN_A)
    monkeypatch.setenv("START_LINE_TOKEN_B", TOKEN_B)
    monkeypatch.setenv("START_LINE_WEBHOOK", TOKEN_W)
    out = _run_quiet(monkeypatch, tmp_path, capsys,
                     [{"agent_id": "agent-one", "token_env": "START_LINE_TOKEN_A"},
                      {"agent_id": "agent-two", "token_env": "START_LINE_TOKEN_B", "may_mint_owner_codes": True}],
                     [{"base_url": "https://consumer.test/", "token_env": "START_LINE_WEBHOOK"}])
    one = _line(out, "  - agent-one ")
    two = _line(out, "  - agent-two ")
    consumer = _line(out, "  - https://consumer.test ")
    assert one.startswith("  - agent-one (token from env START_LINE_TOKEN_A) "), one
    assert two.startswith("  - agent-two (token from env START_LINE_TOKEN_B) ") and "[mints owner codes]" in two, two
    assert consumer == "  - https://consumer.test (token from env START_LINE_WEBHOOK)", consumer
    # Not even a short run of a token's characters in its own line, and none anywhere in the output.
    _assert_no_token_characters(one, (TOKEN_A,), 4)
    _assert_no_token_characters(two, (TOKEN_B,), 4)
    _assert_no_token_characters(consumer, (TOKEN_W,), 4)
    _assert_no_token_characters(out, (TOKEN_A, TOKEN_B, TOKEN_W), 6)
    assert "token =" not in out


def test_a_token_read_from_the_vault_is_named_by_its_vault_entry(monkeypatch, tmp_path, capsys) -> None:
    fetched: list[tuple[str, str]] = []

    class FakeVault:
        def __init__(self, service: str) -> None:
            self.service = service

        def fetch(self, name: str, _config: dict) -> Any:
            fetched.append((self.service, name))
            return mock.MagicMock(value=TOKEN_V)

    monkeypatch.setattr(rbc, "DpapiMachineSource", FakeVault)
    monkeypatch.delenv("START_LINE_UNSET_TOKEN", raising=False)
    out = _run_quiet(monkeypatch, tmp_path, capsys, [
        # token_env names an unset variable: the vault entry is the source, as the resolver reads it
        {"agent_id": "vault-agent", "token_env": "START_LINE_UNSET_TOKEN",
         "vault_service": "StartLineService", "vault_secret": "START_LINE_SECRET"},
        # no vault_secret: the resolver's default name
        {"agent_id": "default-secret-agent", "vault_service": "StartLineService"},
    ])
    assert ("StartLineService", "START_LINE_SECRET") in fetched
    assert ("StartLineService", "RECTO_CAPABILITY_AGENT_TOKEN") in fetched
    vault = _line(out, "  - vault-agent ")
    default = _line(out, "  - default-secret-agent ")
    assert vault.startswith("  - vault-agent (token from vault StartLineService/START_LINE_SECRET) "), vault
    assert default.startswith(
        "  - default-secret-agent (token from vault StartLineService/RECTO_CAPABILITY_AGENT_TOKEN) "), default
    _assert_no_token_characters(vault + default, (TOKEN_V,), 4)
    _assert_no_token_characters(out, (TOKEN_V,), 6)


def test_the_minimal_example_names_its_env_source_and_no_token_characters(monkeypatch, tmp_path, capsys) -> None:
    from tests.test_bootloader_owner_slots import _seed_state_dir, _wrap_real_create_server
    import run_bootloader_example as ex

    monkeypatch.setenv("MYSERVICE_AGENT_TOKEN", TOKEN_A)
    monkeypatch.setattr(ex, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(ex, "BIND_HOST", "127.0.0.1")
    monkeypatch.setattr(ex, "BIND_PORT", 0)
    _seed_state_dir(tmp_path / "state", "open", None)
    made = _wrap_real_create_server(ex, monkeypatch)
    try:
        capsys.readouterr()
        ex.main()
        captured = capsys.readouterr()
    finally:
        for server in made:
            server.server_close()
    out = captured.out + captured.err
    assert _line(out, "Agents:") == "Agents:    myservice-agent (token from env MYSERVICE_AGENT_TOKEN)"
    _assert_no_token_characters(out, (TOKEN_A,), 6)


# A slice of a token-like value (token[:8], tok[-4:], a secret's head) formatted anywhere the bootloader or its
# shipped launchers run. Public keys (pubkey / *_hex) are not secrets and stay out of the pattern.
_TOKEN_SLICE = re.compile(r"\b(?!\w*(?:pubkey|_hex)\b)\w*(?:token|tok|secret)\w*\s*\[\s*-?\d*\s*:\s*-?\d*\s*\]",
                          re.IGNORECASE)


def test_no_shipped_launcher_or_bootloader_module_prints_a_slice_of_a_token() -> None:
    sources = [REPO / "examples" / "run_bootloader_consumer.py", REPO / "examples" / "run_bootloader_example.py"]
    sources += sorted((REPO / "recto").rglob("*.py"))
    found = []
    for path in sources:
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if _TOKEN_SLICE.search(line):
                found.append(f"{path.relative_to(REPO)}:{n}")
    assert not found, found


def test_the_slice_pattern_catches_the_old_line() -> None:
    assert _TOKEN_SLICE.search('print(f"  - {aid} (token = {tok[:8]}...) {ctx_str}")')
    assert _TOKEN_SLICE.search('print(f"Agents: x (token = {agent_token[:8]}...)")')
    assert _TOKEN_SLICE.search("head = webhook_secret[-4:]")
    assert not _TOKEN_SLICE.search('f"{mi.master_pubkey_hex[:8]}...{mi.master_pubkey_hex[-8:]}"')
    assert not _TOKEN_SLICE.search("tokens = parts[1:]")
