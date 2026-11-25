"""A metadata sidecar that cannot be read is never read as empty and never written over: nothing is listed from it, no
value is written beside it, and the file stays byte for byte as it was until it is repaired or restored."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from recto.connections.manage import (
    delete_connection,
    get_connection_meta,
    list_connections,
    set_connection,
    set_enabled,
)
from recto.connections.types import MetadataUnreadableError
from recto.user_vault.manage import (
    delete_user_entry,
    list_user_entries,
    release_user_secret,
    set_user_entry,
)
from tests.test_bootloader_user_vault import USER_1, _hdrs, _MemoryVault, _spawn
from tests.test_bootloader_slots import _http

# A row whose shape is an object's, and whose fields are not: `created_at_unix` is null.
_ROW = {"service": "S", "platform": "P", "subject": USER_1, "key": "one", "created_at_unix": None}
UNREADABLE = ["{ not json", "", "[]", "\"text\"", "{\"connections\": {}, \"entries\": {}}",
              "{}", "{\"schema_version\": 1}", "{\"connections\": null, \"entries\": null}",
              "{\"connection\": [], \"entry\": []}", "{\"connections\": false, \"entries\": 0}",
              "{\"connections\": [1], \"entries\": [1]}", "{\"connections\": [null], \"entries\": [\"row\"]}",
              json.dumps({"connections": [_ROW], "entries": [_ROW]}),
              *(json.dumps({"connections": [row], "entries": [row]}).replace('"1e400"', "1e400") for row in (
                  dict(_ROW, created_at_unix=0, service=["S"], platform=["P"]),
                  dict(_ROW, created_at_unix=0, rotated_at_unix="1e400")))]


@pytest.fixture
def vault() -> _MemoryVault:
    return _MemoryVault()


@pytest.mark.parametrize("stored", UNREADABLE)
def test_connections_are_neither_listed_nor_written_over(tmp_path: Path, vault: Any, stored: str) -> None:
    path = tmp_path / "connections.json"
    set_connection(path, service="S", key="one", secret="v1", secret_source_factory=vault.factory)
    values = dict(vault.data)
    path.write_text(stored, encoding="utf-8")
    before = path.read_bytes()
    for act in (
        lambda: list_connections(path),
        lambda: get_connection_meta(path, "S", "one"),
        lambda: set_connection(path, service="S", key="two", secret="v2", secret_source_factory=vault.factory),
        lambda: set_enabled(path, "S", "one", False),
        lambda: delete_connection(path, service="S", key="one", secret_source_factory=vault.factory),
    ):
        with pytest.raises(MetadataUnreadableError, match="connections.json"):
            act()
    assert path.read_bytes() == before
    assert vault.data == values


@pytest.mark.parametrize("stored", UNREADABLE)
def test_user_entries_are_neither_listed_nor_written_over(tmp_path: Path, vault: Any, stored: str) -> None:
    path = tmp_path / "user_vault.json"
    set_user_entry(path, platform="P", subject=USER_1, key="one", secret="v1", secret_source_factory=vault.factory)
    values = dict(vault.data)
    path.write_text(stored, encoding="utf-8")
    before = path.read_bytes()
    for act in (
        lambda: list_user_entries(path, "P", USER_1),
        lambda: set_user_entry(path, platform="P", subject=USER_1, key="two", secret="v2",
                               secret_source_factory=vault.factory),
        lambda: delete_user_entry(path, platform="P", subject=USER_1, key="one",
                                  secret_source_factory=vault.factory),
    ):
        with pytest.raises(MetadataUnreadableError, match="user_vault.json"):
            act()
    assert path.read_bytes() == before
    assert vault.data == values
    # The value itself never came from the sidecar.
    assert release_user_secret("P", USER_1, "one", secret_source_factory=vault.factory) == "v1"


# ---- what a writer takes, its reader reads ---------------------------------------------------------------------------

NOT_TEXT = [7, 0, True, False, 1.5, [], ["c"], {}, {"a": 1}]


@pytest.mark.parametrize("value", NOT_TEXT)
@pytest.mark.parametrize("field", ["category", "display_name"])
def test_a_label_that_is_not_text_is_refused_before_anything_is_written(tmp_path, vault, field, value) -> None:
    c, u = tmp_path / "connections.json", tmp_path / "user_vault.json"
    set_connection(c, service="S", key="one", secret="v1", secret_source_factory=vault.factory)
    set_user_entry(u, platform="P", subject=USER_1, key="one", secret="v1", secret_source_factory=vault.factory)
    values, before = dict(vault.data), (c.read_bytes(), u.read_bytes())
    with pytest.raises(ValueError, match=field):
        set_connection(c, service="S", key="two", secret="v2", secret_source_factory=vault.factory, **{field: value})
    with pytest.raises(ValueError, match=field):
        set_user_entry(u, platform="P", subject=USER_1, key="two", secret="v2",
                       secret_source_factory=vault.factory, **{field: value})
    assert vault.data == values and (c.read_bytes(), u.read_bytes()) == before
    assert [m.key for m in list_connections(c)] == ["one"]
    assert [m.key for m in list_user_entries(u, "P", USER_1)] == ["one"]


@pytest.mark.parametrize("field", ["service", "platform"])
def test_a_name_that_is_not_text_is_refused_before_anything_is_written(tmp_path, vault, field) -> None:
    with pytest.raises(ValueError, match=field):
        if field == "service":
            set_connection(tmp_path / "c.json", service=7, key="one", secret="v", secret_source_factory=vault.factory)
        else:
            set_user_entry(tmp_path / "u.json", platform=7, subject=USER_1, key="one", secret="v",
                           secret_source_factory=vault.factory)
    assert vault.data == {} and list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("value", [None, *NOT_TEXT])
@pytest.mark.parametrize("field", ["category", "display_name"])
def test_a_stored_label_that_is_not_text_reads_as_its_default_and_every_row_loads(tmp_path, vault, field, value) -> None:
    rows = [dict(_ROW, created_at_unix=0, key=k, **({field: value} if k == "odd" else {})) for k in ("odd", "one")]
    c, u = tmp_path / "connections.json", tmp_path / "user_vault.json"
    c.write_text(json.dumps({"connections": rows}), encoding="utf-8")
    u.write_text(json.dumps({"entries": rows}), encoding="utf-8")
    for metas in (list_connections(c), list_user_entries(u, "P", USER_1)):
        by_key = {m.key: m for m in metas}
        assert set(by_key) == {"odd", "one"}
        assert (by_key["odd"].category, by_key["odd"].display_name) == ("uncategorized", "odd")
    # and the next write keeps both
    set_connection(c, service="S", key="two", secret_source_factory=vault.factory)
    set_user_entry(u, platform="P", subject=USER_1, key="two", secret_source_factory=vault.factory)
    assert len(list_connections(c)) == len(list_user_entries(u, "P", USER_1)) == 3


@pytest.mark.parametrize("value", [None, 7, True])
def test_a_row_under_a_name_that_is_no_text_hides_no_other_and_is_kept(tmp_path, vault, value) -> None:
    odd = dict(_ROW, created_at_unix=0, service=value, platform=value)
    good = dict(_ROW, created_at_unix=0)
    c, u = tmp_path / "connections.json", tmp_path / "user_vault.json"
    c.write_text(json.dumps({"connections": [odd, good]}), encoding="utf-8")
    u.write_text(json.dumps({"entries": [odd, good]}), encoding="utf-8")
    assert [m.service for m in list_connections(c)] == ["S"]
    assert [m.platform for m in list_user_entries(u, "P", USER_1)] == ["P"]
    set_connection(c, service="S", key="two", secret_source_factory=vault.factory)
    set_user_entry(u, platform="P", subject=USER_1, key="two", secret_source_factory=vault.factory)
    assert odd in json.loads(c.read_text(encoding="utf-8"))["connections"]
    assert odd in json.loads(u.read_text(encoding="utf-8"))["entries"]


def test_one_agents_write_never_locks_the_vault(tmp_path: Path) -> None:
    ctx, shutdown = _spawn(tmp_path)
    try:
        base = f"{ctx['base_url']}/v0.4/user-vault"
        assert _http("POST", f"{base}/set", {"key": "one", "secret": "v1"}, headers=_hdrs())[0] == 200
        for field in ("category", "display_name"):
            status, body = _http("POST", f"{base}/set", {"key": "two", "secret": "v2", field: 7}, headers=_hdrs())
            assert status == 400 and field in body["detail"], body
        status, body = _http("GET", base, headers=_hdrs())
        assert status == 200 and [e["key"] for e in body["entries"]] == ["one"], body
        status, body = _http("GET", f"{base}/release?key=two", headers=_hdrs())
        assert body.get("has_value") is False, body
    finally:
        shutdown()


def test_a_missing_sidecar_is_an_empty_one(tmp_path: Path) -> None:
    assert list_connections(tmp_path / "connections.json") == []
    assert list_user_entries(tmp_path / "user_vault.json", "P", USER_1) == []


def test_the_bootloader_names_the_refusal(tmp_path: Path) -> None:
    ctx, shutdown = _spawn(tmp_path)
    try:
        base = f"{ctx['base_url']}/v0.4/user-vault"
        assert _http("POST", f"{base}/set", {"key": "one", "secret": "v1"}, headers=_hdrs())[0] == 200
        (tmp_path / "user_vault.json").write_text("{ not json", encoding="utf-8")
        for status, body in (
            _http("GET", base, headers=_hdrs()),
            _http("POST", f"{base}/set", {"key": "two", "secret": "v2"}, headers=_hdrs()),
            _http("POST", f"{base}/delete", {"key": "one"}, headers=_hdrs()),
        ):
            assert status == 503 and body["error"] == "metadata_unreadable", body
        assert (tmp_path / "user_vault.json").read_text(encoding="utf-8") == "{ not json"
    finally:
        shutdown()
