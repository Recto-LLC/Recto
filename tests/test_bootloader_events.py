"""The folder-drop event bus carries no part of what a card asked.

Owner ruling 2026-11-22: Recto logs nothing of what a service asked and
does not name the services using it; tracking what passes through Recto
is the consuming platform's business. These tests pin that the event
schema itself cannot carry a card's actions, purpose, tier, jti,
audience, scope, claims, payload or its hash, nor the requesting agent,
the request's kind or a denial's free-text reason.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from recto.bootloader.events import (
    EVENT_PAYLOAD_SHAPES,
    FORBIDDEN_EVENT_FIELDS,
    FileEventEmitter,
    shape_payload,
)
from recto.bootloader.state import PendingRequest
from recto.capability.jwt import build_signing_input
from recto.capability.types import (
    CapabilityClaims,
    CapabilityClause,
    CapabilityLimits,
    CapabilityScope,
)

# Distinct markers: if any of them reaches an event file, the card leaked.
ACTION = "marker-action:alpha-7"
DENY = "marker-deny:beta-7"
GROUP = "marker-group-gamma-7"
PURPOSE = "marker purpose delta-7"
AUDIENCE = "marker-audience-epsilon-7"
SERVICE = "marker-service-zeta-7"
JTI = "marker-jti-eta-7"
AGENT = "marker-agent-theta-7"
DESCRIPTION = "marker description iota-7"
REASON = "marker reason kappa-7"
MARKERS = (ACTION, DENY, GROUP, PURPOSE, AUDIENCE, SERVICE, JTI, AGENT, DESCRIPTION, REASON)


def _full_claims() -> CapabilityClaims:
    now = int(time.time())
    return CapabilityClaims(
        iss="phone:operator:enclave",
        sub="agent:sample",
        aud=[AUDIENCE],
        iat=now,
        nbf=now,
        exp=now + 600,
        jti=JTI,
        cap=CapabilityClause(
            tier=3,
            registry_version="2026-11-22",
            groups=[GROUP],
            scope=CapabilityScope(env=["staging"], services=[SERVICE], repos=["sample-repo"]),
            allow_actions=[ACTION],
            deny_actions=[DENY],
            limits=CapabilityLimits(per_hour={}, per_day={ACTION: 3}, per_session={}),
        ),
        purpose=PURPOSE,
    )


def _capability_request() -> PendingRequest:
    digest, header_b64, payload_b64 = build_signing_input(_full_claims())
    return PendingRequest.new_capability_request(
        service=SERVICE,
        secret="capability",
        phone_id="phone-sample",
        operation_description=DESCRIPTION,
        payload_hash_b64u=base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii"),
        child_pid=0,
        child_argv0="(external-agent)",
        cap_header_b64=header_b64,
        cap_payload_b64=payload_b64,
        cap_agent_id=AGENT,
    )


def _read_events(events_dir: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in sorted(events_dir.glob("*.jsonl")):
        out.extend(json.loads(line) for line in f.read_text(encoding="utf-8").splitlines() if line)
    return out


def test_no_declared_shape_carries_a_forbidden_field() -> None:
    for kind, shape in EVENT_PAYLOAD_SHAPES.items():
        assert not set(shape) & FORBIDDEN_EVENT_FIELDS, (kind, set(shape) & FORBIDDEN_EVENT_FIELDS)


@pytest.mark.parametrize("ok", [True, False])
def test_a_capability_event_from_a_full_request_carries_none_of_the_card(tmp_path: Path, ok: bool) -> None:
    req = _capability_request()
    # Even a request object that HAS the old fields cannot put them in an event.
    widened = SimpleNamespace(
        **{f.name: getattr(req, f.name) for f in dataclasses.fields(req)},
        cap_purpose=PURPOSE, cap_tier=3, cap_allow_actions=[ACTION], cap_jti=JTI,
    )
    emitter = FileEventEmitter(tmp_path, bootloader_id="boot-sample")
    for r in (req, widened):
        emitter.notify_resolved(req=r, ok=ok, capability_jws="h.p.s", reason=REASON)

    events = _read_events(tmp_path)
    assert len(events) == 2
    kind = "capability_approved" if ok else "capability_denied"
    for ev in events:
        assert ev["kind"] == kind
        assert set(ev) == {"kind", "ts", "ts_iso", "bootloader", "payload"}
        assert set(ev["payload"]) == set(EVENT_PAYLOAD_SHAPES[kind])
        assert ev["payload"]["request_id"] == req.request_id
        assert not set(ev["payload"]) & FORBIDDEN_EVENT_FIELDS
    raw = "\n".join(p.read_text(encoding="utf-8") for p in tmp_path.glob("*.jsonl"))
    for marker in MARKERS:
        assert marker not in raw, marker
    for b64 in (req.cap_header_b64, req.cap_payload_b64, req.payload_hash_b64u, "h.p.s"):
        assert b64 not in raw


@pytest.mark.parametrize("ok", [True, False])
def test_a_sign_event_carries_neither_the_request_kind_nor_the_reason(tmp_path: Path, ok: bool) -> None:
    req = SimpleNamespace(request_id="rid-sample", kind="eth_sign", service=SERVICE,
                          operation_description=DESCRIPTION, eth_message_text=PURPOSE)
    FileEventEmitter(tmp_path).notify_resolved(req=req, ok=ok, reason=REASON)
    (ev,) = _read_events(tmp_path)
    kind = "sign_approved" if ok else "sign_denied"
    assert ev["kind"] == kind
    assert set(ev["payload"]) == set(EVENT_PAYLOAD_SHAPES[kind])
    raw = json.dumps(ev)
    for leaked in ("eth_sign", SERVICE, DESCRIPTION, PURPOSE, REASON):
        assert leaked not in raw, leaked


def test_emit_drops_undeclared_fields_and_refuses_undeclared_kinds(tmp_path: Path) -> None:
    emitter = FileEventEmitter(tmp_path)
    emitter.emit("capability_approved", {
        "request_id": "rid-1", "approved_at_unix": 1,
        "purpose": PURPOSE, "allow_actions": [ACTION], "jws_jti": JTI, "agent_id": AGENT,
        "aud": [AUDIENCE], "scope": {"services": [SERVICE]}, "claims": {"jti": JTI},
    })
    emitter.emit("capability_revoked", {"jti": JTI, "original_exp_unix": 9, "revoked_at_unix": 2})
    emitter.emit("devices_paired", {"consumer_base_url": SERVICE, "master_pubkey_hex": "ab", "paired_at_unix": 3})
    emitter.emit("an_undeclared_kind", {"purpose": PURPOSE})
    events = _read_events(tmp_path)
    assert [e["kind"] for e in events] == ["capability_approved", "capability_revoked", "devices_paired"]
    assert events[0]["payload"] == {"request_id": "rid-1", "approved_at_unix": 1}
    assert events[1]["payload"] == {"revoked_at_unix": 2}
    assert events[2]["payload"] == {"master_pubkey_hex": "ab", "paired_at_unix": 3}
    raw = "\n".join(json.dumps(e) for e in events)
    for marker in MARKERS:
        assert marker not in raw, marker


def test_shape_payload_is_none_for_an_undeclared_kind() -> None:
    assert shape_payload("not_a_kind", {"request_id": "x"}) is None
