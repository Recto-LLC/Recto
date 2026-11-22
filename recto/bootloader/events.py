r"""Folder-drop event bus for the bootloader.

Substrate-side primitive for AI-to-AI peer communication via the
filesystem. The bootloader emits state-change events as JSONL files
to a configurable directory; application-host AIs on the same
filesystem tail-watch the daily files and react to events at
their own cadence — without polling Recto's HTTP surface.

Architectural posture
=====================

Folder-drop is COMPLEMENTARY to the existing HTTP capability_request
flow, NOT a replacement. HTTP stays canonical for synchronous "I need
authority NOW" verbs. Folder-drop is for async "fyi, this happened"
notifications.

Each event is a single-line JSONL append to a daily-rotated file at
``<events_dir>/<YYYY-MM-DD>.jsonl``. Daily rotation keeps any single
file from growing unboundedly for long-running bootloaders; consumers
can read today's file + yesterday's file to cover the typical
catch-up window.

Event records carry:

- ``kind``       — event taxonomy (capability_approved, phone_paired, etc.)
- ``ts``         — emission timestamp (unix seconds, integer)
- ``ts_iso``     — same timestamp ISO-8601 for human readability
- ``bootloader`` — bootloader_id of the emitter (lets multi-bootloader
                   deployments distinguish event sources)
- ``payload``    — event-kind-specific dict; see EVENT_PAYLOAD_SHAPES below

What an event never carries (owner ruling 2026-11-22): any part of what
a service asked - a card's actions, purpose, tier, jti, audience, scope,
claims, payload or its hash - nor who asked it (the agent's id, the
consumer's address), nor the request's kind or a denial's free-text
reason. Tracking what passes through Recto is the consuming platform's
business; Recto, like an honest witness, does not log the services using
it. ``emit`` enforces the declared shapes, so the bus cannot be widened
by a caller.

Security posture
================

Events are NOTIFICATIONS, not capability assertions. The contents
have NO authority — a malicious consumer that writes fake JSONL into
the events folder can't escalate privileges, because no downstream
consumer treats event payloads as authoritative. Authority flows
exclusively through the HTTP capability_request → operator-phone-
approval → JWS chain per Hard Rule #9; folder-drop is downstream of
the authority decision, never upstream.

Folder permissions: the events directory MUST be writable by the
bootloader and readable by intended peer consumers. In the Docker
deployment, this is typically a bind-mount with container-uid =
peer-AI-host-uid alignment; for native deployments, standard POSIX
group permissions or Windows ACLs apply.

v1 scope (this module)
======================

Wires ONE canonical event-emission site: the existing
``notify_resolved_fn`` hook in ``create_server``. This covers
capability lifecycle events (capability_approved, capability_denied,
capability_signed for multi-coin sign kinds) without touching
``server.py``. Construct a FileEventEmitter, pass its ``__call__``
method as ``notify_resolved_fn`` to ``create_server``, and approved/
denied capability_requests emit JSONL events.

Future emission sites (follow-up sprints, banked separately):

- ``phone_paired``        — bootloader's pairing handshake completes
- ``phone_revoked``       — operator-trusted agent revokes a paired phone
- ``vault_bootstrapped``  — operator pubkey is written to vault_root.json
- ``capability_revoked``  — ``POST /v0.4/capability/revoke`` succeeds
- ``devices_paired``      — Phase-H end-user device pairing relays clean

Each follow-up adds one ``emitter.emit(kind, payload)`` call at the
matching site in ``server.py`` + an entry in EVENT_PAYLOAD_SHAPES
below. The emitter primitive doesn't need to change.

Disabling
=========

When ``RECTO_EVENTS_DIR`` env var is unset, the launcher does NOT
construct a FileEventEmitter and ``notify_resolved_fn`` stays at its
default (None). The bootloader's behavior is unchanged from the
pre-events-folder baseline. Opt-in is the deployment-time switch.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# Event payload shapes documented here as the canonical schema.
#
# WHAT AN EVENT MAY CARRY (owner ruling 2026-11-22): Recto records no
# part of what a service asked and does not name the services using it.
# Tracking what is sent through Recto and received from it is the
# consuming platform's business, never the substrate's. So an event
# carries only the event kind, its timestamps, the emitter's own
# bootloader id and Recto's own opaque handles (the request_id it
# minted, its own phone and key identifiers). The action(s), purpose,
# tier, jti, audience, scope, claims, payload or payload hash of a card,
# the requesting agent's id, the request's kind, a denial's free-text
# reason and a consumer's address are never fields here.
#
# The schema is ENFORCED, not advisory: ``FileEventEmitter.emit`` writes
# only the fields declared below for the event's kind and refuses any
# kind not declared, so a caller cannot widen an event by passing more.
# Consumers can rely on these names; a field is added only when it is
# opaque in the sense above.
EVENT_PAYLOAD_SHAPES: dict[str, dict[str, str]] = {
    "capability_approved": {
        "request_id": "str (uuid the bootloader minted at queue time)",
        "approved_at_unix": "int",
    },
    "capability_denied": {
        "request_id": "str (uuid)",
        "denied_at_unix": "int",
    },
    "sign_approved": {
        # Every approval kind OTHER than capability_request resolves
        # through the same notify path and emits this one generic event,
        # so a watcher sees every operator approval in one stream. The
        # request's kind is not carried: it says what was asked.
        "request_id": "str (uuid)",
        "approved_at_unix": "int",
    },
    "sign_denied": {
        "request_id": "str (uuid)",
        "denied_at_unix": "int",
    },
    # Reserved emission sites - listed for schema stability; the emitter
    # writes them once the corresponding server.py call sites land.
    "phone_paired": {
        "phone_id": "str (the phone's registry handle)",
        "public_key_b64u": "str (base64url, no padding; the phone's own key)",
        "algorithm": "str (ed25519 | ecdsa-p256)",
        "paired_at_unix": "int",
    },
    "phone_revoked": {
        "phone_id": "str (the phone's registry handle)",
        "revoked_at_unix": "int",
    },
    "vault_bootstrapped": {
        "pubkey_hex": "str (128 hex chars, secp256k1 uncompressed without 0x04 prefix)",
        "bootstrapped_at_unix": "int",
    },
    "capability_revoked": {
        # The revoked grant's jti and exp are its claims - not carried.
        "revoked_at_unix": "int",
    },
    "devices_paired": {
        # The consumer's address names the service using Recto - not carried.
        "master_pubkey_hex": "str (128 hex chars)",
        "paired_at_unix": "int",
    },
}

# Names that would carry what a card asked, or name who asked. No shape
# above may declare one; tests pin it, and emit() drops them regardless.
FORBIDDEN_EVENT_FIELDS: frozenset[str] = frozenset({
    "agent_id", "purpose", "tier", "allow_actions", "deny_actions", "groups",
    "jti", "jws_jti", "aud", "audience", "scope", "claims", "cap", "payload",
    "payload_hash", "payload_hash_b64u", "payload_sha256", "operation_description",
    "service", "secret", "kind", "reason", "original_exp_unix", "exp", "consumer_base_url",
})


def shape_payload(kind: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    """The payload an event of ``kind`` may carry: the declared fields only.

    ``None`` when ``kind`` is not declared - such an event is not written.
    """
    shape = EVENT_PAYLOAD_SHAPES.get(kind)
    if shape is None:
        return None
    return {
        name: payload[name]
        for name in shape
        if name in payload and name not in FORBIDDEN_EVENT_FIELDS
    }


class FileEventEmitter:
    """Append JSONL events to a daily-rotated file under ``events_dir``.

    Thread-safe (uses an internal Lock for the file append step).
    Failures are NEVER fatal — if the events directory becomes
    unwritable (full disk, permissions changed, etc.), the emitter
    logs to stderr and continues. The bootloader's primary HTTP path
    is unaffected.

    Construct once at bootloader startup; the same instance handles
    every emission across the process lifetime. Pass the bound
    ``notify_resolved_fn`` method to ``create_server`` as the
    ``notify_resolved_fn`` kwarg to wire capability + sign lifecycle
    events without touching ``server.py``.
    """

    def __init__(
        self,
        events_dir: str | Path,
        *,
        bootloader_id: str | None = None,
    ) -> None:
        self.events_dir = Path(events_dir)
        self.bootloader_id = bootloader_id or ""
        self._lock = threading.Lock()

        # Eager mkdir at construction time. Failures here are
        # surfaced to the launcher rather than swallowed — if the
        # events dir CAN'T be created at startup, the operator
        # should know immediately rather than discover it on first
        # event emission.
        self.events_dir.mkdir(parents=True, exist_ok=True)

    def emit(self, kind: str, payload: dict[str, Any]) -> None:
        """Append one event to today's JSONL file.

        The schema is enforced here: only the fields
        ``EVENT_PAYLOAD_SHAPES`` declares for ``kind`` are written, and a
        kind it does not declare is not written at all. A caller cannot
        make an event carry what a card asked by passing more.
        """
        shaped = shape_payload(kind, payload)
        if shaped is None:
            print(
                f"[recto.bootloader.events] WARNING: undeclared event kind "
                f"{kind!r} not emitted",
                file=sys.stderr,
            )
            return
        now = time.time()
        record = {
            "kind": kind,
            "ts": int(now),
            "ts_iso": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
            "bootloader": self.bootloader_id,
            "payload": shaped,
        }

        # Daily-rotated file. Date in UTC to avoid timezone-shift
        # ambiguity when consumers from different timezones tail-read.
        date_str = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%d")
        target = self.events_dir / f"{date_str}.jsonl"

        line = json.dumps(record, separators=(",", ":")) + "\n"

        try:
            with self._lock:
                # Open in append mode + buffering=1 (line-buffered) so
                # readers see each event as it lands. The lock guards
                # against threadpool races inside ThreadingHTTPServer;
                # without it, two concurrent emissions could interleave
                # bytes within a JSONL line.
                with open(target, "a", encoding="utf-8") as f:
                    f.write(line)
        except OSError as ex:
            # Don't let event emission failures crash the bootloader.
            # Log to stderr (which docker captures into `docker logs`)
            # so the operator sees the failure during routine log
            # inspection, but proceed serving HTTP.
            print(
                f"[recto.bootloader.events] WARNING: emit failed "
                f"({kind!r} -> {target}): {type(ex).__name__}: {ex}",
                file=sys.stderr,
            )

    # ---------------------------------------------------------------
    # notify_resolved_fn adapter
    # ---------------------------------------------------------------
    # The bootloader's existing notify_resolved_fn callback is the
    # natural wiring point for capability + sign lifecycle events.
    # This method matches that callback's signature (with TypeError-
    # tolerant fallback for older signatures, per the same shape the
    # server.py call site uses).

    def notify_resolved(
        self,
        *,
        req: Any,
        ok: bool,
        signature_b64u: str | None = None,
        eth_signature_rsv: str | None = None,
        btc_signature_base64: str | None = None,
        ed_signature_base64: str | None = None,
        ed_pubkey_hex: str | None = None,
        tron_signature_rsv: str | None = None,
        capability_jws: str | None = None,
        reason: str | None = None,
    ) -> None:
        """Translate a notify_resolved_fn callback into a structured
        event JSONL append. Wire as
        ``create_server(notify_resolved_fn=emitter.notify_resolved, ...)``.

        Only Recto's own opaque handle (the request_id) and the moment
        cross into the event; nothing of what the card asked, nor who
        asked it, is read from ``req`` (owner ruling 2026-11-22).
        ``reason`` is not carried either: an operator's note or a
        verifier's diagnostic can quote the card. The requesting agent
        reads its verdict and reason from the result endpoint.
        """
        request_id = getattr(req, "request_id", "") or ""
        now = int(time.time())
        if (getattr(req, "kind", "") or "") == "capability_request":
            if ok:
                self.emit("capability_approved",
                          {"request_id": request_id, "approved_at_unix": now})
            else:
                self.emit("capability_denied",
                          {"request_id": request_id, "denied_at_unix": now})
            return
        if ok:
            self.emit("sign_approved",
                      {"request_id": request_id, "approved_at_unix": now})
        else:
            self.emit("sign_denied",
                      {"request_id": request_id, "denied_at_unix": now})


def construct_from_env(
    bootloader_id: str | None = None,
) -> FileEventEmitter | None:
    """Construct a FileEventEmitter from ``RECTO_EVENTS_DIR`` env var.

    Returns the emitter when ``RECTO_EVENTS_DIR`` is set + the
    directory is writable. Returns ``None`` when the env var is
    unset (opt-in to event emission is the deployment-time decision)
    OR when the directory can't be created (emitter falls back to
    no-op gracefully; the bootloader's primary HTTP behavior is
    unaffected). Failures during construction print to stderr so
    operators see misconfiguration during startup.

    Typical use in the launcher script::

        from recto.bootloader.events import construct_from_env

        events_emitter = construct_from_env(bootloader_id=bootloader_id)
        server = create_server(
            ...,
            notify_resolved_fn=(
                events_emitter.notify_resolved
                if events_emitter is not None
                else None
            ),
        )
    """
    events_dir = (os.environ.get("RECTO_EVENTS_DIR") or "").strip()
    if not events_dir:
        return None

    try:
        return FileEventEmitter(events_dir, bootloader_id=bootloader_id)
    except OSError as ex:
        print(
            f"[recto.bootloader.events] WARNING: cannot construct "
            f"FileEventEmitter at {events_dir!r}: "
            f"{type(ex).__name__}: {ex}. Events will NOT be emitted; "
            "bootloader continues serving HTTP normally.",
            file=sys.stderr,
        )
        return None
