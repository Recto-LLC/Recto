"""Hard rule 14.8: nothing of the evidence outlives its check.

Every field of every certificate (and of an App Attest object) carries a value found nowhere else. Each test walks one
path through a real server and then reads everything that path could have left: the state dir's files, the stores and
the server's own memory, every answer, every log record, stdout and stderr, and what the relay sent. Only the class,
the platform, the date and a test label may be there.
"""

from __future__ import annotations

import ast
import base64
import dataclasses
import json
import logging
import time
import urllib.request
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from recto.bootloader import device_codes as dc  # noqa: E402
from recto.bootloader import device_evidence as de  # noqa: E402
from recto.bootloader.server import MEMBER_REBIND_PREFIX, BootloaderHandler  # noqa: E402
from recto.bootloader.state import PhoneRegistration  # noqa: E402
from tests import test_approval_evidence as acts  # noqa: E402
from tests import test_bootloader_owner_slots as owner_slots  # noqa: E402
from tests import test_bootloader_slots as slots  # noqa: E402
from tests import test_device_evidence_register as reg  # noqa: E402
from tests import test_top_plane_e2e as top_plane_e2e  # noqa: E402
from tests.device_evidence_builder import (  # noqa: E402
    APP_ID,
    AndroidVendor,
    AppleVendor,
    application_id,
    b64u,
    certificate,
    context,
    der,
    integer,
    key_description,
    p256,
    point,
    tlv,
    wire,
)
from tests.test_bootloader_owner_slots import CONSUMER, _subject, serving  # noqa: E402
from tests.test_bootloader_slots import Phone, _approve_owner_cards  # noqa: E402
from tests.test_device_evidence_register import HwPhone, _member_challenge, owner_challenge  # noqa: E402
from tests.test_top_plane_e2e import _approve, _host, _op_key, _reset_code, _seed_chain, _top_cards, tp  # noqa: E402

REAL_DEVICE_DEFAULT = True

# THE CLOSED LIST (hard rule 14.8): the device fields a phone's record has, and the fields of the evidence itself that
# may outlive its check (named as the Canaries below name them) - the App Attest key, in the store and nowhere else. The
# rule and these two change together.
KEPT_FIELDS = {"device_class", "device_platform", "device_class_at_unix", "device_test_label", "app_attest_key_id",
               "app_attest_public_key_b64u", "app_attest_counter", "act_class", "act_class_at_unix"}
KEPT_OF_THE_EVIDENCE = frozenset({"app attest key id", "app attest key"})


class Canaries:
    """Distinct values, and every way one could be written down."""

    def __init__(self) -> None:
        self.forms: dict[str, str] = {}      # how it is written -> which field it came from
        self._n = 0

    def blob(self, name: str, size: int = 16) -> bytes:
        self._n += 1
        raw = (f"CaNaRy{self._n:03d}" + "kQzXvJ" * size)[:size].encode("ascii")
        return self.add(name, raw)

    def add(self, name: str, raw: bytes) -> bytes:
        number = int.from_bytes(raw, "big")
        for form in (raw.decode("latin-1"), raw.hex(), raw.hex().upper(), ":".join(f"{b:02X}" for b in raw), str(number),
                     base64.b64encode(raw).decode().rstrip("=")[:-1], base64.urlsafe_b64encode(raw).decode().rstrip("=")[:-1],
                     repr(raw)[2:-1]):
            self.forms[form] = name
        return raw

    def text(self, name: str) -> str:
        return self.blob(name, 20).decode("ascii")

    def number(self, name: str, size: int = 8) -> int:
        self._n += 1
        value = int.from_bytes(bytes([0x51, 0xC7]) + self._n.to_bytes(2, "big") + b"\x5e\xed\xca\xfe\x13\x37\xbe\xef"[:size - 4], "big")
        for form in (str(value), format(value, "x"), format(value, "X")):
            self.forms[form] = name
        return value

    def wire(self, name: str, text: str) -> None:
        """A field exactly as it was sent: any stretch of it."""
        for i in range(0, max(1, len(text) - 40), 12):
            self.forms[text[i:i + 40]] = name


class CanaryVendor(AndroidVendor):
    def __init__(self, c: Canaries, **kw: Any) -> None:
        super().__init__(**kw)
        self.c = c

        def name(who: str) -> x509.Name:
            return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, c.text(f"{who} subject")),
                              x509.NameAttribute(NameOID.SERIAL_NUMBER, c.text(f"{who} subject serial"))])
        root_name, mid_name, self.batch_name = name("root"), name("intermediate"), name("batch")
        span = {"not_before": self.start, "not_after": self.end}
        extra = ("1.3.6.1.4.1.11129.2.1.30", tlv(0x04, c.blob("provisioning extension")))
        self.root = certificate(root_name, self.root_key.public_key(), root_name, self.root_key, ca=True,
                                serial=c.number("root serial"), **span)
        self.mid = certificate(mid_name, self.mid_key.public_key(), root_name, self.root_key, ca=True,
                               serial=c.number("intermediate serial"), **span)
        self.batch = certificate(self.batch_name, self.batch_key.public_key(), mid_name, self.mid_key, ca=True,
                                 serial=c.number("batch serial"), extension=extra, **span)
        for who, key in (("root", self.root_key), ("intermediate", self.mid_key), ("batch", self.batch_key)):
            pub = key.public_key()
            c.add(f"{who} public key", pub.public_bytes(serialization.Encoding.X962,
                                                        serialization.PublicFormat.UncompressedPoint)[1:])
            c.add(f"{who} spki", pub.public_bytes(serialization.Encoding.DER,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo))
        c.add("batch fingerprint", self.batch.fingerprint(hashes.SHA256()))
        self.package, self.signer = c.text("package"), c.blob("signer", 32)
        self.fields = {
            "unique_id": c.blob("unique id"), "boot_key": c.blob("boot key", 32), "boot_hash": c.blob("boot hash", 32),
            "app": application_id(self.package, self.signer),
            "extra_hardware": b"".join(
                [context(tag, integer(c.number(f"tag {tag}"))) for tag in (705, 706, 718, 719)]
                + [context(tag, tlv(0x04, c.blob(f"tag {tag}"))) for tag in (710, 711, 712, 713, 714, 715, 716, 717)]),
        }

    def evidence(self, key: Any, registration_challenge: str, **kw: Any) -> dict[str, Any]:
        """``kw`` as key_description's, over the canaries."""
        c = self.c
        challenge = c.add("attested challenge", de.android_challenge(registration_challenge))
        leaf = certificate(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, c.text("leaf subject"))]), key.public_key(),
                           self.batch_name, self.batch_key, ca=None, not_before=self.start, not_after=self.end,
                           serial=c.number("leaf serial"),
                           extension=("1.3.6.1.4.1.11129.2.1.17", key_description(challenge, **{**self.fields, **kw})))
        c.add("leaf signature", leaf.signature)
        out = wire([der(x) for x in (leaf, self.batch, self.mid, self.root)])
        for i, text in enumerate(out["chain"]):
            c.wire(f"certificate {i}", text)
        return out


class CanaryApple(AppleVendor):
    def __init__(self, c: Canaries) -> None:
        super().__init__()
        self.c = c

    def evidence(self, registration_challenge: str, identity_b64u: str, poll_b64u: str, **kw: Any) -> dict[str, Any]:
        c, key = self.c, kw.pop("key", None) or p256()
        cdh = c.add("client data hash", de.ios_client_data_hash(registration_challenge, identity_b64u, poll_b64u))
        obj, key_id = self.attestation(cdh, key=key, receipt=c.blob("receipt", 48), subject=c.text("credential subject"),
                                       serial=c.number("credential serial"), **kw)
        c.add("app attest key id", key_id)
        c.add("app attest key", point(key))
        out = {"platform": "ios", "key_id": base64.b64encode(key_id).decode(),
               "attestation": base64.b64encode(obj).decode()}
        c.wire("attestation object", out["attestation"])
        return out


class Watch:
    """Everything a path can leave behind."""

    def __init__(self, tmp_path: Path, caplog: Any, capfd: Any, monkeypatch: Any, warned: Any) -> None:
        self.warned = warned
        self.c, self.dir, self.caplog, self.capfd = Canaries(), tmp_path, caplog, capfd
        self.answers: list[str] = []
        self.allowed: set[str] = set()
        self.ctxs: list[Any] = []
        real = slots._http

        def heard(method: str, url: str, body: Any = None, headers: Any = None):
            status, answer = real(method, url, body, headers=headers)
            self.answers.append(f"{status} {json.dumps(answer)}")
            return status, answer
        for module in (slots, reg, owner_slots, top_plane_e2e, acts):
            monkeypatch.setattr(module, "_http", heard)
        self.http = heard
        caplog.set_level(logging.DEBUG)

    def phone(self, label: str = "phone") -> HwPhone:
        p = HwPhone(label)
        # The identity key is what the registry names the phone by; its own spellings are not the evidence's.
        for k in (p.key, p.poll_key):
            raw = point(k)
            self.allowed |= {b64u(raw), base64.b64encode(raw).decode().rstrip("="), raw.hex(), str(int.from_bytes(raw, "big"))}
        return p

    def left(self) -> tuple[str, str]:
        """(what only the phones' store holds, everything else)"""
        parts, stored = list(self.answers), []
        for path in sorted(self.dir.rglob("*")):
            if path.is_file() and path.name not in (dc.KEY_NAME, "bootloader.lock"):
                (stored if path.name in ("phones.json", "top_plane.json") else parts).append(
                    f"{path.name} {path.read_bytes().decode('latin-1')}")
        for ctx in self.ctxs:
            state = ctx["state"]
            # A phone's repr leaves the kept key out, so a log line that prints one stays clean.
            parts += [repr(state.list_phones()), repr(state.list_owner_enrolls()),
                      repr({k: v for k, v in vars(state).items() if "top_plane" not in k}), repr(vars(ctx["challenges"]))]
            stored += [repr([dataclasses.asdict(p) for p in state.list_phones()]), repr(state.list_top_plane_records())]
        config = BootloaderHandler.config
        parts += [repr({k: getattr(config, k, None) for k in dir(config) if not k.startswith("__") and k != "device_policy"})]
        if config.code_limiter is not None:
            parts.append(repr(vars(config.code_limiter)))
        for r in self.caplog.records:
            parts.append(f"{r.getMessage()} {r.args!r} {r.exc_info!r} {r.exc_text!r} {r.stack_info!r}")
        out = self.capfd.readouterr()
        parts += [out.out, out.err, *[str(w.message) for w in self.warned]]

        def without_the_key(text: str) -> str:
            for spelling in sorted(self.allowed, key=len, reverse=True):
                text = text.replace(spelling, "(the key)")
            return text
        return without_the_key("\n".join(stored)), without_the_key("\n".join(parts))

    def check(self) -> None:
        assert self.c.forms, "the walk sent no evidence"
        stored, text = self.left()
        assert "attested" in text + stored or "unverified" in text or "device_evidence" in text or "internal" in text \
            or "test" in text or "invalid JSON" in text
        found = {name for form, name in self.c.forms.items() if form in text}
        # The kept key is taken out of its one place before that place is searched: the object it came in holds its bytes
        # too, and a stretch of them may fall on the same letters.
        for form, _ in sorted(((f, n) for f, n in self.c.forms.items() if n in KEPT_OF_THE_EVIDENCE), key=lambda x: -len(x[0])):
            stored = stored.replace(form, "(kept)")
        found |= {name for form, name in self.c.forms.items() if form in stored}
        assert not found, f"the evidence outlived its check: {sorted(found)}"


@pytest.fixture
def watch(tmp_path, caplog, capfd, monkeypatch, recwarn):
    return Watch(tmp_path, caplog, capfd, monkeypatch, recwarn)


@pytest.fixture
def vendor(watch):
    return CanaryVendor(watch.c)


def _serve(watch: Watch, policy: Any, **kw: Any):
    cm = serving(watch.dir, device_policy=policy, **kw)

    class _Noted:
        def __enter__(self):
            ctx = cm.__enter__()
            watch.ctxs.append(ctx)
            return ctx

        def __exit__(self, *exc):
            return cm.__exit__(*exc)
    return _Noted()


def test_the_search_finds_what_is_there(watch, vendor) -> None:
    """The instrument: each way of writing each field is seen when it is left."""
    vendor.evidence(watch.phone().key, "c")
    assert len({n for n in watch.c.forms.values()}) > 35
    for form, name in watch.c.forms.items():
        watch.answers = [f"device_evidence {form}"]
        watch.caplog.clear()
        with pytest.raises(AssertionError, match="outlived"):
            watch.check()
        assert name


# --- accepted -------------------------------------------------------------


def test_an_accepted_chain(watch, vendor) -> None:
    policy = vendor.policy(android_apps=frozenset({(vendor.package, vendor.signer.hex())}))
    with _serve(watch, policy) as ctx:
        owner, member = watch.phone(), watch.phone()
        assert owner.register(ctx, vendor=vendor)[0] == 201
        assert member.register(ctx, challenge=_member_challenge(ctx, "member-1"), vendor=vendor)[0] == 201
        assert owner.register(ctx, vendor=vendor)[0] == 201
        owner.read_pending(ctx)
        watch.check()


def test_an_accepted_app_attest_object(watch) -> None:
    apple = CanaryApple(watch.c)
    policy = de.DevicePolicy(mode="require", ios_app_ids=frozenset({APP_ID}), apple_root_pem=apple.root_pem)
    with _serve(watch, policy) as ctx:
        phone = watch.phone()
        status, body = phone.register(ctx, vendor=apple)
        assert status == 201 and body["app_attest_kept"] is True
        stored, text = watch.left()
        kept = [form for form, name in watch.c.forms.items() if name in KEPT_OF_THE_EVIDENCE]
        assert any(form in stored for form in kept) and not any(form in text for form in kept), "kept in one place only"
        watch.check()


@pytest.mark.parametrize("mode", ["record", "require"])
def test_the_acts_of_a_phone_with_a_kept_key(watch, mode) -> None:
    """An assertion's own bytes, accepted, refused, replayed and garbled, on an approval, a deny and the phone list."""
    apple = CanaryApple(watch.c)
    policy = de.DevicePolicy(mode="require", approval_mode=mode, ios_app_ids=frozenset({APP_ID}), apple_root_pem=apple.root_pem)
    with _serve(watch, policy) as ctx:
        phone = acts.iphone(watch.phone(), apple)
        assert phone.enrol(ctx)[0] == 201
        for shape in ("good", "wrong card", "garbled", "replayed", "missing", "deny"):
            card = acts.queue(ctx, phone)
            assertion = None if shape == "missing" else phone.for_card(card, decision="denied" if shape == "deny" else "approved")
            if shape == "wrong card":
                assertion = phone.for_card(acts.queue(ctx, phone))
            if shape == "garbled":
                assertion = assertion[:40] + "!" + assertion[40:]
            if shape == "replayed":
                assert phone.answer(ctx, card, assertion)[0] == 200
                card = acts.queue(ctx, phone)
            for a in (assertion,):
                if a:
                    watch.c.wire("assertion", a)
            phone.answer(ctx, card, assertion, decision="denied" if shape == "deny" else "approved")
        phone.read_pending(ctx)
        watch.check()


# --- refused, and recorded ------------------------------------------------

BAD: dict[str, dict[str, Any]] = {
    "security_level": {"level": 0}, "boot_state": {"locked": b"\x00"}, "key_imported": {"origin": 2},
    "key_purpose": {"purposes": (7,)}, "malformed": {"trailing": b"\x05\x00"}, "repeated tag": {"repeat_tag": True},
}


@pytest.mark.parametrize("mode", ["require", "record"])
@pytest.mark.parametrize("case", [*BAD, "app", "revoked", "expired", "root", "other key", "other challenge", "garbled"])
def test_a_chain_that_does_not_verify(watch, case, mode) -> None:
    import datetime as dt
    vendor = CanaryVendor(watch.c, **({"now": dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=90)} if case == "expired" else {}))
    policy = vendor.policy(mode=mode)
    if case == "app":
        policy = vendor.policy(mode=mode, android_apps=frozenset({("other.app", "0" * 64)}))
    if case == "revoked":
        policy = vendor.policy(mode=mode, revoked_serials=frozenset({format(vendor.batch.serial_number, "x")}))
    if case == "root":
        policy = AndroidVendor().policy(mode=mode)
    with _serve(watch, policy) as ctx:
        phone, challenge = watch.phone(), owner_challenge(ctx)
        evidence = vendor.evidence(watch.phone().key if case == "other key" else phone.key,
                                   "another" if case == "other challenge" else challenge, **BAD.get(case, {}))
        if case == "garbled":
            evidence["chain"][1] = evidence["chain"][1][:200] + "!" + evidence["chain"][1][200:]
        status, body = phone.register(ctx, challenge=challenge, evidence=evidence)
        if mode == "require":
            assert (status, body["error"]) == (403, "device_evidence_invalid") and body["reason"] in de.REASONS
            assert set(body) == {"error", "reason", "detail"}
        else:
            assert (status, body["device_class"]) == (201, "unverified")
        watch.check()


@pytest.mark.parametrize("kw", [{"counter": 1}, {"aaguid": b"appattestdevelop"}, {"app_id": "T.other"}, {"category": 3},
                                {"nonce": bytes(32)}, {"tail": b"\x00"}])
@pytest.mark.parametrize("mode", ["require", "record"])
def test_an_app_attest_object_that_does_not_verify(watch, mode, kw) -> None:
    apple = CanaryApple(watch.c)
    policy = de.DevicePolicy(mode=mode, ios_app_ids=frozenset({APP_ID}), apple_root_pem=apple.root_pem)
    with _serve(watch, policy) as ctx:
        status, _ = watch.phone().register(ctx, vendor=apple, **kw)
        assert status == (403 if mode == "require" else 201)
        watch.check()


def test_bad_evidence_beside_a_test_code(watch, vendor) -> None:
    with _serve(watch, vendor.policy()) as ctx:
        code = dc.issue(watch.dir, plane="owner", label="emulator-1")[0]
        status, body = watch.phone().register(ctx, vendor=vendor, level=0, test_code=code)
        assert (status, body["device_class"]) == (201, "test")
        status, _ = watch.phone().register(ctx, challenge=_member_challenge(ctx, "m"), vendor=vendor, level=0, test_code=code)
        assert status == 403
        watch.check()


# --- where a verdict waits ------------------------------------------------


def test_the_slot_question_and_the_second_pass(watch, vendor) -> None:
    with _serve(watch, vendor.policy()) as ctx:
        owner, second = watch.phone("owner"), watch.phone("second")
        assert owner.register(ctx, vendor=vendor)[0] == 201
        challenge = owner_challenge(ctx)
        assert second.register(ctx, challenge=challenge, vendor=vendor)[0] == 409
        watch.check()
        assert second.register(ctx, challenge=challenge, vendor=vendor, replace=owner.ref)[0] == 403
        waiting = ctx["state"].list_owner_enrolls()
        assert [set(r["device"]) for r in waiting] == [{"class", "platform", "at_unix", "test_label"}]
        assert waiting[0]["incoming_pubkey"] == second.pub, "the verdict is the key's own record's"
        watch.check()
        _approve_owner_cards(ctx, owner)
        watch.check()
        assert second.register(ctx, replace=owner.ref)[0] == 201
        watch.check()


def test_a_contested_slot_and_a_hand_over(watch, vendor) -> None:
    with _serve(watch, vendor.policy()) as ctx:
        owner, a, b = watch.phone(), watch.phone(), watch.phone()
        assert owner.register(ctx, vendor=vendor)[0] == 201
        assert a.register(ctx, "recovery", vendor=vendor)[0] == 403
        assert b.register(ctx, "recovery", vendor=vendor)[1]["error"] == "owner_slot_contested"
        old, new = watch.phone(), watch.phone()
        assert old.register(ctx, challenge=_member_challenge(ctx, "m"), vendor=vendor)[0] == 201
        challenge = _member_challenge(ctx, "m")
        assert new.register(ctx, challenge=challenge, vendor=vendor)[0] == 409
        challenge = _member_challenge(ctx, "m")
        rebind = b64u(old.identity.sign(
            f"{MEMBER_REBIND_PREFIX}|{CONSUMER}|{_subject('m')}|{old.ref}|{new.pub}|{challenge}".encode()))
        assert new.register(ctx, challenge=challenge, vendor=vendor, rebind=rebind)[0] == 201
        watch.check()


def test_the_owner_reset(watch, vendor) -> None:
    with _serve(watch, vendor.policy(mode="record"), capability_operator_pubkey=_op_key()) as ctx:
        BootloaderHandler.config.owner_reset_window_seconds = 1
        try:
            r, p = Phone("recovery"), Phone("primary")
            assert r.register(ctx, "recovery")[0] == 201
            p.register(ctx, "primary")
            _approve_owner_cards(ctx, r)
            assert p.register(ctx, "primary")[0] == 201
            _seed_chain(ctx["state"], r)
            assert _host(tp.seal_id, ctx)[0] == 0
            assert _approve(ctx, r, _top_cards(ctx, r)[0])[0] == 200
            BootloaderHandler.config.device_policy = vendor.policy()

            def said(out: str) -> dict[str, Any]:
                return json.loads(next(line for line in out.splitlines() if line.strip().startswith("{")))
            iid = said(_host(tp.reset_start, ctx, slot="primary", slot_list=["primary"], confirm=p.ref, window_seconds=1)[1])["intent_id"]
            time.sleep(1.5)
            code = _reset_code(_host(tp.reset_arm, ctx, arm=iid, slot="primary")[1])
            challenge = watch.http("GET", f"{ctx['base_url']}/v0.4/registration_challenge?code={code}")[1]["challenge_b64u"]
            fresh = watch.phone()
            assert fresh.register(ctx, challenge=challenge, vendor=vendor, level=0)[0] == 403
            assert fresh.register(ctx, challenge=challenge, vendor=vendor)[0] == 202
            record = next(x for x in ctx["state"].list_top_plane_records() if x.get("fresh"))
            assert set(record["fresh"]["device"]) == {"class", "platform", "at_unix", "test_label"}
            watch.check()
            assert _host(tp.reset_complete, ctx, complete=iid, slot="primary")[0] == 0
            assert ctx["state"].get_phone(fresh.ref).device_class == "attested"
            watch.check()
        finally:
            BootloaderHandler.config.owner_reset_window_seconds = 72 * 3600


# --- faults ---------------------------------------------------------------


@pytest.mark.parametrize("where", ["recto.bootloader.device_evidence._verify_evidence", "recto.bootloader.server.verify_evidence",
                                   "recto.bootloader.device_evidence._check_issued"])
def test_a_fault_whose_own_text_is_the_evidence(watch, vendor, monkeypatch, where) -> None:
    def fault(*args: Any, **kw: Any) -> None:
        raise RuntimeError(f"{args!r} {kw!r} " + " ".join(watch.c.forms))
    monkeypatch.setattr(where, fault)
    with _serve(watch, vendor.policy()) as ctx:
        status, body = watch.phone().register(ctx, vendor=vendor)
        assert status in (403, 500), body
        watch.check()


def test_a_connection_that_drops_while_the_refusal_is_sent(watch, vendor, monkeypatch) -> None:
    """The server's own last-resort traceback, printed by the socket server when an answer cannot be written."""
    real = BootloaderHandler._send_json

    def drop(self, status, body):
        if body.get("error") in ("device_evidence_invalid", "internal"):
            raise ConnectionResetError("gone")
        real(self, status, body)
    with _serve(watch, vendor.policy()) as ctx:
        phone, challenge = watch.phone(), owner_challenge(ctx)
        evidence = vendor.evidence(phone.key, challenge, level=0)
        monkeypatch.setattr(BootloaderHandler, "_send_json", drop)
        with pytest.raises(OSError):
            phone.register(ctx, challenge=challenge, evidence=evidence)
        time.sleep(0.3)
        monkeypatch.setattr(BootloaderHandler, "_send_json", real)
        watch.answers.append("device_evidence (dropped)")
        watch.check()


@pytest.mark.parametrize("cut", ["truncated", "not utf-8", "an array"])
def test_a_body_that_does_not_read(watch, vendor, cut) -> None:
    with _serve(watch, vendor.policy()) as ctx:
        raw = json.dumps({"device_evidence": vendor.evidence(watch.phone().key, "c")}).encode()
        raw = {"truncated": raw[:-20], "not utf-8": raw[:50] + b"\xff" + raw[50:], "an array": b"[" + raw + b"]"}[cut]
        req = urllib.request.Request(f"{ctx['base_url']}/v0.4/register", data=raw, method="POST",
                                     headers={"Content-Type": "application/json"})
        with pytest.raises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(req, timeout=5)
        watch.answers.append("device_evidence " + caught.value.read().decode())
        watch.check()


# --- the relay and the signed result --------------------------------------


def test_the_relay_and_the_signed_result(watch, vendor, monkeypatch) -> None:
    from recto.capability.signing import public_key_hex
    from tests import test_bootloader_devices_pair as pair
    sent: list[tuple[str, str]] = []

    class _Answer:
        status = 200

        def read(self) -> bytes:
            return b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *exc) -> None:
            return None

    real = urllib.request.urlopen

    def relay(request, **kw):
        if "/devices/pairing/complete" in getattr(request, "full_url", ""):
            sent.append((request.data.decode(), repr(request.headers)))
            return _Answer()
        return real(request, **kw)
    monkeypatch.setattr("recto.bootloader.server.urllib.request.urlopen", relay)
    priv, pub = pair._keypair()
    key = bytes(range(1, 33))
    with _serve(watch, vendor.policy(), devices_pair_consumer_webhook_tokens={CONSUMER: "tok"}, devices_pair_signing_key=key) as ctx:
        phone = watch.phone()
        assert phone.register(ctx, challenge=_member_challenge(ctx, "user-1"), vendor=vendor)[0] == 201
        record = pair._record({"pub": pub}, bootloader_id=BootloaderHandler.config.bootloader_id, subject=_subject("user-1"))
        grant = pair._grant({"priv": priv, "pub": pub}, record)
        grant = _regrant(pair, grant, priv, BootloaderHandler.config.bootloader_id)
        status, body = watch.http("POST", f"{ctx['base_url']}/v0.4/devices/pair", {
            "consumer_base_url": CONSUMER, "record": record.to_dict(), "user_jws": grant})
        assert status == 200 and len(sent) == 1, body
        forwarded = json.loads(sent[0][0])
        assert forwarded["deviceClass"] == "attested"
        payload = forwarded["bootloaderJws"].split(".")[1]
        claims = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode()
        assert json.loads(claims)["cap"]["scope"]["device_class"] == "attested" and public_key_hex(key)
        watch.answers += [*sent[0], claims]
        watch.check()


def _regrant(pair: Any, _grant: str, priv: int, bootloader_id: str) -> str:
    """The grant, for this server's id (the pair suite's helper names its own)."""
    payload = _grant.split(".")[1]
    d = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    from recto.capability.types import CapabilityClaims, CapabilityClause, CapabilityScope
    cap = d["cap"]
    return pair._mint(CapabilityClaims(
        iss=d["iss"], sub=d["sub"], aud=[bootloader_id, "consumer"], iat=d["iat"], nbf=d["nbf"], exp=d["exp"], jti=d["jti"],
        cap=CapabilityClause(tier=cap["tier"], registry_version=cap["registry_version"],
                             scope=CapabilityScope(payload_sha256=cap["scope"]["payload_sha256"],
                                                   pairing_code=cap["scope"]["pairing_code"]),
                             allow_actions=cap["allow_actions"]),
        purpose=d["purpose"], max_uses=d["max_uses"]), priv)


# --- the shapes -----------------------------------------------------------


def test_a_phones_record_has_four_device_fields_and_no_others() -> None:
    """Both backends store the dataclass's fields, so this is the whole of what either can hold."""
    assert {f.name for f in dataclasses.fields(PhoneRegistration)} == {
        "phone_id", "device_label", "public_key_b64u", "supported_algorithms", "registered_at_unix", "last_seen_unix",
        "push_token", "push_platform", "poll_public_key_b64u", "slot", "member_bindings", "member_grant_keys"} | KEPT_FIELDS


def test_an_evidence_exception_holds_its_reason_and_nothing_else() -> None:
    exc = de.EvidenceInvalid("malformed", "CANARY")
    assert exc.args == ("malformed",) and vars(exc) == {"reason": "malformed"} and "CANARY" not in f"{exc!r}{exc}"
    assert de.EvidenceInvalid("CANARY").reason == "malformed", "a reason is one of the fixed names"


def test_every_reason_raised_is_a_fixed_name() -> None:
    tree = ast.parse(Path(de.__file__).read_text(encoding="utf-8"))
    reasons = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "EvidenceInvalid":
            assert isinstance(node.args[0], ast.Constant), ast.dump(node)
            reasons.add(node.args[0].value)
    assert reasons == de.REASONS


def test_the_modules_that_see_the_evidence_write_nothing() -> None:
    """The verifier has no logger, no print, no file and no store."""
    source = Path(de.__file__).read_text(encoding="utf-8")
    assert "import logging" not in source and "print(" not in source and source.count("open(") == 1   # the status file's read
