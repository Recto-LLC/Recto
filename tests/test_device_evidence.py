"""GATE 2b, the verifier (hard rule 14.8): what a vendor's evidence must say, and every way it may not."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402

from recto.bootloader import device_codes as dc  # noqa: E402
from recto.bootloader import device_evidence as de  # noqa: E402
from tests import device_evidence_vectors as vectors  # noqa: E402
from tests.device_evidence_builder import (  # noqa: E402
    APP_ID,
    PACKAGE,
    SIGNER,
    AndroidVendor,
    AppleVendor,
    application_id,
    b64u,
    cbor,
    certificate,
    cn,
    der,
    key_description,
    p256,
    point,
    wire,
)

REAL_DEVICE_DEFAULT = True
CHALLENGE = "challenge-of-this-registration"


def _at(*when: int) -> float:
    return dt.datetime(*when, tzinfo=dt.timezone.utc).timestamp()


def _android(vendor: AndroidVendor, key, chain_or_evidence, *, policy=None, challenge=CHALLENGE, now=None) -> str:
    evidence = chain_or_evidence if isinstance(chain_or_evidence, dict) else wire(chain_or_evidence)
    return de.verify_evidence(evidence, policy=policy or vendor.policy(), challenge=challenge,
                              public_key_b64u=b64u(point(key)), poll_public_key_b64u="poll", algorithm="ecdsa-p256",
                              now=now)[0]


def _refused(reason: str, *args, **kw) -> None:
    with pytest.raises(de.EvidenceInvalid) as caught:
        _android(*args, **kw)
    assert caught.value.reason == reason


# --- published vectors ----------------------------------------------------


def _published(name: str):
    chain = [base64.b64decode(c) for c in getattr(vectors, name)]
    leaf = x509.load_der_x509_certificate(chain[0])
    reader = de._Der(de._only(de._ext_bytes(leaf, de._OID_ANDROID_ATTESTATION), 0x30))
    for _ in range(4):
        reader.next()
    return chain, reader.take(0x04), de._point(leaf)


@pytest.mark.parametrize(("name", "when"), [
    ("ANDROID_STRONGBOX_RKP_2026_ROOT", (2026, 2, 25)),
    ("ANDROID_TEE_RKP", (2025, 9, 27)),
    ("ANDROID_TEE_FACTORY", (2026, 11, 25)),     # past its dates, under the root that allows it
])
def test_a_real_phones_chain_verifies_under_the_pinned_roots(name, when) -> None:
    chain, challenge, pt = _published(name)
    de.verify_android_chain(chain, policy=de.DevicePolicy(), challenge=challenge, identity_point=pt, now=_at(*when))


@pytest.mark.parametrize("name", ["ANDROID_STRONGBOX_RKP_2026_ROOT", "ANDROID_TEE_RKP"])
def test_a_remotely_provisioned_chain_is_refused_past_its_dates(name) -> None:
    chain, challenge, pt = _published(name)
    with pytest.raises(de.EvidenceInvalid, match="chain_expired"):
        de.verify_android_chain(chain, policy=de.DevicePolicy(), challenge=challenge, identity_point=pt,
                                now=_at(2026, 11, 25))


def test_a_real_chains_app_is_read() -> None:
    chain, challenge, pt = _published("ANDROID_STRONGBOX_RKP_2026_ROOT")
    signer = "103938ee4537e59e8ee792f654504fb8346fc6b346d0bbc4415fc339fcfc8ec1"
    for package, ok in (("com.google.android.attestation", True), ("app.example.other", False)):
        policy = de.DevicePolicy(android_apps=frozenset({(package, signer)}))
        try:
            de.verify_android_chain(chain, policy=policy, challenge=challenge, identity_point=pt,
                                    now=_at(2026, 2, 25))
            assert ok
        except de.EvidenceInvalid as exc:
            assert exc.reason == "app_mismatch" and not ok


def test_apples_published_attestation_object_verifies() -> None:
    policy = de.DevicePolicy(ios_app_ids=frozenset({"1234567890.com.example.myapp"}),
                             ios_validation_categories=frozenset({1}))
    obj = base64.b64decode(vectors.APPLE_ATTESTATION)
    key_id = base64.b64decode("zgSY9YSD+7TaDXssY6WlOPVS1K3Lmk+pFhlcSWE+ZV0=")
    call = {"key_id": key_id, "client_data_hash": b"example_server_challenge", "policy": policy}
    de.verify_app_attest(obj, now=_at(2026, 4, 21, 18), **call)
    with pytest.raises(de.EvidenceInvalid, match="chain_expired"):
        de.verify_app_attest(obj, now=_at(2026, 11, 25), **call)


def test_the_pinned_roots_are_the_published_ones() -> None:
    assert set(de.ANDROID_ROOTS) == {
        hashlib.sha256(de._spki(x509.load_der_x509_certificate(base64.b64decode(c[-1])))).hexdigest()
        for c in (vectors.ANDROID_TEE_FACTORY, vectors.ANDROID_STRONGBOX_RKP_2026_ROOT)}
    assert [k for k, allows_expired in de.ANDROID_ROOTS.items() if allows_expired] == [
        hashlib.sha256(de._spki(x509.load_der_x509_certificate(
            base64.b64decode(vectors.ANDROID_TEE_FACTORY[-1])))).hexdigest()]


# --- Android, synthetic ---------------------------------------------------


@pytest.mark.parametrize("level", [1, 2])
def test_a_hardware_key_verifies(level) -> None:
    vendor, key = AndroidVendor(), p256()
    assert _android(vendor, key, vendor.evidence(key, CHALLENGE, level=level)) == "android"


def test_a_factory_chain_verifies_past_its_dates_and_only_under_its_root() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    vendor, key = AndroidVendor(factory=True, now=now - dt.timedelta(days=400)), p256()
    evidence = vendor.evidence(key, CHALLENGE)
    assert _android(vendor, key, evidence) == "android"
    vendor.roots = {vendor.pin: False}
    _refused("chain_not_ca", vendor, key, evidence)


def test_a_factory_chain_is_never_longer_than_its_shape() -> None:
    vendor, key, signer = AndroidVendor(factory=True, batch_ca=True), p256(), p256()
    challenge = de.android_challenge(CHALLENGE)
    middle = vendor.leaf(signer, None, ca=False)
    leaf = certificate(cn("k"), key.public_key(), cn("Android Keystore Key"), signer, ca=None, not_before=vendor.start,
                       not_after=vendor.end, extension=(de._OID_ANDROID_ATTESTATION, key_description(challenge)))
    _refused("chain_not_ca", vendor, key, [der(c) for c in (leaf, middle, vendor.batch, vendor.mid, vendor.root)])


@pytest.mark.parametrize(("reason", "kw"), [
    ("security_level", {"level": 0}),
    ("security_level", {"level": 2, "keymint_level": 0}),
    ("security_level", {"level": 0, "keymint_level": 2}),
    ("boot_state", {"locked": b"\x00"}),
    ("boot_state", {"locked": b"\x01"}),
    ("boot_state", {"boot_state": 1}),
    ("boot_state", {"boot_state": 2}),
    ("boot_state", {"root_of_trust": False}),
    ("boot_state", {"root_of_trust_in_software": True}),
    ("key_imported", {"origin": 2}),
    ("key_purpose", {"purposes": (7,)}),
    ("malformed", {"repeat_tag": True}),
    ("malformed", {"trailing": b"\x05\x00"}),
])
def test_what_the_hardware_says_is_read(reason, kw) -> None:
    vendor, key = AndroidVendor(), p256()
    _refused(reason, vendor, key, vendor.evidence(key, CHALLENGE, **kw))


def test_an_attestation_of_another_key_is_refused() -> None:
    vendor, hardware, software = AndroidVendor(), p256(), p256()
    _refused("key_mismatch", vendor, software, vendor.evidence(hardware, CHALLENGE))


def test_an_attestation_for_another_challenge_is_refused() -> None:
    vendor, key = AndroidVendor(), p256()
    _refused("challenge_mismatch", vendor, key, vendor.evidence(key, "an earlier challenge"))


def test_an_unknown_root_is_refused() -> None:
    vendor, stranger, key = AndroidVendor(), AndroidVendor(), p256()
    _refused("root_unknown", vendor, key, stranger.evidence(key, CHALLENGE))


def test_the_pinned_roots_name_over_another_key_is_refused() -> None:
    vendor, stranger, key = AndroidVendor(), AndroidVendor(), p256()
    chain = stranger.chain(key, de.android_challenge(CHALLENGE))
    _refused("chain_signature", vendor, key, [*chain[:-1], der(vendor.root)])


def test_a_root_written_again_around_the_pinned_key_is_refused() -> None:
    """The pinned key with other dates: nothing but the root's own signature says they are not its dates."""
    now = dt.datetime.now(dt.timezone.utc)
    vendor, key = AndroidVendor(now=now - dt.timedelta(days=4000), days=8000), p256()
    rewritten = certificate(vendor.root.subject, vendor.root_key.public_key(), vendor.root.subject, p256(), ca=True,
                            not_before=vendor.start, not_after=now + dt.timedelta(days=400))
    chain = vendor.chain(key, de.android_challenge(CHALLENGE))
    _refused("chain_signature", vendor, key, [*chain[:-1], der(rewritten)])


def test_a_chain_past_its_dates_or_before_them_is_refused() -> None:
    key, now = p256(), dt.datetime.now(dt.timezone.utc)
    for when in (now - dt.timedelta(days=40), now + dt.timedelta(days=40)):
        vendor = AndroidVendor(now=when)
        _refused("chain_expired", vendor, key, vendor.evidence(key, CHALLENGE))


def test_an_expired_root_is_refused() -> None:
    vendor, key = AndroidVendor(now=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=4000), days=8000), p256()
    _refused("chain_expired", vendor, key, vendor.evidence(key, CHALLENGE))


def test_a_certificate_appended_below_an_attested_key_is_refused() -> None:
    """The attested hardware key signs a certificate for a software key and copies an extension into it."""
    vendor, hardware, software = AndroidVendor(), p256(), p256()
    challenge = de.android_challenge(CHALLENGE)
    attested = vendor.leaf(hardware, key_description(challenge))
    forged = certificate(cn("Android Keystore Key"), software.public_key(), cn("Android Keystore Key"), hardware,
                         ca=None, not_before=vendor.start, not_after=vendor.end,
                         extension=(de._OID_ANDROID_ATTESTATION, key_description(challenge)))
    chain = [der(c) for c in (forged, attested, vendor.batch, vendor.mid, vendor.root)]
    _refused("chain_not_ca", vendor, software, chain)


def test_an_issuer_carrying_an_attestation_extension_is_refused_even_as_a_ca() -> None:
    vendor, hardware, software = AndroidVendor(), p256(), p256()
    challenge = de.android_challenge(CHALLENGE)
    attested = vendor.leaf(hardware, key_description(challenge), ca=True)
    forged = certificate(cn("Android Keystore Key"), software.public_key(), cn("Android Keystore Key"), hardware,
                         ca=None, not_before=vendor.start, not_after=vendor.end,
                         extension=(de._OID_ANDROID_ATTESTATION, key_description(challenge)))
    chain = [der(c) for c in (forged, attested, vendor.batch, vendor.mid, vendor.root)]
    _refused("chain_expired", vendor, software, chain, now=dt.datetime(1960, 1, 1, tzinfo=dt.timezone.utc).timestamp())
    _refused("extension_smuggled", vendor, software, chain)


def test_the_factory_shape_smuggles_nothing() -> None:
    """The one issuer a factory chain excuses from the CA flag still may not carry an attestation extension."""
    vendor, hardware, software = AndroidVendor(factory=True), p256(), p256()
    challenge = de.android_challenge(CHALLENGE)
    attested = certificate(vendor.batch_name, hardware.public_key(), vendor.mid.subject, vendor.mid_key, ca=False,
                           not_before=vendor.start, not_after=vendor.end,
                           extension=(de._OID_ANDROID_ATTESTATION, key_description(challenge)))
    forged = certificate(cn("k"), software.public_key(), vendor.batch_name, hardware, ca=None,
                         not_before=vendor.start, not_after=vendor.end,
                         extension=(de._OID_ANDROID_ATTESTATION, key_description(challenge)))
    _refused("extension_smuggled", vendor, software, [der(c) for c in (forged, attested, vendor.mid, vendor.root)])


@pytest.mark.parametrize("kw", [
    {"intermediate_ca": False},
    {"batch_ca": False},
    {"batch_key_usage": "sign"},
    {"intermediate_path_length": 0},
])
def test_an_issuer_that_may_not_issue_is_refused(kw) -> None:
    vendor, key = AndroidVendor(**kw), p256()
    _refused("chain_not_ca", vendor, key, vendor.evidence(key, CHALLENGE))


def test_a_leaf_that_is_a_ca_is_refused() -> None:
    vendor, key = AndroidVendor(), p256()
    leaf = vendor.leaf(key, key_description(de.android_challenge(CHALLENGE)), ca=True)
    _refused("chain_not_ca", vendor, key, [der(c) for c in (leaf, vendor.batch, vendor.mid, vendor.root)])


def test_a_weak_hash_and_an_unread_critical_extension_are_refused() -> None:
    key = p256()
    weak = AndroidVendor(hash_=hashes.SHA224())
    _refused("chain_signature", weak, key, weak.evidence(key, CHALLENGE))
    odd = AndroidVendor(batch_critical_unknown=True)
    _refused("chain_shape", odd, key, odd.evidence(key, CHALLENGE))


def test_a_leaf_with_no_extension_a_short_chain_and_a_reordered_one_are_refused() -> None:
    vendor, key = AndroidVendor(), p256()
    chain = vendor.chain(key, de.android_challenge(CHALLENGE))
    bare = [der(vendor.leaf(key, None)), *chain[1:]]
    _refused("extension_missing", vendor, key, bare)
    _refused("chain_shape", vendor, key, chain[:2])
    _refused("chain_shape", vendor, key, chain * 2)
    _refused("chain_signature", vendor, key, [chain[0], chain[2], chain[1], chain[3]])
    _refused("root_unknown", vendor, key, chain[:3])


def test_a_revoked_serial_is_refused() -> None:
    vendor, key = AndroidVendor(), p256()
    serial = format(vendor.batch.serial_number, "x")
    _refused("key_revoked", vendor, key, vendor.evidence(key, CHALLENGE),
             policy=vendor.policy(revoked_serials=frozenset({serial})))


@pytest.mark.parametrize(("app", "ok"), [
    (application_id(), True),
    (application_id(package="app.example.other"), False),
    (application_id(signer=bytes(32)), False),
    (application_id(extra_package="app.example.friend"), False),
])
def test_the_app_is_checked_when_a_list_is_set(app, ok) -> None:
    vendor, key = AndroidVendor(), p256()
    evidence = vendor.evidence(key, CHALLENGE, app=app)
    policy = vendor.policy(android_apps=frozenset({(PACKAGE, SIGNER.hex())}))
    if ok:
        assert _android(vendor, key, evidence, policy=policy) == "android"
    else:
        _refused("app_mismatch", vendor, key, evidence, policy=policy)
    assert _android(vendor, key, evidence) == "android", "an empty list checks no app"


@pytest.mark.parametrize("evidence", [
    "x", [], {}, {"platform": "android"}, {"platform": "android", "chain": "x"}, {"platform": "web", "chain": []},
    {"platform": "android", "chain": ["!", "!", "!"]}, {"platform": "android", "chain": ["AAAA", "AAAA", "AAAA"]},
    {"platform": "android", "chain": [None, 1, {}]}, {"platform": "ios"},
    {"platform": "ios", "key_id": "AAAA", "attestation": "AAAA"},
])
def test_anything_unreadable_is_evidence_invalid_and_nothing_else(evidence) -> None:
    with pytest.raises(de.EvidenceInvalid):
        _android(AndroidVendor(), p256(), evidence, policy=de.DevicePolicy(ios_app_ids=frozenset({APP_ID}))) \
            if isinstance(evidence, dict) else de.verify_evidence(
                evidence, policy=de.DevicePolicy(), challenge="c", public_key_b64u="AAAA",
                poll_public_key_b64u="AAAA", algorithm="ecdsa-p256")


def test_every_truncation_and_bit_flip_of_a_leaf_is_refused_by_the_one_error() -> None:
    vendor, key = AndroidVendor(), p256()
    chain = vendor.chain(key, de.android_challenge(CHALLENGE))
    for i in range(0, len(chain[0]), 7):
        for bad in (chain[0][:i], chain[0][:i] + bytes([chain[0][i] ^ 0x55]) + chain[0][i + 1:]):
            with pytest.raises(de.EvidenceInvalid):
                _android(vendor, key, [bad, *chain[1:]])


def test_a_fault_in_a_parser_is_evidence_invalid(monkeypatch) -> None:
    def fault(*_a):
        raise RecursionError
    monkeypatch.setattr(de, "_verify_evidence", fault)
    vendor, key = AndroidVendor(), p256()
    _refused("malformed", vendor, key, vendor.evidence(key, CHALLENGE))


def test_an_ed25519_identity_key_carries_no_evidence() -> None:
    vendor, key = AndroidVendor(), p256()
    with pytest.raises(de.EvidenceInvalid, match="algorithm"):
        de.verify_evidence(vendor.evidence(key, CHALLENGE), policy=vendor.policy(), challenge=CHALLENGE,
                           public_key_b64u=b64u(point(key)), poll_public_key_b64u="p", algorithm="ed25519")


# --- App Attest, synthetic ------------------------------------------------

IDENTITY, POLL = "identity-key", "poll-key"


def _ios(vendor: AppleVendor, *, policy=None, challenge=CHALLENGE, identity=IDENTITY, poll=POLL, evidence=None,
         **kw) -> str:
    evidence = evidence or vendor.evidence(CHALLENGE, IDENTITY, POLL, **kw)
    policy = policy or de.DevicePolicy(ios_app_ids=frozenset({APP_ID}), apple_root_pem=vendor.root_pem)
    return de.verify_evidence(evidence, policy=policy, challenge=challenge, public_key_b64u=identity,
                              poll_public_key_b64u=poll, algorithm="ecdsa-p256")[0]


@pytest.mark.parametrize("category", [2, 4, None])
def test_an_app_attest_object_verifies(category) -> None:
    assert _ios(AppleVendor(), category=category) == "ios"


@pytest.mark.parametrize(("reason", "kw"), [
    ("challenge_mismatch", {"challenge": "another"}),
    ("challenge_mismatch", {"identity": "another"}),
    ("challenge_mismatch", {"poll": "another"}),
    ("challenge_mismatch", {"nonce": bytes(32)}),
    ("app_mismatch", {"app_id": "OTHER00001.app.example.phone"}),
    ("app_mismatch", {"category": 3}),
    ("app_mismatch", {"category": 5}),
    ("counter", {"counter": 1}),
    ("environment", {"aaguid": b"appattestdevelop"}),
    ("key_mismatch", {"credential": bytes(32)}),
    ("malformed", {"tail": b"\x00"}),
    ("malformed", {"auth_tail": b"\x00"}),
    ("chain_not_ca", {"leaf": {"ca": True}}),
    ("chain_expired", {"leaf": {"not_before": dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
                                "not_after": dt.datetime(2020, 1, 4, tzinfo=dt.timezone.utc)}}),
])
def test_what_an_app_attest_object_must_say(reason, kw) -> None:
    with pytest.raises(de.EvidenceInvalid) as caught:
        _ios(AppleVendor(), **kw)
    assert caught.value.reason == reason


def test_an_app_attest_object_naming_another_key_is_refused() -> None:
    vendor = AppleVendor()
    with pytest.raises(de.EvidenceInvalid, match="key_mismatch"):
        _ios(vendor, cose_key=p256())
    evidence = vendor.evidence(CHALLENGE, IDENTITY, POLL)
    with pytest.raises(de.EvidenceInvalid, match="key_mismatch"):
        _ios(vendor, evidence={**evidence, "key_id": base64.b64encode(bytes(32)).decode()})


def test_an_app_attest_leaf_the_intermediate_did_not_sign_is_refused() -> None:
    vendor, stranger = AppleVendor(), AppleVendor()
    vendor.mid_key = stranger.mid_key
    with pytest.raises(de.EvidenceInvalid, match="chain_signature"):
        _ios(vendor)


def test_an_app_attest_key_id_is_the_attested_keys_even_when_the_credential_id_agrees_with_it() -> None:
    vendor = AppleVendor()
    evidence = vendor.evidence(CHALLENGE, IDENTITY, POLL, credential=bytes(32))
    with pytest.raises(de.EvidenceInvalid, match="key_mismatch"):
        _ios(vendor, evidence={**evidence, "key_id": base64.b64encode(bytes(32)).decode()})


def test_an_unknown_apple_root_is_refused_and_with_no_app_id_nothing_verifies() -> None:
    vendor = AppleVendor()
    with pytest.raises(de.EvidenceInvalid, match="chain_signature"):
        _ios(vendor, policy=de.DevicePolicy(ios_app_ids=frozenset({APP_ID}), apple_root_pem=AppleVendor().root_pem))
    with pytest.raises(de.EvidenceInvalid, match="app_mismatch"):
        _ios(vendor, policy=de.DevicePolicy(apple_root_pem=vendor.root_pem))


@pytest.mark.parametrize("raw", [
    b"", b"\xbf\xff", b"\x5f\x41a\xff", b"\x18\x05", b"\x19\x00\x10", b"\xa2\x01\x02\x01\x03", b"\xa1\x41a\x01",
    b"\xc0\x01", b"\xf5", b"\xfb" + bytes(8), b"\x42a", b"\x61\xff", b"\x81" * 9 + b"\x01", b"\x9b" + b"\xff" * 8,
])
def test_the_cbor_reader_is_strict(raw) -> None:
    with pytest.raises(de.EvidenceInvalid):
        de._cbor(raw)


def test_the_cbor_reader_reads_what_an_attestation_holds() -> None:
    value = {"a": [1, -7, b"x" * 300], 24: "t", -2: {"k": 70000}}
    assert de._cbor(cbor(value)) == (value, len(cbor(value)))


@pytest.mark.parametrize("raw", [b"\x30\x80\x00\x00", b"\x04\x81\x05abcde", b"\x04\x05ab", b"\x04\x82\x00\x80" + bytes(128),
                                 b"\xbf\x80\x45\x00", b"\xbf\x05\x00", b"\x04"])
def test_the_der_reader_is_strict(raw) -> None:
    with pytest.raises(de.EvidenceInvalid):
        de._Der(raw).next()


# --- the policy -----------------------------------------------------------


def test_the_shipped_default_requires_evidence_and_says_what_it_does_not_check() -> None:
    policy = de.DevicePolicy.from_env({})
    assert policy.mode == de.DEFAULT_MODE == "require"
    said = "\n".join(policy.describe())
    assert "require" in said and "NOT CHECKED (any app" in said and "NONE (no iOS" in said
    assert "revocations: NOT CHECKED" in said and de.ROOTS_REVIEW_DUE in said


def test_the_policy_reads_its_settings(tmp_path: Path) -> None:
    status = tmp_path / "status.json"
    status.write_text(json.dumps({"entries": {"0AbC": {"status": "REVOKED"}}}), encoding="utf-8")
    policy = de.DevicePolicy.from_env({
        "RECTO_DEVICE_EVIDENCE_MODE": " Record ",
        "RECTO_ATTESTATION_ANDROID_APPS": f"{PACKAGE}={':'.join(re.findall('..', SIGNER.hex().upper()))}, b.c={'0' * 64}",
        "RECTO_ATTESTATION_IOS_APP_IDS": APP_ID,
        "RECTO_ATTESTATION_STATUS_FILE": str(status),
    })
    assert policy.mode == "record" and policy.ios_app_ids == {APP_ID}
    assert policy.android_apps == {(PACKAGE, SIGNER.hex()), ("b.c", "0" * 64)}
    assert policy.revoked_serials == {"abc"}
    assert any("1 serial" in line for line in policy.describe())


@pytest.mark.parametrize("env", [
    {"RECTO_DEVICE_EVIDENCE_MODE": "off"},
    {"RECTO_ATTESTATION_ANDROID_APPS": "app.example.phone"},
    {"RECTO_ATTESTATION_ANDROID_APPS": "app.example.phone=zz"},
    {"RECTO_ATTESTATION_IOS_APP_IDS": "noteam"},
    {"RECTO_ATTESTATION_STATUS_FILE": "/no/such/file.json"},
])
def test_a_setting_that_does_not_read_refuses_the_start(env) -> None:
    with pytest.raises(ValueError):
        de.DevicePolicy.from_env(env)


# --- the test-device code -------------------------------------------------


def test_a_test_code_opens_one_plane_once(tmp_path: Path) -> None:
    dc.ensure_key(tmp_path)
    code, expires = dc.issue(tmp_path, plane="member", label="emulator-1")
    assert expires > 0 and dc.find(tmp_path, code, "owner") is None
    assert not dc.spend(tmp_path, code, "owner")
    assert dc.find(tmp_path, code.lower().replace("-", " "), "member").label == "emulator-1"
    assert dc.spend(tmp_path, code, "member") and not dc.spend(tmp_path, code, "member")
    assert dc.find(tmp_path, code, "member") is None


def test_a_test_code_is_stored_only_as_a_mac_and_lapses(tmp_path: Path, monkeypatch) -> None:
    dc.ensure_key(tmp_path)
    code, expires = dc.issue(tmp_path, plane="owner", label="bench")
    stored = [p for p in (tmp_path / dc.CODES_DIR).iterdir()]
    text = "".join(p.name + p.read_text(encoding="utf-8") for p in stored)
    assert len(stored) == 1 and dc.normalize(code) not in text and code not in text
    monkeypatch.setattr(dc.time, "time", lambda: expires + 1)
    assert dc.find(tmp_path, code, "owner") is None and not dc.spend(tmp_path, code, "owner")
    dc.issue(tmp_path, plane="owner", label="bench")
    assert len(list((tmp_path / dc.CODES_DIR).glob("*.json"))) == 1, "an expired code is swept at the next issue"


def test_a_code_copied_to_another_state_dir_opens_nothing(tmp_path: Path) -> None:
    for name in ("a", "b"):
        dc.ensure_key(tmp_path / name)
    code, _ = dc.issue(tmp_path / "a", plane="member", label="x")
    (tmp_path / "a" / dc.CODES_DIR).rename(tmp_path / "b" / dc.CODES_DIR)
    assert dc.find(tmp_path / "b", code, "member") is None


def test_the_host_verb_refuses_a_dir_no_bootloader_served_and_a_bad_request(tmp_path: Path) -> None:
    with pytest.raises(dc.TestCodeRefused, match="no bootloader"):
        dc.issue(tmp_path, plane="member", label="x")
    dc.ensure_key(tmp_path)
    for bad in ({"plane": "both"}, {"label": " "}, {"label": "x" * 41}, {"label": "a\nb"}, {"ttl_seconds": 59},
                {"ttl_seconds": 3601}):
        with pytest.raises(dc.TestCodeRefused):
            dc.issue(tmp_path, **{"plane": "member", "label": "x", **bad})
    for _ in range(dc.MAX_LIVE_CODES):
        dc.issue(tmp_path, plane="member", label="x")
    with pytest.raises(dc.TestCodeRefused, match="live"):
        dc.issue(tmp_path, plane="member", label="x")


def test_the_mac_key_is_made_once(tmp_path: Path) -> None:
    dc.ensure_key(tmp_path)
    first = (tmp_path / dc.KEY_NAME).read_bytes()
    dc.ensure_key(tmp_path)
    assert (tmp_path / dc.KEY_NAME).read_bytes() == first and len(first) == 32


def test_the_verb_prints_a_code_that_opens(tmp_path: Path) -> None:
    import io

    from recto.cli import main
    dc.ensure_key(tmp_path)
    out, err = io.StringIO(), io.StringIO()
    argv = ["bootloader", "test-device", "--state-dir", str(tmp_path), "--plane", "member", "--label", "emulator-1"]
    assert main(argv, stdout=out, stderr=err) == 0, err.getvalue()
    code = re.search(r"TEST DEVICE CODE: (\S+)", out.getvalue()).group(1)
    assert dc.spend(tmp_path, code, "member")
    assert main([*argv[:3], str(tmp_path / "none"), *argv[4:]], stdout=out, stderr=err) == 1


def test_a_code_is_read_however_it_is_typed() -> None:
    assert dc.normalize("abcde-fgh1o") == "ABCDEFGH10"
    for bad in (None, 5, "", "ABCDE", "ABCDE-FGH1U", "../../x-yz1"):
        assert dc.normalize(bad) is None
