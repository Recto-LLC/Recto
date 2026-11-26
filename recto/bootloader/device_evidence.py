"""GATE 2b: where a registering key lives (hard rule 14.8).

A registration proves possession of a key; an algorithm name proves nothing about where that key is. This module reads
the platform vendors' own evidence, offline, at the one moment a NEW key enters the registry:

- ANDROID KEY ATTESTATION is about the identity key itself: the chain's leaf certifies that very key, made inside the
  TEE or StrongBox of a phone whose boot state is verified and locked, for this registration's challenge.
- iOS APP ATTEST is about the app, not the identity key: a genuine instance of an app this bootloader names vouched
  for this identity key and this poll key, on this challenge. That the identity key is in the Secure Enclave then rests
  on that app's own code, which makes identity keys nowhere else.

The vendors' roots gate admission, never identity: nothing after admission reads a certificate again. What an iPhone
whose App Attest key this registry keeps adds to its signed acts is an ASSERTION by that key, verified here against the
kept public key alone (verify_assertion). An Android phone adds nothing: its identity key is the attested key and signs
those acts already.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

from recto.bootloader import BootloaderError

EVIDENCE_MODES = ("record", "require")
# The same two words for what a phone with a kept App Attest key adds to its signed acts. `record` by default.
DEFAULT_APPROVAL_MODE = "record"
UNPAIR_MODES = ("off", "record", "require")
DEFAULT_UNPAIR_MODE = "record"
# `require` refuses a new key without evidence; `record` verifies and stores, and refuses nothing.
DEFAULT_MODE = "require"

ATTESTED, TEST, UNVERIFIED = "attested", "test", "unverified"
ADMITTED_CLASSES = (ATTESTED, TEST)

ANDROID_CHALLENGE_PREFIX = "recto-key-attest-v1"
IOS_CLIENT_DATA_PREFIX = "recto-attest-v1"
ASSERTION_PREFIX = "recto-assert-v1"

# THE ROOTS. Google publishes two at https://android.googleapis.com/attestation/root (also listed at
# https://developer.android.com/privacy-and-security/security-key-attestation). Each is pinned by the SHA-256 of its
# SubjectPublicKeyInfo, because Google reissues the RSA root's certificate over one key. The value says whether an
# EXPIRED factory intermediate below it is tolerated: that page asks verifiers to keep trusting factory-provisioned
# chains under the RSA root past their dates, and never a remotely provisioned one.
ROOTS_REVIEWED = "2026-11-25"
ROOTS_REVIEW_DUE = "2027-05-25"
ANDROID_ROOTS: dict[str, bool] = {
    # RSA-4096, subject serialNumber f92009e853b6b045
    "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae": True,
    # EC P-384, "Key Attestation CA1", signs chains since 2026-02-01
    "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec": False,
}
# https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
APPLE_APP_ATTEST_ROOT = b"""-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----
"""

_OID_ANDROID_ATTESTATION = "1.3.6.1.4.1.11129.2.1.17"
_OID_APPLE_NONCE = "1.2.840.113635.100.8.2"
_MAX_CERTS = 6
_MAX_CERT_BYTES = 8192
_MAX_ATTESTATION_BYTES = 32768
_MAX_ASSERTION_BYTES = 2048
# apple_validation_category_01: TestFlight and App Store builds.
IOS_VALIDATION_CATEGORIES = frozenset({2, 4})


REASONS = frozenset({
    "algorithm", "assertion_signature", "app_mismatch", "boot_state", "chain_expired", "chain_not_ca", "chain_shape", "chain_signature",
    "challenge_mismatch", "counter", "environment", "extension_missing", "extension_smuggled", "key_imported",
    "key_mismatch", "key_purpose", "key_revoked", "malformed", "root_unknown", "security_level",
})


class EvidenceInvalid(ValueError):
    """Evidence that does not verify. ``reason`` is one of REASONS and is all the exception holds: ``why`` is read in
    this file and kept nowhere, so nothing of a certificate can ride an exception into an answer or a log."""

    def __init__(self, reason: str, why: str = "") -> None:
        super().__init__(reason if reason in REASONS else "malformed")
        self.reason: str = self.args[0]


@dataclass(frozen=True)
class DevicePolicy:
    """What this bootloader asks of a new key. Read once, at startup."""

    mode: str = field(default_factory=lambda: DEFAULT_MODE)
    # (package name, lower-case hex SHA-256 of the signing certificate). Empty: any app on a locked phone.
    android_apps: frozenset[tuple[str, str]] = frozenset()
    # "<team id>.<bundle id>". Empty: no iOS evidence verifies, because App Attest is only about an app that is named.
    ios_app_ids: frozenset[str] = frozenset()
    # Certificate serials (lower-case hex) the vendor has revoked or suspended.
    revoked_serials: frozenset[str] = frozenset()
    revocations_loaded: bool = False
    android_roots: dict[str, bool] = field(default_factory=lambda: dict(ANDROID_ROOTS))
    apple_root_pem: bytes = APPLE_APP_ATTEST_ROOT
    ios_validation_categories: frozenset[int] = IOS_VALIDATION_CATEGORIES
    approval_mode: str = DEFAULT_APPROVAL_MODE
    # What the unpair relay asks of the phone: "off", "record" or "require" (hard rule 14.11).
    unpair_mode: str = DEFAULT_UNPAIR_MODE

    def __post_init__(self) -> None:
        if self.unpair_mode not in UNPAIR_MODES:
            raise ValueError("the unpair identity mode (RECTO_UNPAIR_IDENTITY_MODE) must be one of "
                             f"{UNPAIR_MODES}; got {self.unpair_mode!r}")
        if self.approval_mode not in EVIDENCE_MODES:
            raise ValueError("the approval evidence mode (RECTO_APPROVAL_EVIDENCE_MODE) must be one of "
                             f"{EVIDENCE_MODES}; got {self.approval_mode!r}")
        if self.mode not in EVIDENCE_MODES:
            raise ValueError(f"the device evidence mode (RECTO_DEVICE_EVIDENCE_MODE) must be one of {EVIDENCE_MODES}; "
                             f"got {self.mode!r}")

    @classmethod
    def from_env(cls, environ: Any) -> DevicePolicy:
        """RECTO_DEVICE_EVIDENCE_MODE, RECTO_APPROVAL_EVIDENCE_MODE, RECTO_UNPAIR_IDENTITY_MODE,
        RECTO_ATTESTATION_ANDROID_APPS, RECTO_ATTESTATION_IOS_APP_IDS and RECTO_ATTESTATION_STATUS_FILE. A value that cannot be read refuses the start; it is never read as unset."""
        def items(name: str) -> list[str]:
            return [v.strip() for v in (environ.get(name) or "").split(",") if v.strip()]

        mode = (environ.get("RECTO_DEVICE_EVIDENCE_MODE") or "").strip().lower() or DEFAULT_MODE
        apps = set()
        for item in items("RECTO_ATTESTATION_ANDROID_APPS"):
            package, _, digest = item.partition("=")
            digest = digest.replace(":", "").strip().lower()
            if not package.strip() or len(digest) != 64 or not set(digest) <= set("0123456789abcdef"):
                raise ValueError("RECTO_ATTESTATION_ANDROID_APPS is <package>=<sha256 of the signing certificate>, "
                                 "comma-separated")
            apps.add((package.strip(), digest))
        ios = items("RECTO_ATTESTATION_IOS_APP_IDS")
        if any("." not in a for a in ios):
            raise ValueError("RECTO_ATTESTATION_IOS_APP_IDS is <team id>.<bundle id>, comma-separated")
        revoked: frozenset[str] = frozenset()
        status_file = (environ.get("RECTO_ATTESTATION_STATUS_FILE") or "").strip()
        if status_file:
            try:
                with open(status_file, encoding="utf-8") as fh:
                    revoked = frozenset(str(k).lower().lstrip("0") for k in json.load(fh)["entries"])
            except (OSError, ValueError, KeyError, TypeError) as exc:
                raise ValueError(f"RECTO_ATTESTATION_STATUS_FILE does not read ({type(exc).__name__})") from exc
        approval = (environ.get("RECTO_APPROVAL_EVIDENCE_MODE") or "").strip().lower() or DEFAULT_APPROVAL_MODE
        unpair = (environ.get("RECTO_UNPAIR_IDENTITY_MODE") or "").strip().lower() or DEFAULT_UNPAIR_MODE
        return cls(mode=mode, approval_mode=approval, unpair_mode=unpair, android_apps=frozenset(apps),
                   ios_app_ids=frozenset(ios), revoked_serials=revoked, revocations_loaded=bool(status_file))

    def describe(self) -> list[str]:
        """The startup lines: each property this policy has, and each it does not."""
        return [
            f"Device evidence: {self.mode}" + ("" if self.mode == "require" else
                                               " (a new key without evidence is admitted as unverified)"),
            f"Approval evidence: {self.approval_mode}" + (
                " (a phone with a kept App Attest key answers with it, or is refused)"
                if self.approval_mode == "require" else
                " (a missing assertion is accepted and noted; a wrong one is refused)"),
            f"  - roots: {len(self.android_roots)} Android, 1 Apple; reviewed {ROOTS_REVIEWED}, "
            f"review due {ROOTS_REVIEW_DUE}",
            "  - Android apps: " + (f"{len(self.android_apps)} allowed" if self.android_apps
                                    else "NOT CHECKED (any app on a locked phone; set RECTO_ATTESTATION_ANDROID_APPS)"),
            "  - iOS App IDs: " + (f"{len(self.ios_app_ids)} allowed" if self.ios_app_ids
                                   else "NONE (no iOS evidence verifies; set RECTO_ATTESTATION_IOS_APP_IDS)"),
            "  - revocations: " + (f"{len(self.revoked_serials)} serial(s)" if self.revocations_loaded
                                   else "NOT CHECKED (set RECTO_ATTESTATION_STATUS_FILE)"),
        ]


@dataclass(frozen=True)
class AppAttestKey:
    """The one thing kept of an App Attest object (hard rule 14.8): the attested key, by its id and public half, and
    the counter of its last act. Never in an answer, a log line or a relay; hence the repr."""

    key_id: str
    public_key_b64u: str
    counter: int = 0

    def __repr__(self) -> str:
        return "AppAttestKey(...)"


@dataclass(frozen=True)
class DeviceFacts:
    """What a registration keeps. The evidence itself is dropped."""

    device_class: str = UNVERIFIED
    platform: str | None = None
    at_unix: int = 0
    test_label: str | None = None
    # The one-time test-device code still to spend when the key enters the registry.
    test_code: str | None = None
    app_attest: AppAttestKey | None = None
    # True when THIS registration's evidence named the key above (and it was not already held).
    app_attest_new: bool = False

    @property
    def admitted(self) -> bool:
        return self.device_class in ADMITTED_CLASSES

    @staticmethod
    def today() -> int:
        """The date, as the unix second it began: when in the day a phone paired is not kept."""
        return int(time.time()) // 86400 * 86400

    def as_doc(self, *, with_key: bool = False) -> dict[str, Any]:
        """``with_key``: only for a key that is seated without another registration (the owner reset)."""
        doc: dict[str, Any] = {"class": self.device_class, "platform": self.platform, "at_unix": self.at_unix,
                               "test_label": self.test_label}
        if with_key and self.app_attest is not None:
            doc["app_attest"] = [self.app_attest.key_id, self.app_attest.public_key_b64u]
        return doc

    @classmethod
    def from_doc(cls, doc: Any) -> DeviceFacts | None:
        if not isinstance(doc, dict) or doc.get("class") not in (*ADMITTED_CLASSES, UNVERIFIED):
            return None
        key = doc.get("app_attest")
        return cls(doc["class"], doc.get("platform"), int(doc.get("at_unix") or 0), doc.get("test_label"),
                   app_attest=AppAttestKey(str(key[0]), str(key[1])) if isinstance(key, list) and len(key) == 2 else None)


def android_challenge(registration_challenge: str) -> bytes:
    """What the phone passes to setAttestationChallenge. The key is named by the leaf certificate itself, so the
    challenge carries only what ties that key's making to this registration."""
    return hashlib.sha256(f"{ANDROID_CHALLENGE_PREFIX}|{registration_challenge}".encode("ascii")).digest()


def ios_client_data_hash(registration_challenge: str, identity_key_b64u: str, poll_key_b64u: str) -> bytes:
    return hashlib.sha256(
        f"{IOS_CLIENT_DATA_PREFIX}|{registration_challenge}|{identity_key_b64u}|{poll_key_b64u}".encode("ascii")
    ).digest()


def assertion_client_data_hash(act: str, ident: str, payload: bytes, fresh: str) -> bytes:
    """What an assertion is over: the act, the card or challenge it answers, the bytes the phone's own key signs for
    it, and the value this bootloader issued with it. One spelling per act, so an assertion for one opens no other."""
    digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode("ascii")
    return hashlib.sha256(f"{ASSERTION_PREFIX}|{act}|{ident}|{digest}|{fresh}".encode("utf-8")).digest()


def verify_assertion(assertion: Any, *, policy: DevicePolicy, public_key_b64u: str, client_data_hash: bytes) -> int:
    """The counter of an App Attest assertion that verifies, or EvidenceInvalid. The caller advances the stored counter
    with it, in the store's own act: an assertion opens once."""
    try:
        return _verify_assertion(_b64(assertion, _MAX_ASSERTION_BYTES), policy, public_key_b64u, client_data_hash)
    except (EvidenceInvalid, BootloaderError):
        raise
    except Exception as exc:    # noqa: BLE001
        raise EvidenceInvalid("malformed", type(exc).__name__) from None


def _verify_assertion(raw: bytes, policy: DevicePolicy, public_key_b64u: str, client_data_hash: bytes) -> int:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    obj, end = _cbor(raw)
    if end != len(raw) or not isinstance(obj, dict):
        raise EvidenceInvalid("malformed", "not an assertion")
    signature, auth = obj.get("signature"), obj.get("authenticatorData")
    if not isinstance(signature, bytes) or not isinstance(auth, bytes) or len(auth) < 37:
        raise EvidenceInvalid("malformed", "not an assertion")
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + _b64(public_key_b64u, 64))
    try:
        key.verify(signature, hashlib.sha256(auth + client_data_hash).digest(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise EvidenceInvalid("assertion_signature", "not this phone's key, or not this act") from None
    # The kept key was attested for a named app. With no App ID named any more there is nothing to compare it with.
    if policy.ios_app_ids and auth[:32] not in {hashlib.sha256(a.encode("utf-8")).digest() for a in policy.ios_app_ids}:
        raise EvidenceInvalid("app_mismatch", "the app is not on this bootloader's list")
    _check_auth_extensions(auth, 37, policy)
    return int.from_bytes(auth[33:37], "big")


def _check_auth_extensions(auth: bytes, at: int, policy: DevicePolicy) -> None:
    if at >= len(auth):
        return
    extensions, at = _cbor(auth, at)
    if at != len(auth) or not isinstance(extensions, dict):
        raise EvidenceInvalid("malformed", "bytes after the authenticator data")
    category = extensions.get("apple_validation_category_01")
    if category is not None and (not isinstance(category, bytes) or
                                 int.from_bytes(category, "little") not in policy.ios_validation_categories):
        raise EvidenceInvalid("app_mismatch", "not a TestFlight or App Store build")


def verify_evidence(evidence: Any, *, policy: DevicePolicy, challenge: str, public_key_b64u: str,
                    poll_public_key_b64u: str, algorithm: str, now: float | None = None,
                    ) -> tuple[str, AppAttestKey | None]:
    """The platform whose evidence verifies, with the App Attest key when that is what it is, or EvidenceInvalid - the
    one answer to anything a parser trips on."""
    try:
        return _verify_evidence(evidence, policy, challenge, public_key_b64u, poll_public_key_b64u, algorithm,
                                time.time() if now is None else now)
    except (EvidenceInvalid, BootloaderError):
        raise
    except Exception as exc:    # noqa: BLE001
        raise EvidenceInvalid("malformed", type(exc).__name__) from None


def _verify_evidence(evidence: Any, policy: DevicePolicy, challenge: str, public_key_b64u: str,
                     poll_public_key_b64u: str, algorithm: str, when: float) -> tuple[str, AppAttestKey | None]:
    if not isinstance(evidence, dict):
        raise EvidenceInvalid("malformed", "device_evidence must be an object")
    if algorithm != "ecdsa-p256":
        raise EvidenceInvalid("algorithm", "only an ecdsa-p256 identity key carries evidence")
    platform = evidence.get("platform")
    if platform == "android":
        chain = evidence.get("chain")
        if not isinstance(chain, list) or not 3 <= len(chain) <= _MAX_CERTS:
            raise EvidenceInvalid("chain_shape", f"an Android chain has 3 to {_MAX_CERTS} certificates")
        verify_android_chain([_b64(c, _MAX_CERT_BYTES) for c in chain], policy=policy,
                             challenge=android_challenge(challenge),
                             identity_point=_b64(public_key_b64u, 128), now=when)
        return "android", None
    if platform == "ios":
        kept = verify_app_attest(_b64(evidence.get("attestation"), _MAX_ATTESTATION_BYTES),
                                 key_id=_b64(evidence.get("key_id"), 64), policy=policy, now=when,
                                 client_data_hash=ios_client_data_hash(challenge, public_key_b64u,
                                                                       poll_public_key_b64u))
        return "ios", kept
    raise EvidenceInvalid("malformed", "platform must be android or ios")


def _b64(value: Any, limit: int) -> bytes:
    """Standard or url-safe base64, padded or not."""
    if not isinstance(value, str) or not value or len(value) > limit * 2:
        raise EvidenceInvalid("malformed", "a base64 field is missing or too long")
    text = value.rstrip("=").replace("-", "+").replace("_", "/")
    try:
        raw = base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    except ValueError:
        raise EvidenceInvalid("malformed", "a field is not base64") from None
    if len(raw) > limit:
        raise EvidenceInvalid("malformed", "a base64 field is too long")
    return raw


# --- certificate chains ---------------------------------------------------


def _load(der: bytes) -> Any:
    try:
        from cryptography import x509
    except ImportError as exc:
        raise BootloaderError(
            "v0.4 bootloader requires `cryptography`; install via `pip install recto[v0_4]`."
        ) from exc
    try:
        cert = x509.load_der_x509_certificate(der)
        _ = cert.extensions     # parsed now, so a malformed or repeated extension refuses here
        return cert
    except Exception as exc:    # noqa: BLE001 - every parse failure is one refusal
        raise EvidenceInvalid("malformed", f"a certificate does not parse ({type(exc).__name__})") from None


def _spki(cert: Any) -> bytes:
    from cryptography.hazmat.primitives import serialization
    try:
        return cert.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
    except Exception as exc:    # noqa: BLE001
        raise EvidenceInvalid("malformed", f"a certificate's key does not parse ({type(exc).__name__})") from None


def _ext(cert: Any, oid: str) -> Any:
    return next((e for e in cert.extensions if e.oid.dotted_string == oid), None)


def _ext_bytes(cert: Any, oid: str) -> bytes | None:
    ext = _ext(cert, oid)
    return None if ext is None else ext.value.value


def _point(cert: Any) -> bytes | None:
    """The 64-byte X||Y of a P-256 certificate key, or None."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = cert.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        return None
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]


def _check_issued(cert: Any, issuer: Any) -> None:
    """``issuer`` signed ``cert``: the names chain, the signature verifies, with a key and a hash worth having."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    key = issuer.public_key()
    strong = (isinstance(key, rsa.RSAPublicKey) and key.key_size >= 2048) or (
        isinstance(key, ec.EllipticCurvePublicKey) and key.curve.key_size >= 256)
    try:
        if not strong or not isinstance(cert.signature_hash_algorithm, (hashes.SHA256, hashes.SHA384, hashes.SHA512)):
            raise EvidenceInvalid("chain_signature", "a weak key or hash signs the chain")
        cert.verify_directly_issued_by(issuer)
    except EvidenceInvalid:
        raise
    except Exception as exc:    # noqa: BLE001 - a bad name, signature or algorithm is one refusal
        raise EvidenceInvalid("chain_signature", type(exc).__name__) from None


def _check_ca(cert: Any, below: int) -> None:
    """``cert`` may issue, with at most the CAs ``below`` it allowed by its path length."""
    from cryptography import x509
    basic = next((e.value for e in cert.extensions if isinstance(e.value, x509.BasicConstraints)), None)
    usage = next((e.value for e in cert.extensions if isinstance(e.value, x509.KeyUsage)), None)
    if basic is None or not basic.ca or (usage is not None and not usage.key_cert_sign):
        raise EvidenceInvalid("chain_not_ca", "a certificate that may not issue signs the chain")
    if basic.path_length is not None and below > basic.path_length:
        raise EvidenceInvalid("chain_not_ca", "a certificate's path length is exceeded")


def _check_leaf(cert: Any) -> None:
    from cryptography import x509
    if any(isinstance(e.value, x509.BasicConstraints) and e.value.ca for e in cert.extensions):
        raise EvidenceInvalid("chain_not_ca", "the leaf is itself a certificate authority")


def _check_criticals(cert: Any) -> None:
    from cryptography import x509
    if any(e.critical and not isinstance(e.value, (x509.BasicConstraints, x509.KeyUsage)) for e in cert.extensions):
        raise EvidenceInvalid("chain_shape", "a critical extension this verifier does not read")


def _check_dates(cert: Any, now: float, *, expiry: bool = True) -> None:
    if now < cert.not_valid_before_utc.timestamp():
        raise EvidenceInvalid("chain_expired", "a certificate is not valid yet")
    if expiry and now > cert.not_valid_after_utc.timestamp():
        raise EvidenceInvalid("chain_expired", "a certificate has expired")


# --- DER ------------------------------------------------------------------


class _Der:
    """A strict DER reader over one value: definite minimal lengths, nothing left over."""

    def __init__(self, data: bytes) -> None:
        self.data, self.at = data, 0

    def done(self) -> bool:
        return self.at >= len(self.data)

    def _byte(self) -> int:
        if self.done():
            raise EvidenceInvalid("malformed", "truncated DER")
        self.at += 1
        return self.data[self.at - 1]

    def next(self) -> tuple[int, int, bytes]:
        """(class and constructed bits, tag number, content)."""
        first = self._byte()
        number = first & 0x1F
        if number == 0x1F:
            number = 0
            for i in range(5):
                b = self._byte()
                if i == 0 and b == 0x80:
                    raise EvidenceInvalid("malformed", "a padded DER tag")
                number = (number << 7) | (b & 0x7F)
                if not b & 0x80:
                    break
            else:
                raise EvidenceInvalid("malformed", "an oversized DER tag")
            if number < 0x1F:
                raise EvidenceInvalid("malformed", "a long-form DER tag that fits the short form")
        length = self._byte()
        if length >= 0x80:
            octets = length & 0x7F
            if not 1 <= octets <= 3:
                raise EvidenceInvalid("malformed", "an indefinite or oversized DER length")
            length = 0
            for _ in range(octets):
                length = (length << 8) | self._byte()
            if length < 0x80 or length < 1 << (8 * (octets - 1)):
                raise EvidenceInvalid("malformed", "a padded DER length")
        if self.at + length > len(self.data):
            raise EvidenceInvalid("malformed", "truncated DER")
        content = self.data[self.at:self.at + length]
        self.at += length
        return first & 0xE0, number, content

    def take(self, tag: int) -> bytes:
        """The content of the next element, which must be the universal ``tag`` (an identifier byte)."""
        kind, number, content = self.next()
        if kind | number != tag:
            raise EvidenceInvalid("malformed", "an unexpected DER element")
        return content


_SEQ, _SET, _INT, _ENUM, _OCTETS, _BOOL = 0x30, 0x31, 0x02, 0x0A, 0x04, 0x01


def _only(data: bytes, tag: int) -> bytes:
    der = _Der(data)
    content = der.take(tag)
    if not der.done():
        raise EvidenceInvalid("malformed", "bytes after a DER value")
    return content


def _int(content: bytes) -> int:
    if not content or len(content) > 8 or (len(content) > 1 and content[0] == 0 and content[1] < 0x80):
        raise EvidenceInvalid("malformed", "a DER integer")
    return int.from_bytes(content, "big", signed=True)


def _auth_list(content: bytes) -> dict[int, bytes]:
    """tag number -> the explicit value. A repeated tag refuses: two readers must never pick differently."""
    der, out = _Der(content), {}
    while not der.done():
        kind, number, value = der.next()
        if kind != 0xA0 or number in out:
            raise EvidenceInvalid("malformed", "the authorization list")
        out[number] = value
    return out


# --- Android key attestation ---------------------------------------------

_TAG_PURPOSE, _TAG_ORIGIN, _TAG_ROOT_OF_TRUST, _TAG_APPLICATION_ID = 1, 702, 704, 709
_PURPOSE_SIGN, _ORIGIN_GENERATED, _BOOT_VERIFIED = 2, 0, 0
_HARDWARE_LEVELS = (1, 2)   # TrustedEnvironment, StrongBox


def verify_android_chain(chain: list[bytes], *, policy: DevicePolicy, challenge: bytes, identity_point: bytes,
                         now: float) -> None:
    certs = [_load(der) for der in chain]
    leaf, issuers, root = certs[0], certs[1:], certs[-1]
    pin = hashlib.sha256(_spki(root)).hexdigest()
    if pin not in policy.android_roots:
        raise EvidenceInvalid("root_unknown", "the chain does not end at a root this bootloader pins")
    _check_issued(root, root)   # the pin is the key's: the name and dates around it are the root's only if it signed them
    for cert, issuer in zip(certs, issuers, strict=False):
        _check_issued(cert, issuer)
    _check_leaf(leaf)
    # A FACTORY chain's topmost issuer is named by a serial number. Two things are true of those alone, and only under
    # the root that says so: they are trusted past their dates, and the batch key that signs the leaf is not marked as a
    # CA. A remotely provisioned chain has neither allowance.
    factory = policy.android_roots[pin] and len(certs) == 4 and any(
        a.oid.dotted_string == "2.5.4.5" for a in issuers[-2].subject)
    for below, cert in enumerate(issuers):
        if not (factory and below == 0):
            _check_ca(cert, below)
        # The leaf's dates are the phone's own writing, so only the issuers' are read.
        _check_dates(cert, now, expiry=not factory)
        # THE SMUGGLED EXTENSION: hardware writes it in the leaf it issues and nowhere else. A key that was itself
        # attested can sign a further certificate carrying a forged one; its own is then no longer in the leaf.
        if _ext(cert, _OID_ANDROID_ATTESTATION) is not None:
            raise EvidenceInvalid("extension_smuggled", "an issuer carries an attestation extension")
    for cert in certs:
        _check_criticals(cert)
        if format(cert.serial_number, "x") in policy.revoked_serials:
            raise EvidenceInvalid("key_revoked", "the vendor revoked a certificate of the chain")
    if _point(leaf) != identity_point:
        raise EvidenceInvalid("key_mismatch", "the attested key is not the registering key")
    raw = _ext_bytes(leaf, _OID_ANDROID_ATTESTATION)
    if raw is None:
        raise EvidenceInvalid("extension_missing", "the leaf carries no attestation extension")
    der = _Der(_only(raw, _SEQ))
    _int(der.take(_INT))
    attestation_level = _int(der.take(_ENUM))
    _int(der.take(_INT))
    keymint_level = _int(der.take(_ENUM))
    attested_challenge = der.take(_OCTETS)
    der.take(_OCTETS)
    software, hardware = _auth_list(der.take(_SEQ)), _auth_list(der.take(_SEQ))
    if not der.done():
        raise EvidenceInvalid("malformed", "bytes after the key description")
    if attestation_level not in _HARDWARE_LEVELS or keymint_level not in _HARDWARE_LEVELS:
        raise EvidenceInvalid("security_level", "the key or its attestation is software")
    if attested_challenge != challenge:
        raise EvidenceInvalid("challenge_mismatch", "the attestation is for another registration")
    if _TAG_ORIGIN not in hardware or _int(_only(hardware[_TAG_ORIGIN], _INT)) != _ORIGIN_GENERATED:
        raise EvidenceInvalid("key_imported", "the key was not generated in the hardware")
    purposes = _Der(_only(hardware.get(_TAG_PURPOSE, b""), _SET))
    allowed = set()
    while not purposes.done():
        allowed.add(_int(purposes.take(_INT)))
    if _PURPOSE_SIGN not in allowed:
        raise EvidenceInvalid("key_purpose", "the key does not sign")
    if _TAG_ROOT_OF_TRUST not in hardware:
        raise EvidenceInvalid("boot_state", "the hardware states no root of trust")
    trust = _Der(_only(hardware[_TAG_ROOT_OF_TRUST], _SEQ))
    trust.take(_OCTETS)
    locked, state = trust.take(_BOOL), _int(trust.take(_ENUM))
    if locked != b"\xff" or state != _BOOT_VERIFIED:
        raise EvidenceInvalid("boot_state", "the phone's boot state is not verified and locked")
    if policy.android_apps:
        _check_app(software.get(_TAG_APPLICATION_ID), policy)


def _check_app(value: bytes | None, policy: DevicePolicy) -> None:
    """The (package, signer) the phone's own system states for the caller that made the key. Exactly one package and
    one signer: a shared-uid group is refused, since any app in it could have made the key."""
    if value is None:
        raise EvidenceInvalid("app_mismatch", "the attestation names no app")
    der = _Der(_only(_only(value, _OCTETS), _SEQ))
    packages, digests = _Der(der.take(_SET)), _Der(der.take(_SET))
    package = _Der(packages.take(_SEQ))
    name, digest = package.take(_OCTETS), digests.take(_OCTETS)
    if not packages.done() or not digests.done() or not der.done():
        raise EvidenceInvalid("app_mismatch", "the attestation names more than one app or signer")
    if (name.decode("utf-8", "replace"), digest.hex()) not in policy.android_apps:
        raise EvidenceInvalid("app_mismatch", "the app or its signer is not on this bootloader's list")


# --- CBOR and App Attest --------------------------------------------------


def _cbor(data: bytes, at: int = 0, depth: int = 0) -> tuple[Any, int]:
    """One value and the offset past it. Strict: definite minimal lengths, unique map keys, and only the kinds an
    attestation object holds (integers, byte and text strings, arrays, maps)."""
    if depth > 6 or at >= len(data):
        raise EvidenceInvalid("malformed", "CBOR")
    major, info = data[at] >> 5, data[at] & 0x1F
    at += 1
    if info < 24:
        arg = info
    elif info <= 27:
        size = 1 << (info - 24)
        if at + size > len(data):
            raise EvidenceInvalid("malformed", "truncated CBOR")
        arg = int.from_bytes(data[at:at + size], "big")
        at += size
        if arg < (24 if size == 1 else 1 << (4 * size)):
            raise EvidenceInvalid("malformed", "a padded CBOR length")
    else:
        raise EvidenceInvalid("malformed", "an indefinite CBOR length")
    if major == 0:
        return arg, at
    if major == 1:
        return -1 - arg, at
    if major in (2, 3):
        if at + arg > len(data):
            raise EvidenceInvalid("malformed", "truncated CBOR")
        raw = data[at:at + arg]
        if major == 2:
            return raw, at + arg
        try:
            return raw.decode("utf-8"), at + arg
        except UnicodeDecodeError:
            raise EvidenceInvalid("malformed", "CBOR text") from None
    if major == 4:
        items = []
        for _ in range(arg):
            item, at = _cbor(data, at, depth + 1)
            items.append(item)
        return items, at
    if major == 5:
        out: dict[Any, Any] = {}
        for _ in range(arg):
            key, at = _cbor(data, at, depth + 1)
            if not isinstance(key, (int, str)) or key in out:
                raise EvidenceInvalid("malformed", "a CBOR map key")
            out[key], at = _cbor(data, at, depth + 1)
        return out, at
    raise EvidenceInvalid("malformed", "a CBOR kind an attestation never holds")


_AAGUID_PRODUCTION = b"appattest" + bytes(7)


def verify_app_attest(attestation: bytes, *, key_id: bytes, client_data_hash: bytes, policy: DevicePolicy,
                      now: float) -> AppAttestKey:
    from cryptography import x509
    obj, end = _cbor(attestation)
    if end != len(attestation) or not isinstance(obj, dict) or obj.get("fmt") != "apple-appattest":
        raise EvidenceInvalid("malformed", "not an App Attest object")
    statement, auth = obj.get("attStmt"), obj.get("authData")
    x5c = statement.get("x5c") if isinstance(statement, dict) else None
    if (not isinstance(auth, bytes) or not isinstance(x5c, list) or len(x5c) != 2
            or not all(isinstance(c, bytes) and len(c) <= _MAX_CERT_BYTES for c in x5c)):
        raise EvidenceInvalid("chain_shape", "App Attest carries a credential certificate and one intermediate")
    leaf, intermediate = _load(x5c[0]), _load(x5c[1])
    root = x509.load_pem_x509_certificate(policy.apple_root_pem)
    _check_issued(intermediate, root)
    _check_issued(leaf, intermediate)
    _check_leaf(leaf)
    _check_ca(intermediate, 0)
    for cert in (leaf, intermediate, root):
        _check_criticals(cert)
        _check_dates(cert, now)
    nonce = hashlib.sha256(auth + client_data_hash).digest()
    raw = _ext_bytes(leaf, _OID_APPLE_NONCE)
    if raw is None:
        raise EvidenceInvalid("extension_missing", "the credential certificate carries no nonce")
    tagged = _Der(_only(raw, _SEQ))
    kind, number, value = tagged.next()
    if not tagged.done() or kind != 0xA0 or number != 1 or _only(value, _OCTETS) != nonce:
        raise EvidenceInvalid("challenge_mismatch", "the attestation is for another registration")
    point = _point(leaf)
    if point is None or hashlib.sha256(b"\x04" + point).digest() != key_id:
        raise EvidenceInvalid("key_mismatch", "the key id is not the attested key's")
    if len(auth) < 37 + 18 + 32:
        raise EvidenceInvalid("malformed", "the authenticator data is short")
    if auth[:32] not in {hashlib.sha256(a.encode("utf-8")).digest() for a in policy.ios_app_ids}:
        raise EvidenceInvalid("app_mismatch", "the app is not on this bootloader's list")
    if int.from_bytes(auth[33:37], "big") != 0:
        raise EvidenceInvalid("counter", "the attested key has been used")
    if auth[37:53] != _AAGUID_PRODUCTION:
        raise EvidenceInvalid("environment", "not App Attest's production environment")
    if int.from_bytes(auth[53:55], "big") != 32 or auth[55:87] != key_id:
        raise EvidenceInvalid("key_mismatch", "the credential id is not the key id")
    cose, at = _cbor(auth, 87)
    if not isinstance(cose, dict) or cose.get(-2) != point[:32] or cose.get(-3) != point[32:]:
        raise EvidenceInvalid("key_mismatch", "the authenticator data names another key")
    _check_auth_extensions(auth, at, policy)

    def spelled(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
    return AppAttestKey(spelled(key_id), spelled(point))
