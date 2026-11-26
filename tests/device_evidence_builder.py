"""Synthetic vendors for tests: an Android attestation root and an App Attest root, and the evidence each issues.

A server trusts one only when its ``DevicePolicy`` is given the synthetic root (``AndroidVendor.roots`` /
``AppleVendor.root_pem``); the shipped policy pins the vendors' own.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID, ObjectIdentifier

from recto.bootloader import device_evidence as de

PACKAGE = "app.example.phone"
SIGNER = bytes(range(32))
APP_ID = "TEAM000001.app.example.phone"
_FAR = dt.datetime(2048, 1, 1, tzinfo=dt.timezone.utc)
_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def point(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.X962,
                                         serialization.PublicFormat.UncompressedPoint)[1:]


def sign_raw(key: ec.EllipticCurvePrivateKey, payload: bytes) -> str:
    r, s = utils.decode_dss_signature(key.sign(payload, ec.ECDSA(hashes.SHA256())))
    return b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def p256() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    head = bytes([n]) if n < 0x80 else (bytes([0x81, n]) if n < 0x100 else bytes([0x82, n >> 8, n & 0xFF]))
    return bytes([tag]) + head + content


def context(number: int, content: bytes) -> bytes:
    """[number] EXPLICIT."""
    if number < 31:
        return tlv(0xA0 | number, content)
    body, octets = b"", []
    while number:
        octets.insert(0, number & 0x7F)
        number >>= 7
    for i, o in enumerate(octets):
        body += bytes([o | (0x80 if i < len(octets) - 1 else 0)])
    return bytes([0xBF]) + body + tlv(0, content)[1:]


def integer(v: int, tag: int = 0x02) -> bytes:
    return tlv(tag, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big"))


def application_id(package: str = PACKAGE, signer: bytes = SIGNER, extra_package: str | None = None) -> bytes:
    packages = tlv(0x30, tlv(0x04, package.encode()) + integer(22))
    if extra_package:
        packages += tlv(0x30, tlv(0x04, extra_package.encode()) + integer(1))
    return tlv(0x30, tlv(0x31, packages) + tlv(0x31, tlv(0x04, signer)))


def key_description(challenge: bytes, *, level: int = 2, keymint_level: int | None = None, locked: bytes = b"\xff",
                    boot_state: int = 0, origin: int = 0, purposes: tuple[int, ...] = (2,), app: bytes | None = None,
                    root_of_trust: bool = True, root_of_trust_in_software: bool = False, repeat_tag: bool = False,
                    trailing: bytes = b"", unique_id: bytes = b"", boot_key: bytes = bytes(32),
                    boot_hash: bytes = bytes(32), extra_hardware: bytes = b"") -> bytes:
    trust = context(704, tlv(0x30, tlv(0x04, boot_key) + tlv(0x01, locked) + integer(boot_state, 0x0A)
                             + tlv(0x04, boot_hash)))
    software = context(709, tlv(0x04, application_id() if app is None else app))
    if root_of_trust_in_software:
        software = trust + software
    hardware = (context(1, tlv(0x31, b"".join(integer(p) for p in purposes))) + context(2, integer(3))
                + context(702, integer(origin)))
    if repeat_tag:
        hardware += context(702, integer(0))
    if root_of_trust and not root_of_trust_in_software:
        hardware += trust
    hardware += extra_hardware
    return tlv(0x30, integer(300) + integer(level, 0x0A) + integer(300)
               + integer(level if keymint_level is None else keymint_level, 0x0A) + tlv(0x04, challenge)
               + tlv(0x04, unique_id) + tlv(0x30, software) + tlv(0x30, hardware) + trailing)


def certificate(subject: Any, subject_key: Any, issuer: Any, issuer_key: Any, *, ca: bool | None, not_before: Any,
                not_after: Any, extension: tuple[str, bytes] | None = None, path_length: int | None = None,
                key_usage: str | None = None, hash_: Any = None, serial: int | None = None,
                critical_unknown: bool = False) -> x509.Certificate:
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(subject_key)
         .serial_number(serial or x509.random_serial_number()).not_valid_before(not_before).not_valid_after(not_after))
    if ca is not None:
        b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=path_length if ca else None), critical=True)
    usage = key_usage or ("cert" if ca else "sign")
    b = b.add_extension(x509.KeyUsage(
        digital_signature=usage == "sign", content_commitment=False, key_encipherment=False, data_encipherment=False,
        key_agreement=False, key_cert_sign=usage == "cert", crl_sign=False, encipher_only=False,
        decipher_only=False), critical=True)
    if extension is not None:
        b = b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier(extension[0]), extension[1]), critical=False)
    if critical_unknown:
        b = b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.55555.1"), b"\x05\x00"),
                            critical=True)
    return b.sign(issuer_key, hash_ or hashes.SHA256())


def cn(text: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)])


def serial_name(text: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.SERIAL_NUMBER, text)])


def der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


class AndroidVendor:
    """A root, one intermediate and one attestation key - the remotely provisioned shape, or (``factory``) the older
    one, whose topmost issuer is named by a serial number and whose batch key is not marked as a CA."""

    def __init__(self, *, factory: bool = False, now: dt.datetime | None = None, days: int = 10, age_days: int = 1,
                 intermediate_ca: bool = True, batch_ca: bool | None = None, batch_key_usage: str | None = None,
                 intermediate_path_length: int | None = None, root_hash: Any = None, hash_: Any = None,
                 batch_critical_unknown: bool = False) -> None:
        now = now or dt.datetime.now(dt.timezone.utc)
        self.start, self.end = now - dt.timedelta(days=age_days), now + dt.timedelta(days=days)
        self.root_key, self.mid_key, self.batch_key = (ec.generate_private_key(ec.SECP384R1()), p256(), p256())
        root_name = serial_name("f92009e853b6b045") if factory else cn("Test Attestation Root")
        mid_name = serial_name("87f4514475ba0a2b") if factory else cn("Test Server CA")
        self.batch_name = serial_name("3e7fb6a1ee4bd568") if factory else cn("Test TEE")
        self.root = certificate(root_name, self.root_key.public_key(), root_name, self.root_key, ca=True,
                                not_before=now - dt.timedelta(days=3650), not_after=now + dt.timedelta(days=3650))
        self.mid = certificate(mid_name, self.mid_key.public_key(), root_name, self.root_key, ca=intermediate_ca,
                               not_before=self.start, not_after=self.end, path_length=intermediate_path_length,
                               hash_=hash_)
        self.batch = certificate(self.batch_name, self.batch_key.public_key(), mid_name, self.mid_key,
                                 ca=(not factory) if batch_ca is None else batch_ca, not_before=self.start,
                                 not_after=self.end, key_usage=batch_key_usage,
                                 critical_unknown=batch_critical_unknown)
        self.pin = hashlib.sha256(self.root_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        self.roots = {self.pin: factory}

    def leaf(self, key: Any, description: bytes | None, **kw: Any) -> x509.Certificate:
        kw.setdefault("ca", None)
        return certificate(cn("Android Keystore Key"), key.public_key(), self.batch_name, self.batch_key,
                           not_before=_EPOCH, not_after=_FAR, serial=1,
                           extension=None if description is None else ("1.3.6.1.4.1.11129.2.1.17", description), **kw)

    def chain(self, key: Any, challenge: bytes, **kw: Any) -> list[bytes]:
        return [der(c) for c in (self.leaf(key, key_description(challenge, **kw)), self.batch, self.mid, self.root)]

    def evidence(self, key: Any, registration_challenge: str, **kw: Any) -> dict[str, Any]:
        return wire(self.chain(key, de.android_challenge(registration_challenge), **kw))

    def policy(self, **kw: Any) -> de.DevicePolicy:
        kw.setdefault("mode", "require")
        return de.DevicePolicy(android_roots=self.roots, **kw)


def wire(chain: list[bytes]) -> dict[str, Any]:
    return {"platform": "android", "chain": [base64.b64encode(c).decode("ascii") for c in chain]}


# --- App Attest -----------------------------------------------------------


def cbor(v: Any) -> bytes:
    def head(major: int, n: int) -> bytes:
        if n < 24:
            return bytes([major << 5 | n])
        size = 1 if n < 0x100 else 2 if n < 0x10000 else 4
        return bytes([major << 5 | {1: 24, 2: 25, 4: 26}[size]]) + n.to_bytes(size, "big")
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        return head(3, len(v.encode())) + v.encode()
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(cbor(i) for i in v)
    return head(5, len(v)) + b"".join(cbor(k) + cbor(i) for k, i in v.items())


class AppleVendor:
    def __init__(self) -> None:
        now = dt.datetime.now(dt.timezone.utc)
        self.span = {"not_before": now - dt.timedelta(days=1), "not_after": now + dt.timedelta(days=2)}
        self.root_key, self.mid_key = ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP384R1())
        self.root = certificate(cn("Test App Attest Root"), self.root_key.public_key(), cn("Test App Attest Root"),
                                self.root_key, ca=True, **self.span)
        self.mid = certificate(cn("Test App Attest CA"), self.mid_key.public_key(), cn("Test App Attest Root"),
                               self.root_key, ca=True, path_length=0, **self.span)
        self.root_pem = self.root.public_bytes(serialization.Encoding.PEM)

    def attestation(self, client_data_hash: bytes, *, app_id: str = APP_ID, counter: int = 0,
                    aaguid: bytes = b"appattest" + bytes(7), category: int | None = 4, key: Any = None,
                    credential: bytes | None = None, cose_key: Any = None, nonce: bytes | None = None,
                    tail: bytes = b"", auth_tail: bytes = b"", leaf: dict[str, Any] | None = None,
                    receipt: bytes = b"r", subject: str = "credential", serial: int | None = None,
                    ) -> tuple[bytes, bytes]:
        """(the attestation object, the key id)."""
        key = key or p256()
        pt, named = point(key), point(cose_key or key)
        key_id = hashlib.sha256(b"\x04" + pt).digest()
        auth = (hashlib.sha256(app_id.encode()).digest() + b"\x40" + counter.to_bytes(4, "big") + aaguid
                + (32).to_bytes(2, "big") + (credential or key_id)
                + cbor({1: 2, 3: -7, -1: 1, -2: named[:32], -3: named[32:]}))
        if category is not None:
            auth += cbor({"apple_validation_category_01": category.to_bytes(4, "little")})
        auth += auth_tail
        nonce = nonce if nonce is not None else hashlib.sha256(auth + client_data_hash).digest()
        span = {**self.span, **{k: v for k, v in (leaf or {}).items() if k.startswith("not_")}}
        cert = certificate(cn(subject), key.public_key(), cn("Test App Attest CA"), self.mid_key,
                           ca=(leaf or {}).get("ca", False), serial=serial, **span,
                           extension=("1.2.840.113635.100.8.2", tlv(0x30, context(1, tlv(0x04, nonce)))))
        return cbor({"fmt": "apple-appattest", "attStmt": {"x5c": [der(cert), der(self.mid)], "receipt": receipt},
                     "authData": auth}) + tail, key_id

    def assertion(self, key: Any, client_data_hash: bytes, counter: int, *, app_id: str = APP_ID,
                  category: int | None = 4, signer: Any = None, tail: bytes = b"", auth_tail: bytes = b"") -> str:
        """What generateAssertion gives, base64."""
        auth = hashlib.sha256(app_id.encode()).digest() + b"\x40" + counter.to_bytes(4, "big")
        if category is not None:
            auth += cbor({"apple_validation_category_01": category.to_bytes(4, "little")})
        auth += auth_tail
        signature = (signer or key).sign(hashlib.sha256(auth + client_data_hash).digest(), ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(cbor({"signature": signature, "authenticatorData": auth}) + tail).decode()

    def evidence(self, registration_challenge: str, identity_b64u: str, poll_b64u: str, **kw: Any) -> dict[str, Any]:
        obj, key_id = self.attestation(de.ios_client_data_hash(registration_challenge, identity_b64u, poll_b64u), **kw)
        return {"platform": "ios", "key_id": base64.b64encode(key_id).decode(),
                "attestation": base64.b64encode(obj).decode()}
