"""Tests for the push wake substrate (production-scale wave C).

Covers: push-token capture at registration + the multi-URL failover
field, POST /v0.4/manage/push_token rotation, PushDispatcher routing /
best-effort semantics, the ApnsPushSender / FcmPushSender request
shapes (injected fake HTTP clients -- no network), and the end-to-end
"queued request fires a wake push" path through the live HTTP server.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

cryptography = pytest.importorskip(
    "cryptography", reason="recto[v0_4] not installed"
)
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

from recto.bootloader import push as push_mod  # noqa: E402
from recto.bootloader.push import (  # noqa: E402
    ApnsConfig,
    ApnsPushSender,
    FcmConfig,
    FcmPushSender,
    PushDispatcher,
    PushSender,
    PushSendError,
)
from recto.bootloader.server import (  # noqa: E402
    POLL_SIG_HEADER,
    POLL_SIG_PREFIX,
    POLL_SIG_TS_HEADER,
    ChallengeStore,
    create_server,
    poll_key_delegation_payload,
)
from recto.bootloader.state import PhoneRegistration, StateStore  # noqa: E402


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _http_post_json(
    url: str, body: dict[str, Any], headers: dict[str, str] | None = None
) -> tuple[int, dict[str, Any]]:
    data = json.dumps(body).encode("utf-8")
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    req = urlrequest.Request(url, data=data, headers=h, method="POST")
    try:
        with urlrequest.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def _http_get_json(url: str) -> tuple[int, dict[str, Any]]:
    req = urlrequest.Request(url, method="GET")
    try:
        with urlrequest.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


class RecordingSender(PushSender):
    """Fake platform sender; records sends + signals an Event so tests
    can wait for the dispatcher's daemon thread deterministically."""

    def __init__(self, platform: str, *, fail: bool = False):
        self._platform = platform
        self.fail = fail
        self.sends: list[tuple[str, str]] = []
        self.fired = threading.Event()

    @property
    def platform(self) -> str:
        return self._platform

    def send_wake(self, push_token: str, *, request_id: str) -> None:
        try:
            if self.fail:
                raise PushSendError("simulated provider failure")
            self.sends.append((push_token, request_id))
        finally:
            self.fired.set()


def _phone(**kw) -> PhoneRegistration:
    defaults = dict(
        device_label="push-test-phone",
        public_key_b64u="AAAA",
        supported_algorithms=("ed25519",),
    )
    defaults.update(kw)
    return PhoneRegistration.new(**defaults)


# ----------------------------------------------------------------------
# PushDispatcher
# ----------------------------------------------------------------------

class TestPushDispatcher:
    def test_routes_to_matching_platform_sender(self):
        apns, fcm = RecordingSender("apns"), RecordingSender("fcm")
        d = PushDispatcher([apns, fcm])
        phone = _phone(push_token="tok-android", push_platform="fcm")
        d.notify(phone, "req-1")
        assert fcm.fired.wait(timeout=5.0)
        assert fcm.sends == [("tok-android", "req-1")]
        assert apns.sends == []

    def test_phone_without_token_is_skipped(self):
        apns = RecordingSender("apns")
        d = PushDispatcher([apns])
        d.notify(_phone(), "req-1")  # no token registered
        assert not apns.fired.wait(timeout=0.3)
        assert apns.sends == []

    def test_unregistered_platform_is_skipped(self):
        apns = RecordingSender("apns")
        d = PushDispatcher([apns])
        d.notify(_phone(push_token="t", push_platform="fcm"), "req-1")
        assert not apns.fired.wait(timeout=0.3)

    def test_sender_failure_is_swallowed(self):
        failing = RecordingSender("apns", fail=True)
        d = PushDispatcher([failing])
        # Must not raise -- push is best-effort by design.
        d.notify(_phone(push_token="t", push_platform="apns"), "req-1")
        assert failing.fired.wait(timeout=5.0)

    def test_a_burst_is_one_wake_now_and_one_at_the_intervals_end(self):
        fcm = RecordingSender("fcm")
        d = PushDispatcher([fcm], wake_min_interval_seconds=0.4)
        phone = _phone(push_token="tok", push_platform="fcm")
        for n in range(20):
            d.notify(phone, f"req-{n}")
        assert fcm.fired.wait(timeout=5.0)
        time.sleep(0.15)
        assert fcm.sends == [("tok", "req-0")]
        time.sleep(0.6)
        # The burst's last card is not left waiting on a poll.
        assert fcm.sends == [("tok", "req-0"), ("tok", "req-19")]
        time.sleep(0.5)
        d.notify(phone, "req-later")
        time.sleep(0.15)
        assert fcm.sends[-1] == ("tok", "req-later")

    def test_the_interval_is_each_phones_own(self):
        fcm = RecordingSender("fcm")
        d = PushDispatcher([fcm], wake_min_interval_seconds=30)
        d.notify(_phone(push_token="a", push_platform="fcm", public_key_b64u="AAAA"), "req-a")
        d.notify(_phone(push_token="b", push_platform="fcm", public_key_b64u="BBBB"), "req-b")
        time.sleep(0.3)
        assert sorted(fcm.sends) == [("a", "req-a"), ("b", "req-b")]

    def test_an_owed_wake_goes_to_the_newest_token(self):
        fcm = RecordingSender("fcm")
        d = PushDispatcher([fcm], wake_min_interval_seconds=0.3)
        d.notify(_phone(push_token="old", push_platform="fcm"), "req-1")
        d.notify(_phone(push_token="old", push_platform="fcm"), "req-2")
        d.notify(_phone(push_token="new", push_platform="fcm"), "req-3")
        time.sleep(0.7)
        assert fcm.sends == [("old", "req-1"), ("new", "req-3")]

    def test_platforms_property(self):
        d = PushDispatcher([RecordingSender("fcm"), RecordingSender("apns")])
        assert d.platforms == ["apns", "fcm"]


# ----------------------------------------------------------------------
# Provider senders (fake HTTP clients -- request-shape pins)
# ----------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status_code: int, body: dict | None = None):
        self.status_code = status_code
        self._body = body or {}

    def json(self) -> dict:
        return self._body


class _FakeHttpClient:
    def __init__(self, responses: list[_FakeResponse]):
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def post(self, url: str, **kw) -> _FakeResponse:
        self.calls.append({"url": url, **kw})
        return self.responses.pop(0)


@pytest.fixture(scope="module")
def ec_p8_pem() -> str:
    """An ES256 (P-256) signing key PEM standing in for an APNs .p8."""
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


@pytest.fixture(scope="module")
def rsa_sa_json() -> str:
    """A minimal FCM service-account JSON with a real RSA key."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    return json.dumps(
        {"client_email": "push-test@example.iam.gserviceaccount.com",
         "private_key": pem}
    )


class TestApnsPushSender:
    def test_send_shape(self, ec_p8_pem):
        pytest.importorskip("jwt")
        client = _FakeHttpClient([_FakeResponse(200)])
        sender = ApnsPushSender(
            ApnsConfig(
                team_id="TEAM123456",
                key_id="KEY1234567",
                p8_key_pem=ec_p8_pem,
                bundle_id="app.recto.phone",
            ),
            client=client,
        )
        sender.send_wake("device-token-abc", request_id="req-9")
        call = client.calls[0]
        assert call["url"] == (
            "https://api.push.apple.com/3/device/device-token-abc"
        )
        h = call["headers"]
        assert h["apns-topic"] == "app.recto.phone"
        assert h["apns-push-type"] == "alert"
        assert h["apns-priority"] == "10"
        assert h["apns-collapse-id"] == "recto_pending"
        assert h["authorization"].startswith("bearer ")
        # Hard property 1: the fixed sentence and the wake marker, zero request content.
        assert call["json"] == {
            "aps": {
                "alert": {"title": "Recto", "body": "Something is waiting for your approval in Recto."},
                "sound": "default",
                "content-available": 1,
            },
            "recto": "pending_wake",
        }

    def test_sandbox_gateway(self, ec_p8_pem):
        pytest.importorskip("jwt")
        client = _FakeHttpClient([_FakeResponse(200)])
        sender = ApnsPushSender(
            ApnsConfig(
                team_id="T", key_id="K", p8_key_pem=ec_p8_pem,
                bundle_id="b", use_sandbox=True,
            ),
            client=client,
        )
        sender.send_wake("tok", request_id="r")
        assert client.calls[0]["url"].startswith(
            "https://api.sandbox.push.apple.com/"
        )

    def test_non_200_raises_push_send_error(self, ec_p8_pem):
        pytest.importorskip("jwt")
        client = _FakeHttpClient([_FakeResponse(410)])
        sender = ApnsPushSender(
            ApnsConfig(team_id="T", key_id="K", p8_key_pem=ec_p8_pem,
                       bundle_id="b"),
            client=client,
        )
        with pytest.raises(PushSendError, match="410") as caught:
            sender.send_wake("tok", request_id="r")
        assert caught.value.outcome == "dead_token"

    def test_provider_jwt_is_cached(self, ec_p8_pem):
        pytest.importorskip("jwt")
        client = _FakeHttpClient([_FakeResponse(200), _FakeResponse(200)])
        sender = ApnsPushSender(
            ApnsConfig(team_id="T", key_id="K", p8_key_pem=ec_p8_pem,
                       bundle_id="b"),
            client=client,
        )
        sender.send_wake("tok", request_id="r1")
        sender.send_wake("tok", request_id="r2")
        auth1 = client.calls[0]["headers"]["authorization"]
        auth2 = client.calls[1]["headers"]["authorization"]
        assert auth1 == auth2  # minted once inside the cache window


class TestFcmPushSender:
    def test_send_shape_with_token_exchange(self, rsa_sa_json):
        pytest.importorskip("jwt")
        client = _FakeHttpClient([
            _FakeResponse(200, {"access_token": "oauth-tok",
                                "expires_in": 3600}),
            _FakeResponse(200),
        ])
        sender = FcmPushSender(
            FcmConfig(project_id="recto-prod", service_account_json=rsa_sa_json),
            client=client,
        )
        sender.send_wake("fcm-token-xyz", request_id="req-3")
        exchange, send = client.calls
        assert exchange["url"] == "https://oauth2.googleapis.com/token"
        assert send["url"] == (
            "https://fcm.googleapis.com/v1/projects/recto-prod/messages:send"
        )
        assert send["headers"]["authorization"] == "Bearer oauth-tok"
        # Hard property 1: the fixed sentence and the wake marker, zero request content.
        assert send["json"] == {
            "message": {
                "token": "fcm-token-xyz",
                "notification": {"title": "Recto", "body": "Something is waiting for your approval in Recto."},
                "data": {"recto": "pending_wake"},
                "android": {
                    "priority": "HIGH",
                    "collapse_key": "recto_pending",
                    "notification": {"channel_id": "recto_pending", "tag": "recto_pending"},
                },
            }
        }

    def test_oauth_token_cached_across_sends(self, rsa_sa_json):
        pytest.importorskip("jwt")
        client = _FakeHttpClient([
            _FakeResponse(200, {"access_token": "tok", "expires_in": 3600}),
            _FakeResponse(200),
            _FakeResponse(200),
        ])
        sender = FcmPushSender(
            FcmConfig(project_id="p", service_account_json=rsa_sa_json),
            client=client,
        )
        sender.send_wake("t", request_id="r1")
        sender.send_wake("t", request_id="r2")
        # 3 calls total: ONE exchange + two sends.
        assert len(client.calls) == 3

    def test_failed_exchange_raises(self, rsa_sa_json):
        pytest.importorskip("jwt")
        client = _FakeHttpClient([_FakeResponse(403)])
        sender = FcmPushSender(
            FcmConfig(project_id="p", service_account_json=rsa_sa_json),
            client=client,
        )
        with pytest.raises(PushSendError, match="403"):
            sender.send_wake("t", request_id="r")


# ----------------------------------------------------------------------
# The wake is visible and says one fixed thing
# ----------------------------------------------------------------------

_FIXED_WORDS = {"Recto", "Something is waiting for your approval in Recto.", "pending_wake", "recto_pending",
                "default", "HIGH"}


def _strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return [value] if isinstance(value, str) else []


def _apns(ec_p8_pem: str, responses: list[_FakeResponse]) -> tuple[ApnsPushSender, _FakeHttpClient]:
    client = _FakeHttpClient(responses)
    return ApnsPushSender(ApnsConfig(team_id="T", key_id="K", p8_key_pem=ec_p8_pem, bundle_id="b"),
                          client=client), client


def _fcm(rsa_sa_json: str, responses: list[_FakeResponse]) -> tuple[FcmPushSender, _FakeHttpClient]:
    client = _FakeHttpClient([_FakeResponse(200, {"access_token": "oauth-tok", "expires_in": 3600}), *responses])
    return FcmPushSender(FcmConfig(project_id="p", service_account_json=rsa_sa_json), client=client), client


class TestTheWakeSaysOneFixedThing:
    def test_the_sentence_is_the_one_the_phone_shows(self):
        assert push_mod.WAKE_TITLE == "Recto"
        assert push_mod.WAKE_BODY == "Something is waiting for your approval in Recto."

    def test_an_apns_wake_holds_only_the_fixed_words(self, ec_p8_pem):
        pytest.importorskip("jwt")
        sender, client = _apns(ec_p8_pem, [_FakeResponse(200), _FakeResponse(200)])
        sender.send_wake("device-token-one", request_id="request-id-one")
        sender.send_wake("device-token-two", request_id="request-id-two")
        first, second = (c["json"] for c in client.calls)
        # Every string in the payload is one of the fixed words, and no number in it is a count.
        assert set(_strings(first)) <= _FIXED_WORDS
        assert first == second, "the payload is the same for every card and every phone"
        assert "badge" not in first["aps"]
        for call in client.calls:
            sent = json.dumps(call["json"]) + json.dumps(
                {k: v for k, v in call["headers"].items() if k != "authorization"})
            assert "request-id" not in sent and "device-token" not in sent

    def test_an_fcm_wake_holds_only_the_fixed_words_and_its_token(self, rsa_sa_json):
        pytest.importorskip("jwt")
        sender, client = _fcm(rsa_sa_json, [_FakeResponse(200), _FakeResponse(200)])
        sender.send_wake("fcm-token-one", request_id="request-id-one")
        sender.send_wake("fcm-token-two", request_id="request-id-two")
        bodies = [dict(c["json"]["message"]) for c in client.calls[1:]]
        assert [b.pop("token") for b in bodies] == ["fcm-token-one", "fcm-token-two"]
        assert set(_strings(bodies[0])) <= _FIXED_WORDS
        assert bodies[0] == bodies[1], "but for its address the message is the same for every card and every phone"
        assert "request-id" not in json.dumps([c["json"] for c in client.calls[1:]])

    def test_wakes_share_one_collapse_id_so_no_count_shows(self, ec_p8_pem, rsa_sa_json):
        pytest.importorskip("jwt")
        apns, a_client = _apns(ec_p8_pem, [_FakeResponse(200)])
        apns.send_wake("t", request_id="r")
        assert a_client.calls[0]["headers"]["apns-collapse-id"] == push_mod.WAKE_COLLAPSE_ID
        fcm, f_client = _fcm(rsa_sa_json, [_FakeResponse(200)])
        fcm.send_wake("t", request_id="r")
        android = f_client.calls[1]["json"]["message"]["android"]
        assert android["collapse_key"] == android["notification"]["tag"] == push_mod.WAKE_COLLAPSE_ID


class TestTheSilentWakeIsStillThere:
    """visible=False (RECTO_PUSH_VISIBLE=0) sends the payload of 1.2.4 and earlier, byte for byte."""

    def test_apns_silent(self, ec_p8_pem):
        pytest.importorskip("jwt")
        client = _FakeHttpClient([_FakeResponse(200)])
        sender = ApnsPushSender(ApnsConfig(team_id="T", key_id="K", p8_key_pem=ec_p8_pem, bundle_id="b",
                                           visible=False), client=client)
        sender.send_wake("tok", request_id="r")
        call = client.calls[0]
        assert call["json"] == {"aps": {"content-available": 1}, "recto": "pending_wake"}
        assert call["headers"]["apns-push-type"] == "background" and call["headers"]["apns-priority"] == "5"
        assert set(call["headers"]) == {"authorization", "apns-topic", "apns-push-type", "apns-priority"}

    def test_fcm_silent(self, rsa_sa_json):
        pytest.importorskip("jwt")
        client = _FakeHttpClient([_FakeResponse(200, {"access_token": "t", "expires_in": 3600}), _FakeResponse(200)])
        sender = FcmPushSender(FcmConfig(project_id="p", service_account_json=rsa_sa_json, visible=False),
                               client=client)
        sender.send_wake("tok", request_id="r")
        assert client.calls[1]["json"] == {
            "message": {"token": "tok", "data": {"recto": "pending_wake"}, "android": {"priority": "HIGH"}}}

    def test_visible_is_the_default(self):
        assert ApnsConfig(team_id="T", key_id="K", p8_key_pem="x", bundle_id="b").visible is True
        assert FcmConfig(project_id="p", service_account_json="{}").visible is True


# ----------------------------------------------------------------------
# A failed send says which kind of failure it was, and nothing else
# ----------------------------------------------------------------------

class TestFailureClasses:
    @pytest.mark.parametrize("status,body,outcome", [
        (403, {"reason": "InvalidProviderToken"}, "bad_credential"),
        (403, {"reason": "ExpiredProviderToken"}, "bad_credential"),
        (400, {"reason": "BadDeviceToken"}, "wrong_environment"),
        (400, {"reason": "DeviceTokenNotForTopic"}, "wrong_environment"),
        (400, {"reason": "TopicDisallowed"}, "wrong_environment"),
        (410, {"reason": "Unregistered"}, "dead_token"),
        (410, None, "dead_token"),
        (429, {"reason": "TooManyRequests"}, "throttled"),
        (503, {"reason": "ServiceUnavailable"}, "provider_unavailable"),
        (400, {"reason": "PayloadEmpty"}, "rejected"),
        (400, None, "rejected"),
    ])
    def test_apns_outcomes(self, ec_p8_pem, status, body, outcome):
        pytest.importorskip("jwt")
        sender, _ = _apns(ec_p8_pem, [_FakeResponse(status, body)])
        with pytest.raises(PushSendError) as caught:
            sender.send_wake("device-token-abc", request_id="req-9")
        assert caught.value.outcome == outcome and caught.value.status == status
        text = str(caught.value)
        assert "device-token-abc" not in text and "req-9" not in text
        assert not body or body["reason"] not in text, "the provider's words are classed, never repeated"

    @pytest.mark.parametrize("status,body,outcome", [
        (404, {"error": {"status": "NOT_FOUND", "details": [{"errorCode": "UNREGISTERED"}]}}, "dead_token"),
        (403, {"error": {"status": "PERMISSION_DENIED", "details": [{"errorCode": "SENDER_ID_MISMATCH"}]}},
         "wrong_environment"),
        (404, {"error": {"status": "NOT_FOUND"}}, "wrong_environment"),
        (401, {"error": {"status": "UNAUTHENTICATED"}}, "bad_credential"),
        (403, {"error": {"status": "PERMISSION_DENIED"}}, "bad_credential"),
        (429, {"error": {"status": "RESOURCE_EXHAUSTED"}}, "throttled"),
        (503, {"error": {"status": "UNAVAILABLE"}}, "provider_unavailable"),
        (400, {"error": {"status": "INVALID_ARGUMENT"}}, "rejected"),
        (400, {"error": "not an object"}, "rejected"),
    ])
    def test_fcm_outcomes(self, rsa_sa_json, status, body, outcome):
        pytest.importorskip("jwt")
        sender, _ = _fcm(rsa_sa_json, [_FakeResponse(status, body)])
        with pytest.raises(PushSendError) as caught:
            sender.send_wake("fcm-token-xyz", request_id="req-3")
        assert caught.value.outcome == outcome and caught.value.status == status
        assert "fcm-token-xyz" not in str(caught.value) and "req-3" not in str(caught.value)

    def test_a_refused_service_account_is_a_bad_credential(self, rsa_sa_json):
        pytest.importorskip("jwt")
        client = _FakeHttpClient([_FakeResponse(400, {"error": "invalid_grant"})])
        sender = FcmPushSender(FcmConfig(project_id="p", service_account_json=rsa_sa_json), client=client)
        with pytest.raises(PushSendError) as caught:
            sender.send_wake("t", request_id="r")
        assert caught.value.outcome == "bad_credential" and caught.value.status == 400

    def test_no_answer_is_unreachable(self, ec_p8_pem):
        pytest.importorskip("jwt")

        class _Dead:
            def post(self, url: str, **kw):
                raise OSError("connection reset while sending to device-token-abc")

        sender = ApnsPushSender(ApnsConfig(team_id="T", key_id="K", p8_key_pem=ec_p8_pem, bundle_id="b"),
                                client=_Dead())
        with pytest.raises(PushSendError) as caught:
            sender.send_wake("device-token-abc", request_id="r")
        assert caught.value.outcome == "unreachable" and caught.value.status is None
        assert "device-token-abc" not in str(caught.value)

    def test_an_unknown_outcome_is_never_invented(self):
        assert PushSendError("x", outcome="something-else").outcome == "error"


class _Failing(PushSender):
    def __init__(self, platform: str, error: Exception):
        self._platform, self._error = platform, error
        self.fired = threading.Event()

    @property
    def platform(self) -> str:
        return self._platform

    def send_wake(self, push_token: str, *, request_id: str) -> None:
        try:
            raise self._error
        finally:
            self.fired.set()


def _wait_for(check, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return True
        time.sleep(0.02)
    return False


class TestTheFailureLine:
    def test_it_carries_the_outcome_and_counts_and_names_nothing(self, caplog):
        sender = _Failing("apns", PushSendError("apns send returned 403", outcome="bad_credential", status=403))
        d = PushDispatcher([sender], wake_min_interval_seconds=0)
        phone = _phone(push_token="secret-device-token", push_platform="apns", device_label="kitchen-tablet")
        with caplog.at_level("WARNING", logger="recto.bootloader.push"):
            d.notify(phone, "req-private-1")
            assert _wait_for(lambda: d.counts()["failed"].get("apns", {}).get("bad_credential") == 1)
            d.notify(phone, "req-private-2")
            assert _wait_for(lambda: d.counts()["failed"]["apns"]["bad_credential"] == 2)
            assert _wait_for(lambda: len([r for r in caplog.records if r.name == "recto.bootloader.push"]) == 2)
        lines = [r.getMessage() for r in caplog.records if r.name == "recto.bootloader.push"]
        assert "platform=apns outcome=bad_credential status=403" in lines[0]
        assert "this outcome 2; platform sent 0, failed 2" in lines[1]
        for line in lines:
            for private in ("secret-device-token", "req-private", "kitchen-tablet", phone.phone_id):
                assert private not in line

    def test_a_fault_in_the_sender_is_an_error_without_its_text(self, caplog):
        sender = _Failing("fcm", RuntimeError("token secret-device-token is malformed"))
        d = PushDispatcher([sender])
        with caplog.at_level("WARNING", logger="recto.bootloader.push"):
            d.notify(_phone(push_token="secret-device-token", push_platform="fcm"), "req-1")
            assert _wait_for(lambda: d.counts()["failed"].get("fcm", {}).get("error") == 1)
            assert _wait_for(lambda: any(r.name == "recto.bootloader.push" for r in caplog.records))
        line = next(r.getMessage() for r in caplog.records if r.name == "recto.bootloader.push")
        assert "outcome=error status=none" in line and "secret-device-token" not in line

    def test_sent_wakes_are_counted(self):
        fcm = RecordingSender("fcm")
        d = PushDispatcher([fcm])
        d.notify(_phone(push_token="t", push_platform="fcm"), "req-1")
        assert _wait_for(lambda: d.counts() == {"sent": {"fcm": 1}, "failed": {}})


class TestADeadTokenIsDropped:
    def test_the_handler_is_told_of_a_dead_token_only(self):
        told: list[tuple[str, str]] = []
        dead = _Failing("fcm", PushSendError("fcm send returned 404", outcome="dead_token", status=404))
        bad = _Failing("apns", PushSendError("apns send returned 400", outcome="wrong_environment", status=400))
        d = PushDispatcher([dead, bad], on_dead_token=lambda phone_id, token: told.append((phone_id, token)))
        android = _phone(push_token="gone", push_platform="fcm", public_key_b64u="AAAA")
        iphone = _phone(push_token="other-gateway", push_platform="apns", public_key_b64u="BBBB")
        d.notify(android, "req-1")
        d.notify(iphone, "req-2")
        assert _wait_for(lambda: d.counts()["failed"].get("apns", {}).get("wrong_environment") == 1)
        assert _wait_for(lambda: told == [(android.phone_id, "gone")])

    def test_a_handler_that_fails_never_escapes(self):
        def boom(phone_id: str, token: str) -> None:
            raise RuntimeError("the store is away")

        dead = _Failing("fcm", PushSendError("x", outcome="dead_token", status=404))
        d = PushDispatcher([dead], on_dead_token=boom)
        d.notify(_phone(push_token="gone", push_platform="fcm"), "req-1")
        assert _wait_for(lambda: d.counts()["failed"].get("fcm", {}).get("dead_token") == 1)

    def test_the_file_store_clears_only_the_token_that_died(self, tmp_path: Path):
        state = StateStore(state_dir=tmp_path)
        phone = _phone(push_token="tok-1", push_platform="fcm")
        state.register_phone(phone)
        assert state.clear_phone_push(phone.phone_id, "another-token") is False
        assert state.get_phone(phone.phone_id).push_token == "tok-1"
        assert state.clear_phone_push(phone.phone_id, "") is False
        assert state.clear_phone_push("no-such-phone", "tok-1") is False
        assert state.clear_phone_push(phone.phone_id, "tok-1") is True
        kept = state.get_phone(phone.phone_id)
        assert kept.push_token is None and kept.push_platform is None
        # Everything else of the phone is as it was, and it reads the same from disk.
        assert kept.device_label == phone.device_label and kept.public_key_b64u == phone.public_key_b64u
        again = StateStore(state_dir=tmp_path).get_phone(phone.phone_id)
        assert again.push_token is None and again.push_platform is None

    def test_the_server_drops_a_dead_token_and_the_phone_stays(self, tmp_path: Path):
        state = StateStore(state_dir=tmp_path)
        dead = _Failing("fcm", PushSendError("fcm send returned 404", outcome="dead_token", status=404))
        dispatcher = PushDispatcher([dead])
        server = create_server(bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="push-drop-test",
                               challenges=ChallengeStore(), ssl_context=None, push_dispatcher=dispatcher)
        try:
            phone = _phone(push_token="gone", push_platform="fcm")
            state.register_phone(phone)
            dispatcher.notify(state.get_phone(phone.phone_id), "req-1")
            assert _wait_for(lambda: state.get_phone(phone.phone_id).push_token is None)
            assert state.get_phone(phone.phone_id).push_platform is None
            # No token now: the next card sends nothing, and the phone is found by its poll.
            dead.fired.clear()
            dispatcher.notify(state.get_phone(phone.phone_id), "req-2")
            assert not dead.fired.wait(timeout=0.3)
        finally:
            server.server_close()


# ----------------------------------------------------------------------
# Push off: no sender, no dispatcher, and cards are still queued
# ----------------------------------------------------------------------

class TestPushDisabled:
    def test_no_settings_builds_no_dispatcher(self, monkeypatch):
        import importlib.util

        for name in list(__import__("os").environ):
            if name.startswith("RECTO_PUSH_"):
                monkeypatch.delenv(name)
        path = Path(__file__).resolve().parent.parent / "examples" / "run_bootloader_consumer.py"
        spec = importlib.util.spec_from_file_location("run_bootloader_consumer_push_off", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert module._build_push_dispatcher(None) is None

    def test_ids_without_a_key_file_build_no_sender(self, monkeypatch, capsys):
        import importlib.util

        for name in list(__import__("os").environ):
            if name.startswith("RECTO_PUSH_"):
                monkeypatch.delenv(name)
        monkeypatch.setenv("RECTO_PUSH_APNS_TEAM_ID", "TEAM123456")
        monkeypatch.setenv("RECTO_PUSH_APNS_KEY_ID", "KEY1234567")
        monkeypatch.setenv("RECTO_PUSH_APNS_BUNDLE_ID", "app.recto.phone")
        monkeypatch.setenv("RECTO_PUSH_FCM_PROJECT_ID", "example-project")
        path = Path(__file__).resolve().parent.parent / "examples" / "run_bootloader_consumer.py"
        spec = importlib.util.spec_from_file_location("run_bootloader_consumer_push_half", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert module._build_push_dispatcher(None) is None
        warned = capsys.readouterr().err
        assert "APNs wake disabled" in warned and "FCM wake disabled" in warned

    def test_a_server_started_without_push_has_no_dispatcher(self, tmp_path: Path):
        state = StateStore(state_dir=tmp_path)
        server = create_server(bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="push-off-test",
                               challenges=ChallengeStore(), ssl_context=None)
        try:
            from recto.bootloader.server import BootloaderHandler
            assert BootloaderHandler.config.push_dispatcher is None
        finally:
            server.server_close()

    def test_a_phone_with_no_token_is_never_sent_to(self):
        fcm = RecordingSender("fcm")
        d = PushDispatcher([fcm])
        d.notify(_phone(), "req-1")
        assert not fcm.fired.wait(timeout=0.3)
        assert d.counts() == {"sent": {}, "failed": {}}


# ----------------------------------------------------------------------
# Live-server integration: registration fields, token rotation, and
# queued-request-fires-wake
# ----------------------------------------------------------------------

@pytest.fixture
def push_server(tmp_path: Path):
    state = StateStore(state_dir=tmp_path)
    challenges = ChallengeStore()
    dispatcher_sender = RecordingSender("fcm")
    server = create_server(
        bind_host="127.0.0.1",
        bind_port=0,
        state=state,
        bootloader_id="push-test-bootloader",
        challenges=challenges,
        ssl_context=None,
        capability_agent_tokens={"agent-1": "tok-agent-1"},
        push_dispatcher=PushDispatcher([dispatcher_sender]),
        public_urls=["https://bootloader.example.com",
                     "https://bootloader-failover.example.com"],
    )
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "base_url": f"http://{host}:{port}",
            "state": state,
            "challenges": challenges,
            "sender": dispatcher_sender,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _register_phone_http(ctx, *, push_token=None, push_platform=None):
    """Full HTTP registration with a real Ed25519 proof."""
    code, _exp = ctx["challenges"].issue_pairing_code()
    status, challenge_body = _http_get_json(
        f"{ctx['base_url']}/v0.4/registration_challenge?code={code}"
    )
    assert status == 200
    challenge = challenge_body["challenge_b64u"]

    key = Ed25519PrivateKey.generate()
    pub_raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    # Canonical convention: sign the literal ASCII bytes of the
    # base64url challenge string.
    signature = key.sign(challenge.encode("ascii"))
    ctx["poll_key"] = Ed25519PrivateKey.generate()
    poll_pub_raw = ctx["poll_key"].public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    body = {
        "phone_id": "phone-supplied-id-ignored",
        "device_label": "push-integration-phone",
        "public_key_b64u": _b64u(pub_raw),
        "supported_algorithms": ["ed25519"],
        "v0_4_protocol": 1,
        "registration_proof": {
            "challenge": challenge,
            "signature_b64u": _b64u(signature),
        },
        # rule 14.2: a registration delegates a poll key or it is refused
        "poll_public_key_b64u": _b64u(poll_pub_raw),
        "poll_key_delegation_b64u": _b64u(key.sign(
            poll_key_delegation_payload(_b64u(pub_raw), _b64u(poll_pub_raw))
        )),
    }
    if push_token is not None:
        body["push_token"] = push_token
    if push_platform is not None:
        body["push_platform"] = push_platform
    return _http_post_json(f"{ctx['base_url']}/v0.4/register", body)


class TestRegistrationPushFields:
    def test_register_captures_push_token_and_emits_urls(self, push_server):
        status, body = _register_phone_http(
            push_server, push_token="fcm-tok-1", push_platform="fcm"
        )
        assert status == 201
        assert body["registered"] is True
        # Multi-URL failover field, primary first.
        assert body["bootloader_urls"] == [
            "https://bootloader.example.com",
            "https://bootloader-failover.example.com",
        ]
        phone = push_server["state"].get_phone(body["phone_id"])
        assert phone.push_token == "fcm-tok-1"
        assert phone.push_platform == "fcm"

    def test_register_without_push_token_is_poll_only(self, push_server):
        status, body = _register_phone_http(push_server)
        assert status == 201
        phone = push_server["state"].get_phone(body["phone_id"])
        assert phone.push_token is None
        assert phone.push_platform is None

    def test_register_rejects_unknown_platform(self, push_server):
        status, body = _register_phone_http(
            push_server, push_token="t", push_platform="carrier-pigeon"
        )
        assert status == 400
        assert "push_platform" in body["detail"]


class TestPushTokenUpdateEndpoint:
    def test_rotation_updates_registration(self, push_server):
        _, reg = _register_phone_http(
            push_server, push_token="old-tok", push_platform="fcm"
        )
        phone_id = reg["phone_id"]
        ts = int(time.time())
        signed = push_server["poll_key"].sign(
            f"{POLL_SIG_PREFIX}|{phone_id}|{ts}|/v0.4/manage/push_token".encode("ascii"))
        status, body = _http_post_json(
            f"{push_server['base_url']}/v0.4/manage/push_token",
            {"phone_id": phone_id, "push_token": "new-tok",
             "push_platform": "fcm"},
            headers={POLL_SIG_HEADER: _b64u(signed), POLL_SIG_TS_HEADER: str(ts)},
        )
        assert status == 200
        assert body == {"updated": True, "phone_id": phone_id}
        phone = push_server["state"].get_phone(phone_id)
        assert phone.push_token == "new-tok"
        # Everything else survives the rotation.
        assert phone.device_label == "push-integration-phone"

    def test_unknown_phone_rejected(self, push_server):
        status, body = _http_post_json(
            f"{push_server['base_url']}/v0.4/manage/push_token",
            {"phone_id": "nope", "push_token": "t", "push_platform": "apns"},
        )
        assert status == 400

    def test_missing_fields_rejected(self, push_server):
        _, reg = _register_phone_http(push_server)
        status, _ = _http_post_json(
            f"{push_server['base_url']}/v0.4/manage/push_token",
            {"phone_id": reg["phone_id"], "push_token": ""},
        )
        assert status == 400


class TestQueuedRequestFiresWake:
    def test_capability_request_wakes_target_phone(self, push_server):
        from recto.capability.types import (
            CapabilityClaims,
            CapabilityClause,
            CapabilityLimits,
            CapabilityScope,
        )

        _, reg = _register_phone_http(
            push_server, push_token="wake-me", push_platform="fcm"
        )
        now = int(time.time())
        claims = CapabilityClaims(
            iss="phone:operator:enclave",
            sub="agent:test",
            aud=["consumer-app"],
            iat=now,
            nbf=now,
            exp=now + 3600,
            jti=f"cap_push_test_{now}",
            cap=CapabilityClause(
                tier=0,
                registry_version="2026-05-05",
                groups=[],
                scope=CapabilityScope(env=[], services=[], repos=[]),
                allow_actions=["doc:edit"],
                deny_actions=[],
                limits=CapabilityLimits(per_hour={}, per_day={},
                                        per_session={}),
            ),
            purpose="push wake integration test",
        )
        status, body = _http_post_json(
            f"{push_server['base_url']}/v0.4/capability/request",
            {"phone_id": reg["phone_id"], "claims": asdict(claims)},
            headers={
                "X-Recto-Agent-Id": "agent-1",
                "X-Recto-Agent-Token": "tok-agent-1",
            },
        )
        assert status == 201
        sender = push_server["sender"]
        assert sender.fired.wait(timeout=5.0), "wake push never fired"
        token, request_id = sender.sends[0]
        assert token == "wake-me"
        assert request_id == body["request_id"]
