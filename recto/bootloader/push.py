"""Push wake senders -- the production replacement for tight polling.

Production-scale wave C (docs/production-scale-brief.md, layer 3): at
consumer scale the phone-side polling loop can't be the primary
notification path -- N paired phones polling ``GET /v0.4/pending`` every
few seconds is almost pure waste. This module gives the bootloader a
SEND side for the push tokens phones already supply at registration
(``push_token`` + ``push_platform`` on ``POST /v0.4/register``, rotated
via ``POST /v0.4/manage/push_token``): when a request is queued for a
phone, the bootloader fires a wake push; the phone shows one fixed
notification, and the app fetches its pending queue over the normal
authenticated channel.

A wake is VISIBLE unless the operator turns that off. A silent push only
reaches an app that is running: with the app closed nothing was shown,
and the platforms do not deliver a silent push to an app its owner
swiped away. So each wake is drawn by the phone's own system, app
running or not. This changed the payload's shape on purpose: until
1.2.5 it had no notification block at all. ``visible=False`` on a
sender's config (``RECTO_PUSH_VISIBLE=0``) sends that earlier payload,
byte for byte: the bare marker and nothing a person sees.

Three hard properties, non-negotiable:

1. **Push payloads carry NO request content.** Not the operation
   description, not the service name, not the agent's name, not a
   count, not hashes, not a request id -- only a bare "check your
   pending queue" marker and, when visible, ONE FIXED TITLE AND
   SENTENCE (``WAKE_TITLE`` / ``WAKE_BODY``): constants in this file,
   never interpolated, identical for every card on every phone, an
   owner's and a member's alike. No field of the payload differs from
   one card to the next. Push transports are third-party
   infrastructure (Apple / Google); Recto's threat model treats them as
   delivery hints, never as data channels. What they learn from a wake:
   that this phone was woken, when, and the fixed words. Wakes share
   one collapse id, so several of them are one notification and the
   lock screen shows no count either. The phone always fetches the real
   request over the paired bootloader channel.
2. **Push is best-effort and never blocks or fails a request.** The
   dispatcher swallows + logs every send failure; polling remains the
   fallback path (foregrounded app, push outage, token rotation lag).
3. **A failure is recorded as an outcome and a count** (hard rule
   15.ab): the platform, a class from ``OUTCOMES``, the provider's
   status number and running totals. Never a token, a key, a device's
   name, a phone, a request, or a word of the provider's answer.

Config values (APNs .p8 signing key, FCM service-account JSON) are
SECRET MATERIAL -- resolve them through a SecretSource at config-build
time (Key Vault in production); never inline them in service.yaml.

Install with ``pip install recto[push]`` (httpx with HTTP/2 -- APNs is
HTTP/2-only; FCM rides the same client).
"""

from __future__ import annotations

import json
import logging
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("recto.bootloader.push")

#: One wake per phone per this many seconds. A wake says only "check your
#: queue", so the cards queued meanwhile need one more, not one each.
WAKE_MIN_INTERVAL_SECONDS = 3.0

#: Platform discriminators -- byte-for-byte the values the phone app's
#: PushPlatform constants send on the wire.
PLATFORM_APNS = "apns"
PLATFORM_FCM = "fcm"

#: THE ONE NOTIFICATION. Every wake shows exactly these words: they name no
#: card, no service, no agent and no count, and they never vary.
WAKE_TITLE = "Recto"
WAKE_BODY = "Something is waiting for your approval in Recto."

#: The marker an open app reads to fetch its queue at once.
WAKE_MARKER = "pending_wake"

#: One id for every wake: a newer wake replaces the one still showing, so a
#: phone never stacks them into a count. Also the Android channel's id --
#: byte-for-byte the phone app's PushWake constants.
WAKE_COLLAPSE_ID = "recto_pending"

#: What a failed send is recorded as. A class, never the provider's words.
OUTCOME_BAD_CREDENTIAL = "bad_credential"          # the provider refused THIS SENDER's key or account
OUTCOME_WRONG_ENVIRONMENT = "wrong_environment"    # the token belongs to another gateway, app or project
OUTCOME_DEAD_TOKEN = "dead_token"                  # the provider says the token is no longer registered
OUTCOME_THROTTLED = "throttled"
OUTCOME_PROVIDER_UNAVAILABLE = "provider_unavailable"
OUTCOME_UNREACHABLE = "unreachable"                # no answer at all (network, TLS, timeout)
OUTCOME_REJECTED = "rejected"                      # refused for a reason none of the above names
OUTCOME_ERROR = "error"                            # a fault in the sender itself
OUTCOMES = (
    OUTCOME_BAD_CREDENTIAL, OUTCOME_WRONG_ENVIRONMENT, OUTCOME_DEAD_TOKEN, OUTCOME_THROTTLED,
    OUTCOME_PROVIDER_UNAVAILABLE, OUTCOME_UNREACHABLE, OUTCOME_REJECTED, OUTCOME_ERROR,
)


def _import_httpx() -> Any:
    try:
        import httpx
    except ImportError as exc:
        raise ImportError(
            "push senders require the optional push extra: "
            "pip install recto[push]"
        ) from exc
    return httpx


def _import_jwt() -> Any:
    try:
        import jwt
    except ImportError as exc:
        raise ImportError(
            "push senders require pyjwt[crypto] (installed by "
            "recto[v0_4]) for provider-auth token minting"
        ) from exc
    return jwt


class PushSendError(Exception):
    """A push send failed. The dispatcher logs and continues -- this
    never propagates into a request path.

    ``outcome`` is one of ``OUTCOMES`` and ``status`` the provider's HTTP
    status (None when there was no answer). The message carries those two
    and nothing of the provider's answer, the token or the credential."""

    def __init__(self, message: str, *, outcome: str = OUTCOME_ERROR, status: int | None = None) -> None:
        super().__init__(message)
        self.outcome = outcome if outcome in OUTCOMES else OUTCOME_ERROR
        self.status = status


def _reason_words(resp: Any) -> set[str]:
    """The provider's own reason codes from a failed answer, upper-cased, for CLASSING only. They are compared with
    fixed names and dropped: nothing read here is logged, stored or raised."""
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001 - an answer with no readable body has no reason
        return set()
    words: set[str] = set()
    if isinstance(body, dict):
        if isinstance(body.get("reason"), str):
            words.add(body["reason"].upper())
        error = body.get("error")
        if isinstance(error, str):
            words.add(error.upper())
        if isinstance(error, dict):
            if isinstance(error.get("status"), str):
                words.add(error["status"].upper())
            details = error.get("details")
            for detail in details if isinstance(details, list) else []:
                if isinstance(detail, dict) and isinstance(detail.get("errorCode"), str):
                    words.add(detail["errorCode"].upper())
    return words


def classify_apns(status: int, reasons: set[str]) -> str:
    """An APNs answer as an outcome class. 403 is the provider token or its key; 410 is a token APNs has retired; a
    400 that names the token or the topic is a token from the other gateway or for another app."""
    if status == 403:
        return OUTCOME_BAD_CREDENTIAL
    if status == 410:
        return OUTCOME_DEAD_TOKEN
    if status == 400 and reasons & {"BADDEVICETOKEN", "DEVICETOKENNOTFORTOPIC", "BADTOPIC", "TOPICDISALLOWED",
                                    "MISSINGTOPIC"}:
        return OUTCOME_WRONG_ENVIRONMENT
    if status == 429:
        return OUTCOME_THROTTLED
    if status >= 500:
        return OUTCOME_PROVIDER_UNAVAILABLE
    return OUTCOME_REJECTED


def classify_fcm(status: int, reasons: set[str]) -> str:
    """An FCM answer as an outcome class. UNREGISTERED is a token FCM has retired; SENDER_ID_MISMATCH is a token minted
    for another project; 401, and a 403 that is not a mismatch, are the service account."""
    if "UNREGISTERED" in reasons:
        return OUTCOME_DEAD_TOKEN
    if "SENDER_ID_MISMATCH" in reasons:
        return OUTCOME_WRONG_ENVIRONMENT
    if status in (401, 403):
        return OUTCOME_BAD_CREDENTIAL
    if status == 404:
        # No reason given with a 404: the project the sender names does not hold this token, or does not exist.
        return OUTCOME_WRONG_ENVIRONMENT
    if status == 429:
        return OUTCOME_THROTTLED
    if status >= 500:
        return OUTCOME_PROVIDER_UNAVAILABLE
    return OUTCOME_REJECTED


class PushSender(ABC):
    """One platform's wake sender."""

    @property
    @abstractmethod
    def platform(self) -> str:
        """Platform discriminator this sender serves ("apns" / "fcm")."""

    @abstractmethod
    def send_wake(self, push_token: str, *, request_id: str) -> None:
        """Fire one wake push. ``request_id`` is never placed in the
        push payload, and since the failure line carries outcomes and
        counts only, nowhere else either.

        Raises PushSendError on failure (dispatcher catches).
        """


@dataclass(frozen=True)
class ApnsConfig:
    """APNs provider-token auth config.

    ``p8_key_pem`` is the CONTENT of the .p8 signing key (resolve via a
    SecretSource); ``team_id`` + ``key_id`` come from the Apple
    Developer portal; ``bundle_id`` is the phone app's bundle id
    (becomes the ``apns-topic`` header); ``use_sandbox`` selects the
    sandbox gateway for development-signed builds.
    """

    team_id: str
    key_id: str
    p8_key_pem: str
    bundle_id: str
    use_sandbox: bool = False
    #: False sends the silent wake of 1.2.4 and earlier: nothing is shown.
    visible: bool = True


class ApnsPushSender(PushSender):
    """APNs HTTP/2 sender using provider-token (JWT ES256) auth.

    Provider JWTs are cached ~50 minutes (Apple accepts 20-60 min).
    The wake push is an ``alert`` at priority 10 carrying the one fixed
    sentence, with ``content-available: 1`` kept so an app that is open
    or suspended still fetches at once. One ``apns-collapse-id`` for
    every wake: a new one replaces the one showing.
    """

    _TOKEN_LIFETIME_SECONDS = 50 * 60

    def __init__(self, config: ApnsConfig, *, client: Any = None):
        self._cfg = config
        self._jwt_value: str | None = None
        self._jwt_minted_at = 0.0
        self._jwt_lock = threading.Lock()
        if client is not None:
            self._client = client
        else:
            httpx = _import_httpx()
            self._client = httpx.Client(http2=True, timeout=10.0)

    @property
    def platform(self) -> str:
        return PLATFORM_APNS

    @property
    def _base_url(self) -> str:
        return (
            "https://api.sandbox.push.apple.com"
            if self._cfg.use_sandbox
            else "https://api.push.apple.com"
        )

    def _provider_jwt(self) -> str:
        with self._jwt_lock:
            now = time.time()
            if (
                self._jwt_value is not None
                and now - self._jwt_minted_at < self._TOKEN_LIFETIME_SECONDS
            ):
                return self._jwt_value
            jwt_mod = _import_jwt()
            self._jwt_value = jwt_mod.encode(
                {"iss": self._cfg.team_id, "iat": int(now)},
                self._cfg.p8_key_pem,
                algorithm="ES256",
                headers={"kid": self._cfg.key_id},
            )
            self._jwt_minted_at = now
            return self._jwt_value

    def send_wake(self, push_token: str, *, request_id: str) -> None:
        url = f"{self._base_url}/3/device/{push_token}"
        headers = {
            "authorization": f"bearer {self._provider_jwt()}",
            "apns-topic": self._cfg.bundle_id,
            "apns-push-type": "alert",
            "apns-priority": "10",
            "apns-collapse-id": WAKE_COLLAPSE_ID,
        }
        # Payload rule 1: the fixed sentence and the bare wake marker -- no request content.
        payload: dict[str, Any] = {
            "aps": {
                "alert": {"title": WAKE_TITLE, "body": WAKE_BODY},
                "sound": "default",
                "content-available": 1,
            },
            "recto": WAKE_MARKER,
        }
        if not self._cfg.visible:
            # The silent wake, as before 1.2.5: the bare marker, nothing shown.
            headers = {
                "authorization": headers["authorization"],
                "apns-topic": self._cfg.bundle_id,
                "apns-push-type": "background",
                "apns-priority": "5",
            }
            payload = {"aps": {"content-available": 1}, "recto": WAKE_MARKER}
        try:
            resp = self._client.post(url, headers=headers, json=payload)
        except Exception as exc:
            raise PushSendError("apns send got no answer", outcome=OUTCOME_UNREACHABLE) from exc
        if resp.status_code != 200:
            raise PushSendError(
                f"apns send returned {resp.status_code}",
                outcome=classify_apns(resp.status_code, _reason_words(resp)),
                status=resp.status_code,
            )


@dataclass(frozen=True)
class FcmConfig:
    """FCM HTTP v1 config. ``service_account_json`` is the CONTENT of a
    Google service-account key file with the ``cloudmessaging.messages``
    permission (resolve via a SecretSource)."""

    project_id: str
    service_account_json: str
    #: False sends the silent wake of 1.2.4 and earlier: nothing is shown.
    visible: bool = True


class FcmPushSender(PushSender):
    """FCM HTTP v1 sender using service-account OAuth2 (JWT-bearer).

    Access tokens are cached until ~5 minutes before expiry. The wake
    push is a high-priority message with a ``notification`` block that
    carries the one fixed sentence (the system draws it when the app is
    not in front) and the ``data`` marker an open app reads. One
    collapse key and one notification tag for every wake: a new one
    replaces the one showing.
    """

    _SCOPE = "https://www.googleapis.com/auth/firebase.messaging"
    _TOKEN_URL = "https://oauth2.googleapis.com/token"

    def __init__(self, config: FcmConfig, *, client: Any = None):
        self._cfg = config
        self._sa = json.loads(config.service_account_json)
        self._access_token: str | None = None
        self._token_expires_at = 0.0
        self._token_lock = threading.Lock()
        if client is not None:
            self._client = client
        else:
            httpx = _import_httpx()
            self._client = httpx.Client(timeout=10.0)

    @property
    def platform(self) -> str:
        return PLATFORM_FCM

    def _oauth_token(self) -> str:
        with self._token_lock:
            now = time.time()
            if self._access_token is not None and now < self._token_expires_at:
                return self._access_token
            jwt_mod = _import_jwt()
            assertion = jwt_mod.encode(
                {
                    "iss": self._sa["client_email"],
                    "scope": self._SCOPE,
                    "aud": self._TOKEN_URL,
                    "iat": int(now),
                    "exp": int(now) + 3600,
                },
                self._sa["private_key"],
                algorithm="RS256",
            )
            resp = self._client.post(
                self._TOKEN_URL,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": assertion,
                },
            )
            if resp.status_code != 200:
                # The token endpoint refuses the service account itself, whatever the status below 500.
                raise PushSendError(
                    f"fcm oauth token exchange returned {resp.status_code}",
                    outcome=(OUTCOME_PROVIDER_UNAVAILABLE if resp.status_code >= 500
                             else OUTCOME_THROTTLED if resp.status_code == 429 else OUTCOME_BAD_CREDENTIAL),
                    status=resp.status_code,
                )
            body = resp.json()
            self._access_token = body["access_token"]
            self._token_expires_at = now + float(body.get("expires_in", 3600)) - 300
            return self._access_token

    def send_wake(self, push_token: str, *, request_id: str) -> None:
        url = (
            f"https://fcm.googleapis.com/v1/projects/"
            f"{self._cfg.project_id}/messages:send"
        )
        # Payload rule 1: the fixed sentence and the bare wake marker -- no request content.
        message: dict[str, Any] = {
            "message": {
                "token": push_token,
                "notification": {"title": WAKE_TITLE, "body": WAKE_BODY},
                "data": {"recto": WAKE_MARKER},
                "android": {
                    "priority": "HIGH",
                    "collapse_key": WAKE_COLLAPSE_ID,
                    "notification": {"channel_id": WAKE_COLLAPSE_ID, "tag": WAKE_COLLAPSE_ID},
                },
            }
        }
        if not self._cfg.visible:
            # The silent wake, as before 1.2.5: data only, nothing shown.
            message = {
                "message": {
                    "token": push_token,
                    "data": {"recto": WAKE_MARKER},
                    "android": {"priority": "HIGH"},
                }
            }
        try:
            resp = self._client.post(
                url,
                headers={"authorization": f"Bearer {self._oauth_token()}"},
                json=message,
            )
        except PushSendError:
            raise
        except Exception as exc:
            raise PushSendError("fcm send got no answer", outcome=OUTCOME_UNREACHABLE) from exc
        if resp.status_code != 200:
            raise PushSendError(
                f"fcm send returned {resp.status_code}",
                outcome=classify_fcm(resp.status_code, _reason_words(resp)),
                status=resp.status_code,
            )


class PushDispatcher:
    """Routes wake pushes to the right platform sender, asynchronously.

    ``notify(phone, request_id)`` is safe to call from any request
    handler: it returns immediately (daemon thread does the send) and
    NEVER raises -- push is best-effort by design (hard property 2).
    Phones without a registered token are silently skipped (poll-only).

    At most one wake leaves for a phone per ``wake_min_interval_seconds``:
    the first goes at once, and the ones asked for inside the interval are
    one wake at its end -- late by seconds, never lost.

    A token the provider calls dead is handed to ``on_dead_token(phone_id,
    token)`` once, so the registry can drop it and stop sending to it; the
    phone sends its live token again the next time it opens.
    """

    def __init__(
        self,
        senders: list[PushSender],
        *,
        wake_min_interval_seconds: float = WAKE_MIN_INTERVAL_SECONDS,
        on_dead_token: Callable[[str, str], Any] | None = None,
    ):
        self._senders = {s.platform: s for s in senders}
        self._interval = max(0.0, float(wake_min_interval_seconds))
        self._on_dead_token = on_dead_token
        self._count_lock = threading.Lock()
        self._sent: dict[str, int] = {}                      # platform -> wakes the provider took
        self._failed: dict[tuple[str, str], int] = {}        # (platform, outcome) -> wakes that failed so
        self._wake_lock = threading.Lock()
        self._last_wake: dict[str, float] = {}      # phone -> monotonic time of its last wake
        self._owed_wake: dict[str, tuple[PushSender, str, str, str]] = {}   # phone -> the wake due at its interval's end

    @property
    def platforms(self) -> list[str]:
        return sorted(self._senders.keys())

    def set_dead_token_handler(self, handler: Callable[[str, str], Any] | None) -> None:
        """Who is told of a dead token: ``handler(phone_id, token)``. The server sets it to its registry."""
        self._on_dead_token = handler

    def counts(self) -> dict[str, Any]:
        """Since this process started: ``{"sent": {platform: n}, "failed": {platform: {outcome: n}}}``."""
        with self._count_lock:
            failed: dict[str, dict[str, int]] = {}
            for (platform, outcome), n in self._failed.items():
                failed.setdefault(platform, {})[outcome] = n
            return {"sent": dict(self._sent), "failed": failed}

    def notify(self, phone: Any, request_id: str) -> None:
        token = getattr(phone, "push_token", None)
        platform = getattr(phone, "push_platform", None)
        if not token or not platform:
            return
        sender = self._senders.get(platform)
        if sender is None:
            logger.debug(
                "no push sender registered for platform %r (phone %s)",
                platform,
                getattr(phone, "phone_id", "?"),
            )
            return
        phone_id = getattr(phone, "phone_id", "?")
        wake = (sender, token, request_id, phone_id)
        now = time.monotonic()
        with self._wake_lock:
            if phone_id in self._owed_wake:
                # Already owed one; the newest token is the one it goes to.
                self._owed_wake[phone_id] = wake
                return
            self._last_wake = {p: t for p, t in self._last_wake.items() if t + self._interval > now}
            last = self._last_wake.get(phone_id)
            wait = 0.0 if last is None else last + self._interval - now
            if wait > 0:
                self._owed_wake[phone_id] = wake
            else:
                self._last_wake[phone_id] = now
        if wait <= 0:
            self._start_send(wake)
            return
        timer = threading.Timer(wait, self._send_owed, args=(phone_id,))
        timer.daemon = True
        try:
            timer.start()
        except RuntimeError:
            # No thread to wait in: the wake goes now rather than never.
            self._send_owed(phone_id)

    def _send_owed(self, phone_id: str) -> None:
        with self._wake_lock:
            wake = self._owed_wake.pop(phone_id, None)
            if wake is not None:
                self._last_wake[phone_id] = time.monotonic()
        if wake is not None:
            self._start_send(wake)

    def _start_send(self, wake: tuple[PushSender, str, str, str]) -> None:
        threading.Thread(
            target=self._send_logged,
            args=wake,
            daemon=True,
            name=f"recto-push-{wake[0].platform}",
        ).start()

    def _send_logged(
        self, sender: PushSender, token: str, request_id: str, phone_id: str
    ) -> None:
        platform = sender.platform
        try:
            sender.send_wake(token, request_id=request_id)
        except Exception as exc:  # noqa: BLE001 - hard property 2
            # Hard property 3: the outcome's class, the provider's status number and the running counts - never the
            # token, a key, the phone, the request or the provider's words (hard rule 15.ab).
            outcome = exc.outcome if isinstance(exc, PushSendError) else OUTCOME_ERROR
            status = exc.status if isinstance(exc, PushSendError) else None
            with self._count_lock:
                self._failed[(platform, outcome)] = self._failed.get((platform, outcome), 0) + 1
                of_class = self._failed[(platform, outcome)]
                failed = sum(n for (p, _), n in self._failed.items() if p == platform)
                sent = self._sent.get(platform, 0)
            logger.warning(
                "push wake failed: platform=%s outcome=%s status=%s (this outcome %d; platform sent %d, failed %d)",
                platform,
                outcome,
                "none" if status is None else status,
                of_class,
                sent,
                failed,
            )
            if outcome == OUTCOME_DEAD_TOKEN and self._on_dead_token is not None:
                try:
                    self._on_dead_token(phone_id, token)
                except Exception:  # noqa: BLE001 - hard property 2: the drop is best effort too
                    logger.warning("push wake: a dead token could not be dropped (platform=%s)", platform)
            return
        with self._count_lock:
            self._sent[platform] = self._sent.get(platform, 0) + 1
