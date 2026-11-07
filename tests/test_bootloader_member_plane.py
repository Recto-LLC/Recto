"""THE MEMBER PLANE (2026-09-30) -- members pair to the business one plane DOWN, never into its slots.

The bootloader's two slots (hard rule 14.4) are the BUSINESS owner's phones. A consumer (a
downstream service that pairs its own users through this bootloader) mints codes for its MEMBERS
through ``/v0.4/pairing/code`` with its agent token. Today that code is indistinguishable from the
owner's: a member's fresh phone registers into ``primary`` by default, meets the owner's phone
there (409 slot_occupied), and the REPLACE answer -- signed by the member's OWN incoming key --
revokes the owner's phone. That is a plane crossing: a member's code must never carry the
authority to read, fill or displace a business slot.

THE SHAPE THESE TESTS PIN: a consumer mints a
MEMBER code by naming who it is for -- ``{"member_of": {"consumer": <base url>, "subject": <opaque handle>}}``
on ``/v0.4/pairing/code``; a registration on a member code lands in the member plane (no slot,
bound to that consumer user) and never answers 409 slot_occupied.

RED-BUILDS (both failed on the server before the member plane, 409 slot_occupied; a probe showed the
REPLACE answer displacing the owner):
  - a member registration never displaces the owner, even with a REPLACE signed by its own key;
  - a member registration lands beside the slots, and the owner's slot still holds the owner.
POSITIVE CONTROL: the owner's own code still fills the business slots exactly as 14.4 says.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest

from recto.bootloader.server import ChallengeStore, create_server
from recto.bootloader.state import SLOTS, StateStore

from tests.test_bootloader_slots import Phone, _http


def _subject(name: str) -> str:
    """An opaque subject handle for a test user, minted the way a consumer would (hard rule 15.m)."""
    return base64.urlsafe_b64encode(hashlib.sha256(name.encode()).digest()).rstrip(b"=").decode("ascii")


AGENT_ID = "consumer-agent"
AGENT_TOKEN = "agent-token-fixture"
CONSUMER = "https://consumer.example"


@pytest.fixture
def ctx(tmp_path):
    import threading

    state = StateStore(state_dir=tmp_path)
    challenges = ChallengeStore(state=state)
    server = create_server(
        bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="member-plane-test",
        challenges=challenges, ssl_context=None, signed_poll_mode="required",
        capability_agent_tokens={AGENT_ID: AGENT_TOKEN},
        member_code_consumers={AGENT_ID: [CONSUMER]},
    )
    host, port = server.server_address
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield {"base_url": f"http://{host}:{port}", "state": state, "challenges": challenges}
    finally:
        server.shutdown()


def _member_challenge(ctx, user_id: str) -> str:
    """A consumer mints a MEMBER code for one of its users, then the phone asks for its challenge."""
    status, minted = _http(
        "POST", f"{ctx['base_url']}/v0.4/pairing/code",
        {"member_of": {"consumer": CONSUMER, "subject": _subject(user_id)}},
        headers={"X-Recto-Agent-Id": AGENT_ID, "X-Recto-Agent-Token": AGENT_TOKEN},
    )
    assert status == 200, minted
    status, chal = _http("GET", f"{ctx['base_url']}/v0.4/registration_challenge?code={minted['code']}")
    assert status == 200, chal
    return chal["challenge_b64u"]


def _business_slot_holders(ctx) -> dict[str, str]:
    return {p.slot: p.phone_id for p in ctx["state"].list_phones() if p.slot in SLOTS}


def test_the_owners_code_still_fills_the_business_slots(ctx) -> None:
    """POSITIVE CONTROL: 14.4 unchanged for the business owner."""
    owner = Phone("owner pixel")
    status, body = owner.register(ctx, "primary")
    assert status in (200, 201), body
    assert _business_slot_holders(ctx) == {"primary": owner.ref}


def test_a_member_registration_never_displaces_the_owner(ctx) -> None:
    """The member plane: no 409 for a member code, and no REPLACE of the owner even when the member signs one."""
    owner = Phone("owner pixel")
    assert owner.register(ctx, "primary")[0] in (200, 201)

    member = Phone("member phone")
    challenge = _member_challenge(ctx, user_id="member-1")
    first, first_body = member.register(ctx, "primary", challenge=challenge)
    assert first != 409, f"a member code must never reach the business slot question: {first_body}"

    # even a replace the member signs itself must displace nobody
    member.register(ctx, "primary", replace=owner.ref, challenge=challenge)
    assert _business_slot_holders(ctx).get("primary") == owner.ref, "the owner's phone left its slot for a member"


def test_a_member_registration_lands_beside_the_slots_bound_to_its_user(ctx) -> None:
    """The member plane: the member phone registers, outside SLOTS, and the owner's slot is untouched."""
    owner = Phone("owner pixel")
    assert owner.register(ctx, "primary")[0] in (200, 201)

    member = Phone("member phone")
    status, body = member.register(ctx, challenge=_member_challenge(ctx, user_id="member-1"))
    assert status in (200, 201), body

    record = ctx["state"].get_phone(member.ref)
    assert record is not None, "the member phone has no registration"
    assert record.slot not in SLOTS, f"a member took a business slot: {record.slot!r}"
    assert _business_slot_holders(ctx) == {"primary": owner.ref}


def test_the_owners_phone_scanning_a_member_code_keeps_its_slot(ctx) -> None:
    """A member code can never DEMOTE a business key: re-registering the owner's own key through it keeps primary."""
    owner = Phone("owner pixel")
    assert owner.register(ctx, "primary")[0] in (200, 201)
    status, body = owner.register(ctx, challenge=_member_challenge(ctx, user_id="member-1"))
    assert status in (200, 201), body
    assert _business_slot_holders(ctx) == {"primary": owner.ref}


def test_a_member_code_answers_no_slot_question_by_name(ctx) -> None:
    """The replace claim on a member challenge is refused BY NAME, and the challenge displaces nobody."""
    owner = Phone("owner pixel")
    assert owner.register(ctx, "primary")[0] in (200, 201)
    member = Phone("member phone")
    status, body = member.register(ctx, "primary", replace=owner.ref, challenge=_member_challenge(ctx, user_id="member-1"))
    assert status == 400 and "answers no slot question" in json.dumps(body), (status, body)
    assert ctx["state"].get_phone(owner.ref) is not None


# --------------------------------------------------------------------------
# CARDING BY PLANE (2026-11-06, the order's change 2). A member phone answers only a request its consumer's agent makes
# for THAT member: the request names {consumer, subject} in member_of, and the pair is one of the phone's
# member_bindings. A request that names no member, or another one, is refused by name before anything is queued - a
# member phone never answers a business-plane request. The business slots card exactly as before.
# --------------------------------------------------------------------------


def _card(ctx, phone_ref: str, member_of: Any = None, *, omit: bool = False) -> tuple[int, dict[str, Any]]:
    """The consumer's agent asks for a capability on one phone; ``member_of`` rides beside the claims."""
    from tests.test_bootloader_capability import _claims_dict

    body: dict[str, Any] = {"phone_id": phone_ref, "claims": _claims_dict(), "operation_description": "member plane"}
    if not omit:
        body["member_of"] = member_of
    return _http("POST", f"{ctx['base_url']}/v0.4/capability/request", body,
                 headers={"X-Recto-Agent-Id": AGENT_ID, "X-Recto-Agent-Token": AGENT_TOKEN})


def _member(ctx, user_id: str = "member-1") -> Phone:
    """A member phone registered on a member code for ``user_id``, beside an owner who holds primary."""
    if not _business_slot_holders(ctx):
        assert Phone("owner pixel").register(ctx, "primary")[0] in (200, 201)
    member = Phone(f"phone of {user_id}")
    status, body = member.register(ctx, challenge=_member_challenge(ctx, user_id=user_id))
    assert status in (200, 201), body
    return member


def _queued(ctx, phone_ref: str) -> int:
    return len(ctx["state"].list_pending_for_phone(phone_ref))


def test_a_member_phone_carded_for_its_own_member_is_queued(ctx) -> None:
    """POSITIVE CONTROL: the consumer's agent cards the member's phone for that member."""
    member = _member(ctx)
    status, body = _card(ctx, member.ref, {"consumer": CONSUMER, "subject": _subject("member-1")})
    assert status == 201, body
    assert _queued(ctx, member.ref) == 1


def test_a_member_phone_carded_for_another_member_is_refused_by_name(ctx) -> None:
    """A consumer cannot card a member phone registered for another of its users."""
    member = _member(ctx)
    status, body = _card(ctx, member.ref, {"consumer": CONSUMER, "subject": _subject("member-2")})
    assert status == 403 and body.get("error") == "member_binding_mismatch", (status, body)
    assert _queued(ctx, member.ref) == 0


def test_a_member_phone_carded_for_another_consumer_is_refused_by_name(ctx) -> None:
    """The same subject handle under another consumer is another member: the pair is compared whole."""
    member = _member(ctx)
    status, body = _card(ctx, member.ref, {"consumer": "https://other.example", "subject": _subject("member-1")})
    assert status == 403 and body.get("error") == "member_binding_mismatch", (status, body)
    assert _queued(ctx, member.ref) == 0


def test_a_member_phone_never_answers_a_business_plane_request(ctx) -> None:
    """A request that names no member is the business plane's; a member phone is never carded for one."""
    member = _member(ctx)
    status, body = _card(ctx, member.ref, omit=True)
    assert status == 403 and body.get("error") == "member_binding_required", (status, body)
    assert _queued(ctx, member.ref) == 0


@pytest.mark.parametrize("member_of, error", [
    ({"consumer": CONSUMER}, "member_of_invalid"),
    ({"subject": _subject("member-1")}, "member_of_invalid"),
    ({"consumer": "  ", "subject": _subject("member-1")}, "member_of_invalid"),
    ("member-1", "member_of_invalid"),
    ({"consumer": CONSUMER, "subject": ""}, "subject_invalid"),
    ({"consumer": CONSUMER, "subject": "member-1"}, "subject_invalid"),
    (None, "member_binding_required"),
])
def test_a_member_phone_carded_with_no_subject_is_refused(ctx, member_of: Any, error: str) -> None:
    """No subject, a subject in any shape but the opaque handle's, or no consumer: refused by name, nothing queued."""
    member = _member(ctx)
    status, body = _card(ctx, member.ref, member_of)
    assert status in (400, 403) and body.get("error") == error, (status, body)
    assert _queued(ctx, member.ref) == 0


def test_a_member_phone_whose_binding_moved_away_answers_no_one(ctx) -> None:
    """A member phone left with no binding (its member moved to another phone) is carded for nobody."""
    from dataclasses import replace as _replace

    member = _member(ctx)
    record = ctx["state"].get_phone(member.ref)
    ctx["state"].register_phone(_replace(record, member_bindings=()))
    status, body = _card(ctx, member.ref, {"consumer": CONSUMER, "subject": _subject("member-1")})
    assert status == 403 and body.get("error") == "member_binding_mismatch", (status, body)
    assert _queued(ctx, member.ref) == 0


def test_an_owner_slot_phone_is_carded_as_before(ctx) -> None:
    """The business slots are unchanged: no member_of needed, and one sent is not read (the owner's own consumer user
    may ask on the owner's phone; the business plane's authority is the owner's own tap)."""
    owner = Phone("owner pixel")
    assert owner.register(ctx, "primary")[0] in (200, 201)
    assert _card(ctx, owner.ref, omit=True)[0] == 201
    assert _card(ctx, owner.ref, {"consumer": CONSUMER, "subject": _subject("member-1")})[0] == 201
    assert _card(ctx, owner.ref, "not even an object")[0] == 201
    assert _queued(ctx, owner.ref) == 3


def test_the_owners_phone_holding_a_member_binding_keeps_its_business_carding(ctx) -> None:
    """The owner's phone that scanned a member code keeps its slot AND its business-plane cards."""
    owner = Phone("owner pixel")
    assert owner.register(ctx, "primary")[0] in (200, 201)
    assert owner.register(ctx, challenge=_member_challenge(ctx, user_id="member-1"))[0] in (200, 201)
    assert _card(ctx, owner.ref, omit=True)[0] == 201
    assert _queued(ctx, owner.ref) == 1
