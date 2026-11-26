"""What a member may approve (hard rule 14.12).

A member's phone is bound to one consumer's one subject. Its approvals are checked against the key that member presented
when it paired that consumer, never the operator's, and the bootloader decides what one may be about: the consumer's agent
asks, and this is what it may ask for. Nothing a member approves names the bootloader, its vault, the owner's slots, a
deployment, or another member, whatever the operator's list says.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from recto.capability.types import CapabilityClaims

# The issuer a member's grant carries. An operator's verifier pins another, and refuses this one by name.
MEMBER_ISSUER = "phone:member:enclave"
MAX_MEMBER_WINDOW_SECONDS = 25 * 3600

# THE FLOOR, under every list: no audience and no action of these families is ever a member's.
_AUDIENCE_FAMILIES = ("recto", "repo:", "bootloader", "rb1-")
_ACTION_FAMILIES = ("recto:", "bootloader:", "connections:", "secret:", "devices:pair", "devices:unpair", "profile", "owner", "top-plane",
                    "capability:", "vault:", "user-vault")


@dataclass(frozen=True)
class MemberPolicy:
    """The operator's list for one agent: what its members' cards may allow, and for which audiences."""

    actions: frozenset[str]
    audiences: frozenset[str]


def forbidden_audience(audience: str, bootloader_id: str) -> bool:
    a = audience.strip().lower()
    return a == bootloader_id.strip().lower() or a.startswith(_AUDIENCE_FAMILIES)


def forbidden_action(action: str) -> bool:
    # An act a member approves is named <service's noun>:<verb>. A bare name (a deployment's, an operator tool's) is never one.
    return action.strip().lower().startswith(_ACTION_FAMILIES) or "*" in action or ":" not in action


def member_policies(raw: Any) -> dict[str, MemberPolicy]:
    """agent id -> its MemberPolicy, from ``{agent_id: {"actions": [...], "audiences": [...]}}``. None: no agent may card a
    member. An entry that is not two non-empty lists of names, or that names something under the floor, refuses the
    start: a list that cannot be honoured is never read as a shorter one."""
    out: dict[str, MemberPolicy] = {}
    for agent_id, entry in dict(raw or {}).items():
        if not isinstance(entry, Mapping) or set(entry) != {"actions", "audiences"}:
            raise ValueError(f"member_grants[{agent_id!r}] is {{actions, audiences}}")
        lists = {}
        for name in ("actions", "audiences"):
            values = entry[name]
            if (not isinstance(values, (list, tuple, frozenset, set)) or not values
                    or not all(isinstance(v, str) and v.strip() == v and v for v in values)):
                raise ValueError(f"member_grants[{agent_id!r}].{name} must be a non-empty list of names")
            lists[name] = frozenset(values)
        bad = sorted(a for a in lists["actions"] if forbidden_action(a)) + sorted(
            a for a in lists["audiences"] if forbidden_audience(a, "\0"))
        if bad:
            raise ValueError(f"member_grants[{agent_id!r}] names what no member approves: {', '.join(bad)}")
        out[str(agent_id)] = MemberPolicy(**lists)
    return out


def member_claims_refusal(claims: CapabilityClaims, *, subject: str, policy: MemberPolicy, bootloader_id: str,
                          now: int) -> tuple[str, str] | None:
    """Why these claims are not a member's to approve, as (name, detail), or None."""
    if claims.iss != MEMBER_ISSUER:
        return "member_issuer", f"a member's grant is issued as {MEMBER_ISSUER}"
    if claims.sub != subject and not (claims.sub.startswith("agent:") and claims.sub.endswith(f"@user:{subject}")
                                      and claims.sub.count("@") == 1):
        return "member_subject_mismatch", "the claims' subject is not the member the card is for"
    if not claims.aud or any(forbidden_audience(a, bootloader_id) or a not in policy.audiences for a in claims.aud):
        return "member_audience_denied", "an audience is not one a member's grant may name"
    cap = claims.cap
    if cap.groups:
        return "member_groups_denied", "a member's grant names its actions, never a group"
    if not cap.allow_actions or any(forbidden_action(a) or a not in policy.actions for a in cap.allow_actions):
        return "member_action_denied", "an action is not one a member's grant may name"
    if cap.scope.create_for_owner is not None or cap.scope.target_user_id is not None:
        return "member_scope_denied", "a member's grant names no other person"
    if claims.parent_cap is not None or claims.parent_profile is not None:
        return "member_parent_denied", "a member's grant has no parent"
    if claims.max_uses != 1:
        return "member_max_uses", "a member's grant is for one use"
    if not now < claims.exp <= now + MAX_MEMBER_WINDOW_SECONDS:
        return "member_window", "a member's grant has passed, or outlives a day"
    return None
