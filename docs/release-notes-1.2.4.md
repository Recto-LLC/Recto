# Recto Agentic 1.2.4 (build 22)

The phone app and the bootloader. It follows 1.2.3 (build 21). No re-pair: a
phone paired on 1.2.3 keeps its pairing, its keys and its recovery phrase, and
is never asked for evidence. Update the phones first, then the bootloader (see
below). A member pairs a SERVICE once more before its first approval.

This file is not a published page. The site publishes only the pages its
allowlist names (`docs/_config.yml`).

---

## What changed for someone using the app

**A new pairing shows where its key lives.** On Android the identity key is made
with a key attestation for that one pairing and its certificate chain is sent;
on iOS the app asks App Attest to vouch for the two keys being registered. A
bootloader that does not read either ignores them.

**A key made for a pairing that never reached a bootloader is made again** for
the next one, on Android, where a key carries its attestation for ever. Any other
key is reused as before. When a bootloader refuses a key it does not hold, the
app offers to make a new one, asks twice, refuses for a genesis member, and
keeps the recovery phrase.

**Test device** (under the pairing code) takes a one-time code from the
bootloader's own host, for an emulator or a phone no vendor vouches for.

**On an iPhone, an approval is also answered by the app's own attested key**
when the bootloader keeps that key. It asks for nothing more: no second Face ID,
and an answer is sent without it when it cannot be made within three seconds.

**A member approves from their own phone.** A card asked of a member's phone was
checked against the operator's key and always failed. It is now checked against
the key the member's phone showed when it paired the service. Pairing a service
is signed by the identity key too, with the one biometric it already asked.

**An approval card's validity counts while the card is open.** It was worked out
once, when the card was first drawn.

## What changed for someone running a bootloader

**A new key needs evidence (hard rule 14.8).** `RECTO_DEVICE_EVIDENCE_MODE` is
`require` unless it is set to `record`, which verifies, stores the class and
refuses nothing. To move a live bootloader: update the phones, set `record`
before the new bootloader starts, read the classes new pairings get, then
`require`.

- It covers the owner slots, the member plane, a member hand-over and the owner
  reset's fresh device.
- A phone the registry holds re-pairs, polls and approves as before, whatever it
  can show. An older app re-pairs; an older app cannot enter a `require`
  bootloader as a NEW phone.
- Refusals: `device_evidence_required`, `device_evidence_invalid` with a
  `reason`, `test_device_code_invalid`.
- `GET /v0.4/manage/phones`, the registration answer and `recto bootloader
  owner-slots` show each phone's class.
- The pair relay sends `deviceClass`, and the signed pair result carries it as
  `cap.scope.device_class`: `attested`, `test`, `unverified`, or `none` when no
  phone is bound to the pair. A consumer decides by the signed copy.

| Setting | Default |
|---|---|
| `RECTO_DEVICE_EVIDENCE_MODE` | `require` |
| `RECTO_APPROVAL_EVIDENCE_MODE` | `record` |
| `RECTO_UNPAIR_IDENTITY_MODE` | `record` |
| `RECTO_ATTESTATION_ANDROID_APPS` | empty (the app is not checked) |
| `RECTO_ATTESTATION_IOS_APP_IDS` | empty (no iOS evidence verifies) |
| `RECTO_ATTESTATION_STATUS_FILE` | unset (revocations are not checked) |

**The acts of a phone whose App Attest key is kept.** An iPhone that enters with
App Attest has that key kept (its id, public half and counter; never the
receipt). Each act it signs then carries an assertion over the act, the card,
what its identity key signs and the card's issue time, checked offline: an
approval, a deny, an owner-slot or reset card, a phone revoke, a push token, a
vault grant, revoke, stop-all and deny, a service pairing, and a member
hand-over. Reads are not asked.

- A wrong assertion is refused as `approval_evidence_invalid` in both modes and
  the card stays open. A missing one is accepted and noted under `record`, and
  refused as `approval_evidence_required` under `require`. Under `require` a
  missing one is still accepted where the act only removes authority: a deny, a
  phone revoke, a vault revoke, stop-all or deny, and the cancel of an owner
  reset.
- A phone with no kept key - every Android phone, and every iPhone paired before
  this - is asked nothing, in either mode.
- **A lost key** (a reinstall, a new phone from a backup: Apple says these keys
  do not survive). Under `record` nothing stops. Under `require` the phone comes
  back by pairing again with a fresh attestation, or, with no vendor, by pairing
  again with a test-device code from the host, which lets the key go. A re-pair
  with nothing to show is not refused, and keeps the key.
- Whether a phone needs Apple's servers to make an assertion is not stated by
  Apple. Test a real iPhone with Apple's hosts blocked before `require`.
- The phone list and `recto bootloader owner-slots` show whether a phone's last
  act was `asserted` or `missing`. It is not relayed to a consumer.

**What is kept of the evidence is a closed list (hard rule 14.8).** It is checked
once and dropped. A phone's record gains the class, the platform, the date (not
the time) and a test device's label, the App Attest key as above, and the class
and date of its last act. An enrollment that waits for an owner's approval holds
the first four beside the key it is for, and no evidence; an iPhone attests again
on its second pass.

**A grant redeemed here was approved here (hard rule 14.9).** `/v0.4/secrets/read`
and `/v0.4/connections/act` took a grant signed by the operator's key as their
only authority, and that key is the recovery phrase's. They now also ask that an
owner phone's identity key approved that grant's card on this bootloader, and
answer `403 grant_not_approved_here` otherwise. No caller changes. What was
accepted and is now refused: a grant signed with no card; one approved on another
bootloader, or on a member's phone; and one approved before this update and not
yet redeemed - ask for it again. Kept until the grant expires: its digest and its
expiry (`approved_grants.json`, or a row in the Postgres `results` table).

**An approved grant carries a receipt (hard rule 14.10).** `GET
/v0.4/capability/result/<id>` adds `grant_receipt` beside `capability_jws` when
the bootloader holds a signing key: a JWS by that key which says an owner phone's
identity key approved this grant here. It is additive; nothing asks for it yet.
`recto/capability/grant_receipt.py` mints and checks it, and
`tests/grant_receipt_vectors.json` holds vectors for any verifier. A Postgres
deployment rolling between this and an older bootloader answers an approved
result made by the new one with a 500 on the old one until it expires (10
minutes): update every instance together.

**An unpairing is signed by the identity key too (hard rule 14.11).** `POST
/v0.4/devices/unpair` takes `phone_id` and `identity_signature_b64u`, and passes
on to the consumer, as `bootloaderJws`, this bootloader's signed word that a
paired phone asked (`devices:unpair_result`, 300 s). `RECTO_UNPAIR_IDENTITY_MODE`
is `record` by default: an unpairing without it goes through and is noted.
`require` refuses it as `unpair_identity_required`; a phone on an older app then
updates first or unpairs from the service's account page. `off` looks at nothing.
The word is for the owner's own key or for the member bound to that service; an
owner's phone stands in for no member (`not_the_owners`).

**A member's approvals (hard rule 14.12)** are off until an agent's entry lists
what it may ask a member: `member_actions` and `member_audiences`, two non-empty
lists in the agents file. An entry that names anything of the floor (the
bootloader, its vault, connections, pairings, profiles, owner slots), or an act
not named `noun:verb` (a deployment's bare name is one), refuses the start. With a list, `/v0.4/health` says `member_grants: true`, so a
consumer asks a member only of a bootloader that can verify one.

- An agent asks only the members of the consumers its entry names
  (`member_consumers`): `member_consumer_not_allowed`. An owner's phone is never
  asked a member's card: `member_phone_required`.
- Refusals when a card is asked: `member_grants_off`, `member_key_missing`,
  `member_issuer`, `member_subject_mismatch`, `member_audience_denied`,
  `member_action_denied`, `member_groups_denied`, `member_scope_denied`,
  `member_parent_denied`, `member_max_uses`, `member_window`.
- At the tap: `member_binding_changed`, when the service was unpaired, the
  binding moved, or the key is another than when it was asked.
- At a pairing: `pair_identity_invalid`, for a bound phone's signature that does
  not verify. With none the pairing goes on and no key is kept.
- A member who paired before this, or on an older app, has no key kept: pair the
  service once more.
- The key goes when the service is unpaired through the relay, when the binding
  moves to another phone, and when the phone is revoked.
- A grant names its member as its `sub`: the handle itself, or
  `agent:<id>@user:<handle>`; its `iss` is `phone:member:enclave`.
- The receipt of a member's approval names the slot `member` and the handle as
  `cap.scope.subject`. A door that takes a member's act takes that receipt and no
  owner's in its place.

**On the phone the identity key signs first.** A capability, a profile card, a
coin signature, and pairing or unpairing a service ask the biometric before the
recovery phrase's key signs. Pairing and unpairing a service now ask for it once;
everything else asks as often as before.

**Stored state gains fields.** Each phone's record in `phones.json` (or its
Postgres row) gains `device_class`, `device_platform`, `device_class_at_unix`,
`device_test_label`, `app_attest_key_id`, `app_attest_public_key_b64u`,
`app_attest_counter`, `act_class` and `act_class_at_unix`. An older bootloader does not start on a record that
carries them: to go back, restore the state dir from before the update. `member_grant_keys`
(and, on a waiting card, its member's consumer, handle and key) is written only once
a member has paired under this.

## A correction to the 1.2.3 notes

They said an auth-only agent raises no card of any kind. It raises no card on
the queue. A user-vault grant request from such an agent still rings the
subject's own bound phone, as hard rule 15.z has it.

## Known, and not in this build

- **App Attest proves the app, not the key.** A jailbroken iPhone running the
  genuine app passes it, as Apple says. Android's evidence is about the key.
- **A service unpairing** is asked for no App Attest assertion: it only removes
  authority. A member hand-over's assertion has no sender in the app, which does not
  offer the hand-over.
- **An iPhone paired before this has no way to add a key** but pairing again.
- **A member's approval is never redeemed at the bootloader itself.**
- **A consumer's own way of unpairing** (its account page) does not reach the
  bootloader, which keeps the member's key until the service is paired again; the
  consumer refuses a user it has no key for.
- **The vendors' device marks, a device block list and Play Integrity** are not
  part of this.
- **Attestation keys a vendor has revoked** are refused only when
  `RECTO_ATTESTATION_STATUS_FILE` names a list; nothing fetches it.
- **The bootloader answers HTTP/1.0** and **the phone polls every three
  seconds**, as in 1.2.3.
