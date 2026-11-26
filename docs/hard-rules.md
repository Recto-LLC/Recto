# Recto — Hard Rules

Non-negotiable constraints on substrate code. Read before authoring.

**This registry is the CONTRACT: what an integrator can rely on the substrate
to do, and what it will never do.** Rules governing how any particular operator
runs their own deployment are not contract, and are not here.

**Numbers are stable anchors and are never renumbered** — source across this
repo cites them, so a gap is deliberate and reusing one would silently
re-point every citation. The gaps are rules that turned out to govern an
operator's own tooling rather than this substrate; they were removed rather
than renumbered.

Every rule cited anywhere in this repository is declared here. A citation to
a number this file does not carry is a bug — it points at a registry the
reader has no access to, which is worse than no citation at all.

---

**1. The YAML schema is additive only.** `apiVersion: recto/v1` is locked. No
renames, no field removals; two minor versions of deprecation before anything
goes. A v2 schema lives *alongside* v1, never in place of it. Deployed config
outlives the release that read it.

**2. Secrets are never logged, serialized, or echoed in stack traces.** A
secret value is consumed immediately and never held in a longer-lived object
than necessary. `SecretMaterial.__repr__` returns `<redacted>`. Any new path
handling secret values follows the same convention.

**3. Apache 2.0, and the substrate stays free.** No commercial-only features in
`recto-core`. Hardware-enclave backends may be a separate paid offering; the
substrate is not.

**4. The launcher path is single-file-runnable.** `python -m recto launch
<yaml>` works after `pip install recto` and nothing else. No daemon, no central
registry, no prerequisite database.

**5. Recto is wrapped by the Windows service registrar, not the reverse.** The
registrar's application parameter points at `python -m recto launch`. Absorbing
registration natively is allowed only with a documented migration path.

**6. The `SecretSource` ABC is the public API contract.** A new backend must not
require changes to `recto.launcher` or to any consumer's `service.yaml` beyond
the `source:` selector. Backends declare themselves; the launcher stays generic.

**9. The phone enclave is the root of trust; agents inherit from humans.** Each
new credential type adds a `PendingRequest.kind` and reuses the operator-gated
phone-side primitive. Agents never get direct phone-side access and never
bypass approval — they act only via operator-issued, scoped, time-bounded
capabilities. **No flow may let an agent act past its capability's expiry,
exceed its scope, or persist after revocation.**

**10. Runtime architecture and packaging architecture are separate concerns.**
Recto ships as `recto-core` (substrate), `recto-client-{py,ts,cs}` (agent
SDKs), and the phone app. Three audiences, three channels. Ask which package a
feature belongs in before shaping the implementation.

**13. The artifact is the canonical record, not a ledger row.** Signed payloads
— capability JWS, pairing JWS — are portable: the
bytes themselves are the record. Transports (HTTP, folder drop, QR) are
interchangeable serializations of the same payload. **Verification must never
require any particular runtime to still be alive.**

**14. The key is the identity.** A phone IS its enclave keypair, named by its
`phone_ref` - derived from the public key, usable as a credential by no one.

1. **`phone_ref` names the phone;** the registry mints no other identifier.
2. **Every crossing is a signature by the phone's key over what crossed.**
3. **Registries key on the key:** the same key pairing again is the same phone.
4. **A bootloader holds two owner slots, primary and recovery;** after its first
   owner, a new owner key enters one only with an owner phone's approval.
5. **A consumer binds to the key, not to the id.**
6. **The user plane is a vault plane:** a consumer holds no opener for any
   user's vault and no roster of users' phones.
7. **The top plane needs the recovery passphrase AND one owner device, every
   time,** and the bootloader's id is sealed at genesis, never re-derived.
8. **A new key shows where it lives.** Unless the operator sets `record`, a key
   this registry does not hold enters a slot only with its platform's evidence
   for this registration, or on a one-time test-device code issued at the
   bootloader's own host, and it is kept as `attested` or `test`. Android key
   attestation is about the identity key itself: made in the TEE or StrongBox of
   a phone with a verified, locked boot. iOS App Attest is about the app: a
   genuine build this bootloader names vouched for the identity key and the poll
   key, and that the key is in the Secure Enclave rests on that app's code. A
   key the registry holds is not refused a re-pairing for want of evidence, and
   no read asks for any; a vendor's root gates admission, never identity.
   **An iPhone answers with its attested key.** Where the registry keeps a
   phone's App Attest key, each act the phone signs may carry that key's
   assertion over the act, checked here with no vendor asked. A wrong one is
   refused and the act stays undone. A missing one is accepted and noted, or
   under `require` refused - unless the act only removes authority (a deny, a
   revoke, a vault revoke or stop-all, the cancel of an owner reset). A phone
   with no kept key is asked nothing; an Android phone's identity key is its
   attested key and signs already.
   **Nothing of the evidence outlives its check except what this rule names.**
   The evidence is read once and dropped, and the list of what is kept is
   closed, beside the identity key the registry already names the phone by: the
   class, the platform, the date and a test device's label; **of an App Attest
   object, its key's id, its public key and its counter, and nothing else;** and
   whether the phone's last act carried an assertion, and its date. The App
   Attest receipt is not kept: it serves only the vendor's own service. The kept
   key is in the phone's record (and in the record of an owner reset until it
   seats the phone) and nowhere else. Nothing off the list reaches a stored
   record, an enrollment that waits, a log line, a refusal beyond its fixed
   reason, an event, the relay or a signed result, and the kept key reaches none
   of these but its record. A thing joins the list by being named here, and
   nothing on it is a device identifier. The phone reads the proof for the one
   registration, keeps of it the App Attest key's id alone, and never asks the
   platform to attest a device identifier or a device property.
9. **A grant redeemed here was approved here.** The recovery phrase alone opens
   nothing at a bootloader: a grant that reads a secret or acts on a connection
   is taken only where an owner phone's identity key approved its card on this
   bootloader. Kept of it until the grant expires: its digest and that expiry.
   On the phone the identity key signs first, with its biometric, and the
   phrase's key only after.
10. **An approved grant carries this bootloader's receipt.** Beside the grant it
   hands out, the bootloader signs, with its own key, that a paired phone's
   identity key approved that grant here: the grant's digest, its audience and
   expiry, the approver's slot and the classes of rule 8. A verifier checks it
   offline against the key it pinned. The receipt names no phone, is never spent
   and is not kept.
11. **An unpairing relayed here is the phone's own act.** The phrase's key signs
   it, and the identity key signs it too; the bootloader passes on its own signed
   word that one did, and for whom: an owner's phone for the owner's own key, a
   member's for its own subject at that consumer, and neither for the other. A
   person who has no phone is never kept from unpairing: a consumer keeps a way
   of its own that asks no phone.
12. **A member approves for itself alone.** A member's approval is checked against
   the key that member's own phone presented, under its identity key, when it
   paired that consumer, and never the operator's. That public key is kept on the
   phone's record, for that consumer, while the binding and the pairing stand.
   What a member may be asked is the operator's list, over a floor no list moves:
   never the bootloader, its vault, a connection, an owner slot, a deployment or
   another person. It is refused when it is asked, by name, not after the tap.
   Its receipt says `member` and the subject's handle.
   **The planes.** A member is a consumer's, one plane below the owner's: bound to
   that consumer by an opaque handle, its key kept under that binding and gone
   with it. Nothing of a member's is judged by, signed with or kept beside an
   owner slot's, the operator's key or the top plane, and nothing of the owner's
   is reached through a consumer. An owner's phone speaks for no member, and an
   owner's receipt stands in for no member's. An agent asks only the members of
   the consumers it is listed for, and one consumer's members are not another's.
   What a consumer does to its own member is the consumer's act, on its records.

**15. Fail-closed has named shapes.** Each is a decision Recto stands on,
pinned by a test; a finding that names one is answered by its letter.

- **a.** No operator key, no authority.
- **b.** The pending envelope is a read, never an approval.
- **c.** Time bounds are checked upstream; a grant adds its ceiling.
- **d.** A master is revocable once its children are revoked.
- **e.** The recovery phrase is exported only behind a fresh biometric proof.
- **f.** An unpinned certificate is accepted only within one pairing, for one host.
- **g.** A challenge is single use and expires, in every store.
- **h.** The wire names what it carries; a secret's name is never its value.
- **i.** Development-only key code is compiled out of store builds.
- **j.** Verification is staged, and each stage says what it defers.
- **k.** A secret's config is the operator's definition, never a caller's request.
- **l.** A heartbeat token is a credential, not a capability.
- **m.** A subject is an opaque handle, never a platform identity.
- **n.** A bound subject rebinds only by its bound phone.
- **o.** The bootloader stores no platform user id.
- **p.** An auth-only agent raises no card.
- **q.** The relay log carries the status only.
- **r.** A device label is generated, never asked.
- **s.** A grant verifies against the subject's bound phone alone.
- **t.** A grant past its date, or longer than the cap, is refused at admission.
- **u.** A revoked grant never grants again.
- **v.** A grant names one agent.
- **w.** Admission is not release.
- **x.** A card that cannot render a signed field refuses to sign.
- **y.** Nothing from a card persists after the tap.
- **z.** A grant request rings only the subject's bound phone.
- **aa.** A revoke never needs the platform.
- **ab.** Recto records nothing of what a service asks or which service asked:
  no event, log line or banner carries a card's content, an agent's or
  service's name, a connection key's name or a consumer's address. The
  platform tracks what it sends to Recto and receives from it. Recto keeps
  only its own records (poll verdicts, its own keys, enrollment, phone
  revokes), never a service's. The connections key gate's audit mode follows
  the same rule: it logs counts only, so the keys a service reads are known
  from the platform's records, never Recto's.
