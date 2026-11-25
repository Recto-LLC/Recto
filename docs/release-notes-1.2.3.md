# Recto Agentic 1.2.3 (build 21)

The phone app. It follows 1.2.2 (build 20). No re-pair: a phone paired on
1.2.2 keeps its pairing, its keys and its recovery phrase. Update the
bootloader first, then the phone (see below).

This file is not a published page. The site publishes only the pages its
allowlist names (`docs/_config.yml`).

---

## What changed for someone using the app

**A capability card shows everything it signs.** A purpose longer than 240
characters is read a part at a time: *Read on*, beside Approve, shows the next
part, and Approve waits for the last. The card shows how often a grant may be
used (*any number until it ends* when it signs no count), its limits, a later
start, a parent grant, a profile, its scope (*any* when nothing limits it) and
up to three of its actions at a glance. A card that signs a field the app
cannot show takes a Deny only.

**A request that changes under its id is refused and says so.** The app
remembers, in memory and as a digest only, what each request was first shown
with. One that arrives again with another payload cannot be approved.

**Hidden characters are written out.** A character that draws nothing, strikes
out another or changes the reading order is shown as its code point, on every
kind of card. Text reads in its own direction. The joiners that Persian,
Arabic, Devanagari and emoji are spelled with are left as they are, and so is
a quoted title's balanced isolate in a sentence.

**A UUID in a request's words is checked against the signed subject however it
is spelled.** Another dash, a look-alike letter, a mark or a line break is the
same UUID to the check.

**One card that cannot be read is one card.** It is shown as *Unreadable
request* with a Deny, and the cards beside it stand.

**Approve waits one second after a card appears or moves,** so a tap meant for
what stood there is not a tap on the card that took its place.

**Pairing a service shows this phone's fingerprint.** It is in the form the
service's page shows, before the request is sent and after it, so the two can
be compared.

**A full wipe asks before it erases a recovery phrase.** A phone that holds a
recovery phrase, was set up with one, or cannot say, is asked a second
question in Settings. The one-tap start-fresh path never erases it.

## What changed for someone running a bootloader

Update the bootloader before the phones: this app refuses a request id whose
window is stamped twice, and this release's bootloader stamps it once. A later
bootloader that signs a new field needs the phone first.

**The card queue has limits.** An agent holds at most 12 open cards on one
phone for one `sub`; all agents together hold 40, and a `sub` with no open card
passes that by up to 8. An agent asks at most 30 times a minute for one `sub`.
A card lives at least 30 seconds. Its fields are UTF-8 text with lengths. Each
refusal names itself; the README lists them. A request that asks exactly what
an open card asks is answered with that card's id and
`"status": "already_open"`. One wake goes to a phone per three seconds.

| Setting | Default |
|---|---|
| `max_open_cards_per_agent` (`RECTO_MAX_OPEN_CARDS_PER_AGENT`) | 12 |
| `max_open_cards_per_phone` (`RECTO_MAX_OPEN_CARDS_PER_PHONE`) | 40 |

**`POST /v0.4/manage/push_token` answers only the phone's poll key,** in every
`signed_poll_mode`.

**A card's app banner is the authenticated agent's** and nothing the request
body says. An auth-only agent raises no card of any kind.

**Stored state that cannot be read is refused by name.** A connections or
user-vault sidecar answers 503 `metadata_unreadable` and is left as it is; a
genesis members file is never written over, `--force` or not; one stored card
that cannot be served is left out, and the rest are served.

**The genesis roster changes by the passphrase.** A chain with no passphrase
member reads as before and takes one entry: the one that seats it.

**The admin UI answers loopback Host names or the declared tunnel hostname.**
A bind beyond loopback is refused while `cf_access_required` is true.

## Known, and not in this build

- **The bootloader answers HTTP/1.0** and **the phone polls every three
  seconds**, as in 1.2.2.
- **The card has been tested by its model and its markup.** The layout is
  measured on no device yet.
