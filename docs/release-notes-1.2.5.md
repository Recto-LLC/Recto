# Recto Agentic 1.2.5 (build 23)

The phone app and the bootloader. It follows 1.2.4 (build 22). No re-pair: a
phone paired on 1.2.4 keeps its pairing, its keys and its recovery phrase.
Update the phones first, then the bootloader (see "The order" below).

This file is not a published page. The site publishes only the pages its
allowlist names (`docs/_config.yml`).

---

## What changed for someone using the app

**A waiting approval is shown when the app is closed.** When a card is asked,
the phone shows one notification: `Recto` - `Something is waiting for your
approval in Recto.` It is the same for every card. It never says what is
waiting, which service or agent asked, or how many there are, and a newer one
replaces the one showing. A tap opens the app, which reads the card from the
bootloader as it always did. On Android 13 and later the app asks once for
permission to show notifications. Before this, a wake reached only an app that
was open or in the background, and showed nothing.

**The banners say when the bootloader was last heard.** "Couldn't reach the
bootloader" and the server-identity banner each carry `Last heard from the
bootloader: ...`. It was only inside Pairing details.

**A bootloader that did not answer is not called a changed server.** When the
identity check gets no answer the banner is titled `Could not check the
bootloader.` It was titled `Server identity changed.` Polling still stops, and
"Re-verify server" is still the way on.

**An out-of-date reply is checked again when the app comes back.** When polling
stopped because the bootloader's signed reply was out of date twice in a row
(usually a phone clock since corrected), returning to the app runs the full
identity check once, as "Re-verify server" does. Nothing else restarts by
itself. What did not change: only a reply signed by the pinned key, with every
binding right and its expiry alone in the past, earns one refetch; a reply
another key signed, or one that fails any binding, is refused at once with no
refetch, polling stops, and no resume restarts it.

**The pairing screen takes an owner reset's code.** Under the pairing code,
"Owner reset" takes the sixteen-character code the bootloader's host shows
(`XXXX-XXXX-XXXX-XXXX`). Lower case, dashes and spaces are fine, and I, L and O
are read as 1, 1 and 0. The six-digit field keeps its numeric keypad. The
host's QR fills the field. The code is sent once, upper case with no dashes,
and is not stored or logged by the app.

## What changed for someone running a bootloader

### Push wake

**A wake is visible.** `recto/bootloader/push.py` sends an APNs `alert` (priority
10, `content-available` kept) and an FCM message with a `notification` block.
Both carry the fixed title and sentence above and the `pending_wake` marker, and
nothing else: no field differs from one card to the next, an owner's wake and a
member's are the same, and every wake shares one collapse id (`recto_pending`),
so several are one notification. Until this release the payload had no
notification block at all; that changed on purpose. Apple and Google now see
that a phone was woken, when, and the fixed words.

- `RECTO_PUSH_VISIBLE=0` sends the earlier silent wake, byte for byte. Default:
  visible.
- One wake per phone per three seconds, as before.
- Push is still never a dependency: no sender, or a failed send, and the card is
  found by polling.

**A failed send says which kind it was.** The line was the exception's class
name. It is now an outcome, the provider's status number and counts, and it no
longer names the phone or the request:

```
push wake failed: platform=fcm outcome=bad_credential status=401 (this outcome 1; platform sent 0, failed 1)
```

| `outcome` | Meaning |
|---|---|
| `bad_credential` | the provider refused the sender's key or account (APNs 403; FCM 401, a 403 that is not a sender mismatch, a refused service account) |
| `wrong_environment` | the token is for the other APNs gateway or another app (APNs 400 that names the token or the topic), or for another Firebase project |
| `dead_token` | the provider retired the token (APNs 410, FCM `UNREGISTERED`) |
| `throttled`, `provider_unavailable`, `unreachable` | 429; 5xx; no answer at all |
| `rejected`, `error` | refused for another reason; a fault in the sender |

The provider's answer is read only to choose the class and is then dropped: no
word of it, no token and no key reaches the line.

**A dead token is dropped.** On `dead_token` the bootloader clears that phone's
push token and platform - only while the stored token is still the one that
died, never as an upsert, and nothing else of the phone changes. The phone is
found by polling and sends its live token the next time it opens. This is the
bootloader's own act on the provider's answer; no route was added, and `POST
/v0.4/manage/push_token` answers only the phone's poll key as before.

**Settings.** None is new but `RECTO_PUSH_VISIBLE`. The bootloader image now
installs the `push` extra; without it a configured sender failed at start.
`docker/bootloader/docker-compose.bootloader.example.yml` and the README
("Waking a phone") name them:

| Setting | |
|---|---|
| `RECTO_PUSH_APNS_TEAM_ID`, `RECTO_PUSH_APNS_KEY_ID`, `RECTO_PUSH_APNS_BUNDLE_ID` | all three, or APNs is off |
| `RECTO_PUSH_APNS_P8_FILE` | the APNs key, a read-only file |
| `RECTO_PUSH_APNS_SANDBOX` | `1` = sandbox gateway |
| `RECTO_PUSH_FCM_PROJECT_ID` | without it FCM is off |
| `RECTO_PUSH_FCM_SA_FILE` | the service-account JSON, a read-only file |
| `RECTO_PUSH_VISIBLE` | `0` = silent |

A push service delivers only to an app published under the account its key
belongs to. Push wake therefore serves the bootloaders of whoever publishes the
phone build; any other bootloader pairs the same app and is found by polling.
An Android build with no `google-services.json` has no token, asks for no
permission and runs as before.

### The owner reset's code

**Sixteen characters, and no longer burned.** `recto bootloader owner-reset
--arm` returns sixteen characters of Crockford base32 (80 bits, from the
system's random source), shown once as `XXXX-XXXX-XXXX-XXXX` on its own line,
and as a QR of the pairing link when the `qr` extra is installed and the phone's
address is known (`--phone-url`, or `--bootloader-url` when that is not
loopback). The code is redeemed where it was: the `code` parameter of `GET
/v0.4/registration_challenge`. It is still single use, lives ten minutes, is
kept only as a MAC, and is compared in constant time.

- **No count of wrong codes is kept against a long code.** Six digits could be
  guessed, so five wrong codes from the public network burned a live reset code
  - which let a stranger take the operator's reset away. Eighty bits cannot be
  guessed in ten minutes, so the long form is never burned.
- A wrong code still counts against its own public client (five per fifteen
  minutes, `too_many_wrong_codes`).
- **The form is the signer's.** The arm the passphrase signs carries
  `code_form`: `long` or `digits`. The answer and the reset's record carry it
  too. A code is matched only against resets armed in its own form. An arm with
  no `code_form` (an older host) is `digits`; an unknown form is
  `owner_reset_invalid` and arms nothing. No refusal name is new.
- **Six digits for one more release.** `--arm --six-digits` mints the earlier
  code, for a fresh phone whose app cannot take the long one. It burns exactly
  as before: five wrong codes over the public edge, never a private-route typo.
  The switch and the six-digit form go in the next release.
- The pairing link's `kind=bootloader` code is six digits or the sixteen
  canonical characters, in `recto/qr/pair.py` and the app's parser alike. A
  service link's `bootstrap_pair_code` stays six digits.
- `tests/reset_code_vectors.json` is run by the bootloader's tests and the
  app's, so the two read a typed code the same way.

**The order.** An app before 1.2.5 has a six-digit field only and cannot enter a
long code. Ship the phone build first; rely on the long form once 1.2.5 is what
the stores serve (a reset's fresh phone is a new install). Until then arm with
`--six-digits`. A 1.2.5 host against a 1.2.4 bootloader gets six digits back and
says so.

**Stored state gains a field.** A reset's record in `top_plane.json` gains
`code_form` while it is armed.

## The app build

**DataStore's native library is the rebuilt one.** Google Play's 16 KB notice
named `libdatastore_shared_counter.so`: aligned to 16 KB, but built by NDK r20.
`Xamarin.AndroidX.DataStore.Core.Android` 1.2.1.1 still ships that build; 1.3.0
is the first with a rebuilt library (NDK r27, read from the package). The build
now holds the thirteen DataStore packages at 1.3.0. That version needs AndroidX
Collection 1.7.0, so the three Collection packages are held at 1.7.0 too, and
with them the Kotlin standard library, coroutines, OkIO, Annotation and Tracing
resolve newer. See "Known" below.

**A Play gate for the NDK.** `phone/gates/PlayGates.cs` reads each library's
`.note.android.ident`. A 64-bit library whose note names an NDK older than r27
fails the Release build, by name. A library with no such note is listed and not
failed. The floor is the property `RectoPlayMinNdkMajor` (27): raise it, never
lower it. The build log's "Play gates:" lines now end with each library's NDK.
No existing gate changed.

## Known, and not in this build

- **Nothing here was run on a device.** The notification, the Android
  permission question, the tap, the iPhone alert and the resume re-check were
  built and unit-tested; a real Android phone and a real iPhone have to show
  them. The package bump moves the Kotlin and AndroidX libraries under Firebase
  Messaging, and a class R8 no longer keeps shows only at run time: pair, take a
  push wake and approve on a real Android phone before the build is uploaded.
- **Push needs its credentials.** None is in the repository. Until a host sets
  them, push is off and phones poll every three seconds, as in 1.2.4.
- **One APNs gateway per bootloader.** A development-signed iPhone build and a
  store build cannot both be woken by one bootloader.
- **The failure line** is one per failed send, not one per interval.
- **A terminal QR** needs the `qr` extra where the host verb runs; without it
  the code is typed.
- **The ordinary pairing code is still six digits**, with its wrong-code limit
  and exposure budget unchanged.
