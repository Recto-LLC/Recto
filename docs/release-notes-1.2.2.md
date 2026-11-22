# Recto Agentic 1.2.2 (build 20)

The phone app. It follows 1.2.1 (build 19) on both stores. No protocol
change and no re-pair: a phone paired on 1.2.1 keeps its pairing, its keys
and its recovery phrase.

This file is not a published page. The site publishes only the pages its
allowlist names (`docs/_config.yml`).

---

## What changed for someone using the app

**A profile card is checked before the master key signs it.** The phone reads
the signing input back against the card it is showing: it must be the
bootloader's canonical JSON of exactly that card's fields, naming the card's
own ids, request and time and this phone's own master key, and its SHA-256
must be the card's hash. Anything else is refused by name and nothing is
signed.

**A recovery phrase this phone once held is never silently replaced.** When a
phrase that was provisioned reads empty, pairing a service is refused by name
and offers a restore in Settings or an explicit new phrase. A sign, an address
shown on a card and a revoke read the phrase and never create one.

**Android: memory no longer grows without bound while the app sits open and
polls.** The platform's HTTP handler makes a new set of TLS objects for every
request and leaves their release to the collector, so an idle app filled its
Java heap. The app now runs one collection after every 20th request and
releases the platform objects it signs with as soon as each signing ends: the
key handle, the signature, the key store and its entry and, added last, the
biometric prompt, its crypto object, its info and the info's builder.

**Android: a biometric prompt that cannot be shown says so.** When the app
has left the screen the system returns from the prompt call without showing a
prompt and without calling back, and the app waited on that callback for
ever, its "Awaiting biometric approval" line never ending. The app now checks
first and answers *"The biometric prompt could not be shown because Recto is
not on screen. Open Recto and try again."* A prompt that fails to start is
answered the same way, as a refusal, never as a crash.

**Android: one biometric prompt at a time.** The prompt library keeps one
callback for the whole screen and returns without showing when a prompt is
already up, so a second signing started under a showing prompt took over its
callback: the first was never answered and the second was handed the first
one's touch. A second signing is now refused by name - *"Another approval is
waiting for your biometric. Finish or cancel it, then try again."* - until the
first prompt has ended. If the screen the prompt was shown on is closed under
it, the waiting signing is answered with a refusal and the next one is let
in; before, nothing would have answered it. A screen that is only rebuilt
under the prompt - a change of language, font size or keyboard - is followed,
and the prompt goes on as the one prompt; a rebuild that has produced no new
screen after ten seconds counts as closed.

**Android: a biometric prompt has three minutes.** Every way a prompt ends
rests on its ending reaching the app, and when the screen is rebuilt under a
prompt the app does not restore the prompt's own part of that screen, so its
ending may never come. The prompt now says *"Approve within 3 minutes."*
Three minutes after a prompt is shown, the signing is
ended whatever the prompt is doing: the caller is told *"The approval was not
answered in time. Nothing was signed."*, the prompt is asked to close, and the
next approval is let in a moment later, once the old prompt has had time to
close. The phone can no longer be left refusing every approval until the app
is closed. A touch that arrives carrying another prompt's signing object signs
nothing and says so: *"This approval's touch belonged to another prompt.
Nothing was signed."*

The key service can also close
the prompt of a signing its caller cancels; no caller in this release
cancels one, so that path is there for callers that do.

**A refused pairing leaves no certificate anchor behind.** A bootloader's
certificate became the phone's anchor for that host as soon as the register
call answered. A pairing refused a moment later - the poll key not echoed, an
identity that does not verify, a state that could not be saved - still left
it set until the app closed, so a self-signed host stayed accepted. The anchor
is now set once, after the pairing is confirmed and saved.

**A release desktop build cannot pair.** The software key service compiles
into DEBUG Windows and Mac Catalyst builds only; a release build of those
targets refuses every key act by name before it contacts the bootloader.

## What changed for someone running a bootloader

**The phone tries a failed read signature once more, and says why a read went
unsigned.** The phone's reads (`/v0.4/pending`, `/v0.4/manage/phones`,
`/v0.4/manage/push_token`) and its two denials are signed by the delegated
poll key. A signing that failed sent the read bare, silently. It is now tried
once more, at once, with a new timestamp. A read is never allowed to raise a
biometric prompt: a poll key the key store reports as gated is refused before
any prompt is made, on Android by reading the key and on iOS by using it with
interaction disallowed. A key store that could not describe the key just then
is an ordinary failure, tried again like any other. When a read still goes bare the
phone logs one line and keeps one entry under Settings, Recent errors:

| Reason | Meaning |
|---|---|
| `no_poll_key` | The pairing recorded no poll key. Pair again. |
| `poll_key_gated` | The key store says the poll key needs a biometric. It is refused without a prompt and not retried. Pair again. |
| `device_locked` | The device is locked and its key store will not use the poll key until it is unlocked (iOS). A normal state: logged for information, not kept in Settings, not retried. |
| `not_paired` | There is no pairing record. A normal state: logged for information, not kept in Settings. |
| `pairing_unreadable` | The pairing record could not be read. |
| `sign_failed` | The key store answered both attempts with a failure. |
| `sign_threw` | The key store threw on the last attempt. |

The line names the route from a fixed list and the failure's kind (an error
code or an exception's type name). It never carries a phone id, a request id,
a key, a signature or an exception's text. It is written when the reason
changes, not on every poll, and the first signed read after it is logged too.

This is the evidence `signed_poll_mode` waits on. Leave the bootloader at
`advisory` until the phones that poll it are on this build and its own
verdicts read `signed`; then `required` refuses only a phone that has a
reason to show.

## What changed in the build

**The Android Release build runs the Play gates on its own package.** After
the package is signed the build reads it and fails on any miss
(`phone/gates/PlayGates.cs`, wired at the end of `Recto.csproj`):

- the DEX sum - every `.dex` in the package, uncompressed - is under
  10,000,000 bytes;
- every 64-bit native library's loadable segments are aligned to 16 KB, read
  from each `.so`'s ELF program headers; a library that cannot be read fails
  too, and a 32-bit library is listed and not judged;
- a bundle carries its R8 mapping.

The package it reads is the one that build made: the signed package of the
format the build produces, refused when it is missing or older than the app
assembly the build compiled.

The build log lists the sum and every library with its alignment, on lines
that begin `Play gates:`. A Release build whose log has no such line did not
run them. No property skips the gates.

**Two files are written beside the package:**

- `mapping.txt`, R8's mapping, which is also carried inside the bundle, where
  Play reads it;
- `native-debug-symbols.zip`, the native libraries that still carry a symbol
  table, one folder per ABI - the layout Google documents for a symbols zip
  made by hand. Most of the runtime's libraries ship stripped and have no
  symbols to give; the log names the ones included. No upload has yet
  confirmed that Play accepts this zip, so treat it as a candidate.

**DataStore's native library is a direct reference.**
`libdatastore_shared_counter.so` arrives through Firebase Messaging. Its
binding is now named in `Recto.csproj` and versioned in
`Directory.Packages.props`, so the version is a choice and the gate reads the
result. The library build 19 shipped was already aligned for 16 KB pages, and
this build ships the same one: it changes who chooses it, not its alignment.

**iOS declares its export-compliance answer.**
`ITSAppUsesNonExemptEncryption` is `false` in `Info.plist`, so an upload
carries the answer and App Store Connect does not ask it per build.

**The shared assembly opens its internals to no other assembly.** The
`InternalsVisibleTo` line added with the memory fix is gone; the one type the
tests needed is public.

## Removed

**The multi-witness QR.** `recto/qr/multi_witness.py`,
`QR/QrMultiWitness.cs`, their `Witness` and `MultiWitnessContract` types, the
encoder entry points that took them and their tests. Nothing outside their
own tests called them. `recto.qr` no longer exports
`create_multi_witness_contract`, `add_witness_signature`,
`canonical_signing_input_for_witness`, `encode_multi_witness_qr`,
`MultiWitnessContract` or `Witness`. The single-payload QR (`qr_encode_jws`,
`qr_encode_payload`, `QRPayloadV1`) and the pairing QR are unchanged.

## Known, and not in this build

- **The bootloader answers HTTP/1.0**, so every poll is a new connection and
  a new TLS handshake. Moving its handler to HTTP/1.1 keep-alive is bootloader
  work: every answer must carry its length, an idle connection must time out,
  and a test must hold one connection across two requests.
- **The phone polls every three seconds** whether or not a push can wake it.
  A longer idle interval wants push delivery measured on both platforms first.
- **The mock bootloader under `phone/dev-tools` cannot pair this app.** It
  does not record or echo a poll key, which the app requires of a
  registration. Use a real bootloader on a development host.
- **The memory change is measured on Android only.** iOS is unmeasured.
