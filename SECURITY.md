# Recto — Security Policy

**Report a vulnerability privately, never in a public issue.** Use GitHub's
private reporting: open this repository's **Security** tab and choose **Report a
vulnerability**. Only Recto's maintainers can see the report. If you cannot use
GitHub, email support@rectophone.com instead.

Recto is maintained by **Recto LLC**.

## What to include

- **Which part:** `recto-core`, the bootloader, or the phone app (Android or
  iOS).
- **Which version:** the release or commit you tested.
- **How to reproduce it:** the steps, what happened, and what you expected.

A report does not need a working exploit.

## Good-faith research

Recto LLC will not take legal action against you, or ask anyone else to, for
research that keeps to these three:

- **Your own ground.** Test a deployment you run yourself, or one whose
  operator has agreed. Never someone else's.
- **Stop at the proof.** Do not read, change or keep anyone else's data beyond
  what shows the issue.
- **Tell us first.** Report privately here and give the fix its time (below)
  before you say anything in public.

This is Recto LLC's promise only. It cannot speak for an operator, an app
store or a network you cross on the way.

## What happens next

- **An acknowledgement within 7 days.**
- **An assessment within 30 days, shown to you before anything is published:**
  a fix, or the reason the behaviour is intended. Some behaviour is a
  deliberate decision listed in [docs/hard-rules.md](docs/hard-rules.md); a
  report that meets one is answered by its rule.
- **The fix.** An issue that lets anyone approve, sign or read a secret without
  the phone owner's own approval goes ahead of all other work and gets a
  release of its own. Any other confirmed issue ships in the next release.
- **Coordinated disclosure:** the advisory is published when the fix ships, and
  it credits you unless you ask otherwise. If 90 days pass from your report
  with no fix, you are free to publish; tell us the date first.

Recto LLC pays no bounty. A report earns credit in the advisory.

## Published advisories

Every advisory is published under this repository's **Security** tab, in
**Advisories**.

## Supported versions

Fixes land on `main` and in the next release of `recto-core` and the phone app.
Earlier releases are not patched.

## Scope

**In scope:** the code in this repository — `recto-core`, the bootloader and
the phone app — and the phone app as Recto LLC publishes it in the app stores.

**Out of scope:**

- **An operator's own deployment** — the host, the configuration, the users.
  That is the operator's to secure, and reports about it go to them.
- **A deliberate decision** listed in [docs/hard-rules.md](docs/hard-rules.md),
  unless you can show the rule itself does not hold.
- **Volume alone:** flooding a service until it stops answering.
- **A scanner's output** with no demonstrated effect.
