"""GATE 5 -- the chain WRITER (`recto vault enrol-member`).

WHAT THESE TESTS PROTECT. GATE 5 shipped a chain reader with no producer, so
until this command existed **no vault anywhere held a chain** and the tamper
detection guarded a shape that occurred only in test fixtures. The risk that
creates is specific: a writer added later can quietly produce chains the reader
accepts for the wrong reason, and nobody would notice because the reader was
never wrong about a real one.

So the assertions here are about the JOINT behaviour of writer and reader:

    * a chain the writer produced REPLAYS (the positive control);
    * the passphrase and a device are genuinely required -- one short is refused;
    * a set that holds no passphrase takes one change: the add that seats it;
    * a byte changed on disk afterwards makes the set UNREADABLE, not absent;
    * the writer cannot extend a chain that is already broken;
    * an unparseable file is never mistaken for "no chain yet".

THE POSITIVE CONTROL IS `test_genesis_then_add_then_read_back`. Almost
everything else asserts a refusal, and a command that refused unconditionally
would pass every one of them.
"""

from __future__ import annotations

import base64
import io
import json
import types

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import recto.cli as cli
from recto.bootloader.genesis_chain import ChainError
from recto.bootloader.state import StateStore


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")


def _keypair():
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return key, pub


@pytest.fixture
def vault(tmp_path):
    """(run, state) -- `run` invokes the command and returns (rc, stdout, stderr)."""

    def run(**kwargs):
        args = types.SimpleNamespace(
            state_dir=str(tmp_path), kind=None, pubkey=None,
            algorithm="ed25519", remove=False, genesis=False,
            adopt_existing=False, signature=[], show_challenge=False,
        )
        for k, v in kwargs.items():
            setattr(args, k, v)
        out, err = io.StringIO(), io.StringIO()
        rc = cli._cmd_vault_enrol_member(args, out=out, err=err)
        return rc, out.getvalue(), err.getvalue()

    return run, StateStore(state_dir=tmp_path)


def _challenge(stdout: str) -> bytes:
    """Pull the base64url challenge out of the printed block."""
    for line in stdout.splitlines():
        token = line.strip()
        if len(token) > 40 and " " not in token and not token.endswith(":"):
            return base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    raise AssertionError(f"no challenge found in:\n{stdout}")


def _add(run, kind, pub, *signers):
    """Add one member through the two-step command, signed by `signers`."""
    rc, out, err = run(kind=kind, pubkey=pub.hex(), show_challenge=True)
    if rc != 0:
        return rc, out, err
    c = _challenge(out)
    return run(kind=kind, pubkey=pub.hex(), signature=[_b64u(s.sign(c)) for s in signers])


def _roster(run):
    """The real shape of a vault: the passphrase, then a recovery phone, then a primary phone. Returns
    {kind: (key, pub)}."""
    keys = {k: _keypair() for k in ("passphrase", "recovery-phone", "primary-phone")}
    rc, _, err = run(kind="passphrase", pubkey=keys["passphrase"][1].hex(), genesis=True)
    assert rc == 0, err
    rc, _, err = _add(run, "recovery-phone", keys["recovery-phone"][1], keys["passphrase"][0])
    assert rc == 0, err
    rc, _, err = _add(run, "primary-phone", keys["primary-phone"][1], keys["passphrase"][0], keys["recovery-phone"][0])
    assert rc == 0, err
    return keys


# ---------------------------------------------------------------------------
# THE POSITIVE CONTROL
# ---------------------------------------------------------------------------

def test_genesis_then_add_then_read_back(vault):
    run, state = vault
    phrase, phrase_pub = _keypair()
    _, phone_pub = _keypair()

    rc, _, err = run(kind="passphrase", pubkey=phrase_pub.hex(), genesis=True)
    assert rc == 0, err
    assert sorted(state.list_genesis_members_full()) == ["passphrase"]

    rc, _, err = _add(run, "recovery-phone", phone_pub, phrase)
    assert rc == 0, err

    members = state.list_genesis_members_full()
    assert sorted(members) == ["passphrase", "recovery-phone"]
    assert members["recovery-phone"].pubkey == phone_pub
    assert state.list_unreadable_genesis_members() == {}


def test_the_written_chain_is_what_the_reader_replays(vault):
    """The stored artifact is a chain, not a flat map wearing one."""
    run, state = vault
    _, pub = _keypair()
    run(kind="alpha", pubkey=pub.hex(), genesis=True)

    chain = state.read_genesis_chain()
    assert len(chain) == 1
    assert chain[0]["seq"] == 0
    assert chain[0]["op"] == "add"
    assert chain[0]["prev"] is None
    # Genesis is unsigned BY DEFINITION -- there is no prior set.
    assert chain[0]["signatures"] == []


# ---------------------------------------------------------------------------
# THE THRESHOLD IS REAL (hard rule 14.7)
# ---------------------------------------------------------------------------

def test_one_signature_short_is_refused(vault):
    """Once a device is sealed a change needs the passphrase AND a device. This is the assertion that makes the
    threshold a rule rather than a comment."""
    run, state = vault
    phrase, phrase_pub = _keypair()
    phone, phone_pub = _keypair()
    _, other_pub = _keypair()
    run(kind="passphrase", pubkey=phrase_pub.hex(), genesis=True)
    _add(run, "recovery-phone", phone_pub, phrase)

    for short in ([phrase], [phone]):
        rc, _, err = _add(run, "primary-phone", other_pub, *short)
        assert rc != 0
        assert "hard rule 14.7" in err
        assert sorted(state.list_genesis_members_full()) == ["passphrase", "recovery-phone"], \
            "a refused entry must not have been written"

    rc, _, err = _add(run, "primary-phone", other_pub, phrase, phone)
    assert rc == 0, err
    assert sorted(state.list_genesis_members_full()) == ["passphrase", "primary-phone", "recovery-phone"]


def test_one_member_cannot_sign_twice_for_two(vault):
    """Members satisfied, never signatures accepted."""
    run, _ = vault
    phrase, phrase_pub = _keypair()
    _, phone_pub = _keypair()
    _, other_pub = _keypair()
    run(kind="passphrase", pubkey=phrase_pub.hex(), genesis=True)
    _add(run, "recovery-phone", phone_pub, phrase)

    rc, _, err = _add(run, "primary-phone", other_pub, phrase, phrase)
    assert rc != 0
    assert "no device signature" in err


def test_a_lost_device_is_removed_by_the_passphrase_and_the_other(vault):
    """The reason it is the passphrase and ONE device: a lost phone must be removable by what remains."""
    run, state = vault
    keys = _roster(run)

    _, out, _ = run(kind="recovery-phone", remove=True, show_challenge=True)
    c = _challenge(out)
    rc, _, err = run(kind="recovery-phone", remove=True,
                     signature=[_b64u(keys["passphrase"][0].sign(c)), _b64u(keys["primary-phone"][0].sign(c))])
    assert rc == 0, err
    assert sorted(state.list_genesis_members_full()) == ["passphrase", "primary-phone"]

    # ...and the last device is never removed here (the owner reset's job).
    _, out, _ = run(kind="primary-phone", remove=True, show_challenge=True)
    c = _challenge(out)
    rc, _, err = run(kind="primary-phone", remove=True,
                     signature=[_b64u(keys["passphrase"][0].sign(c)), _b64u(keys["primary-phone"][0].sign(c))])
    assert rc != 0
    assert "last device" in err


def test_the_last_member_cannot_go(vault):
    run, _ = vault
    _, pub = _keypair()
    run(kind="passphrase", pubkey=pub.hex(), genesis=True)
    rc, _, err = run(kind="passphrase", remove=True, show_challenge=True)
    assert rc != 0
    assert "last member" in err


# ---------------------------------------------------------------------------
# A SET WITH NO PASSPHRASE TAKES ONE CHANGE: THE ADD THAT SEATS IT
# ---------------------------------------------------------------------------

def test_a_device_alone_never_changes_the_roster(vault):
    run, state = vault
    phone, phone_pub = _keypair()
    _, other_pub = _keypair()
    run(kind="recovery-phone", pubkey=phone_pub.hex(), genesis=True)

    rc, _, err = run(kind="primary-phone", pubkey=other_pub.hex(), show_challenge=True)
    assert rc != 0
    assert "holds no passphrase" in err
    assert sorted(state.list_genesis_members_full()) == ["recovery-phone"]


def test_the_store_refuses_it_too(vault, tmp_path):
    """The command's refusal is manners; the store is the guard."""
    from recto.bootloader.genesis_chain import build_entry, entry_hash, entries_from_records, signing_bytes

    run, state = vault
    phone, phone_pub = _keypair()
    _, other_pub = _keypair()
    run(kind="recovery-phone", pubkey=phone_pub.hex(), genesis=True)
    tip = entry_hash(entries_from_records(state.read_genesis_chain())[-1])
    msg = signing_bytes(seq=1, op="add", kind="primary-phone", pubkey=other_pub, algorithm="ed25519", prev=tip)
    entry = build_entry(seq=1, op="add", kind="primary-phone", pubkey=other_pub, algorithm="ed25519", prev=tip,
                        signatures=[phone.sign(msg)])
    before = (tmp_path / "genesis_members.json").read_bytes()
    with pytest.raises(ChainError, match="holds no passphrase"):
        state.append_genesis_chain_entry(entry.as_record())
    assert (tmp_path / "genesis_members.json").read_bytes() == before


def test_the_passphrase_is_seated_by_the_set_as_it_stands(vault):
    run, state = vault
    phone, phone_pub = _keypair()
    _, phrase_pub = _keypair()
    run(kind="recovery-phone", pubkey=phone_pub.hex(), genesis=True)

    stranger, _ = _keypair()
    rc, _, err = _add(run, "passphrase", phrase_pub, stranger)
    assert rc != 0
    rc, _, err = _add(run, "passphrase", phrase_pub, phone)
    assert rc == 0, err
    assert sorted(state.list_genesis_members_full()) == ["passphrase", "recovery-phone"]


def test_a_chain_written_before_the_rule_still_reads(vault, tmp_path):
    """An older chain with no passphrase replays exactly as it did: it is read, and only a NEW entry is refused."""
    from recto.bootloader.genesis_chain import build_entry, entry_hash, entries_from_records, signing_bytes

    run, state = vault
    phone, phone_pub = _keypair()
    _, other_pub = _keypair()
    run(kind="recovery-phone", pubkey=phone_pub.hex(), genesis=True)
    tip = entry_hash(entries_from_records(state.read_genesis_chain())[-1])
    msg = signing_bytes(seq=1, op="add", kind="primary-phone", pubkey=other_pub, algorithm="ed25519", prev=tip)
    entry = build_entry(seq=1, op="add", kind="primary-phone", pubkey=other_pub, algorithm="ed25519", prev=tip,
                        signatures=[phone.sign(msg)])
    path = tmp_path / "genesis_members.json"
    body = json.loads(path.read_text(encoding="utf-8"))
    body["chain"].append(entry.as_record())   # as a writer before the rule left it
    path.write_text(json.dumps(body), encoding="utf-8")

    older = StateStore(state_dir=tmp_path)
    assert sorted(older.list_genesis_members_full()) == ["primary-phone", "recovery-phone"]
    assert older.list_unreadable_genesis_members() == {}
    assert older.genesis_chain_state().length == 2


def test_removing_a_non_member_is_refused(vault):
    run, _ = vault
    _, pub = _keypair()
    run(kind="passphrase", pubkey=pub.hex(), genesis=True)
    rc, _, err = run(kind="nobody", remove=True, show_challenge=True)
    assert rc != 0
    assert "not a current member" in err


def test_removal_refuses_a_pubkey_that_disagrees_with_the_chain(vault):
    """A removal names a member by KIND but the entry carries the pubkey. If
    the operator supplies one and it disagrees, they are not looking at the
    vault they think they are -- silently using the chain's value hides that."""
    run, _ = vault
    _roster(run)
    _, other_pub = _keypair()

    rc, _, err = run(kind="recovery-phone", remove=True, pubkey=other_pub.hex(),
                     show_challenge=True)
    assert rc != 0
    assert "does not match" in err


# ---------------------------------------------------------------------------
# TAMPER IS DETECTED, AND READS AS TAMPER
# ---------------------------------------------------------------------------

def test_editing_the_file_makes_the_set_unreadable_not_empty(vault, tmp_path):
    """The whole point of GATE 5. A code guard cannot defend a file from
    someone who has the file -- so the property is DETECTION.

    And the detection must not report as an EMPTY VAULT: told "nothing is
    sealed" mid-recovery, an operator starts over, which is the one action
    that destroys what was still there.
    """
    run, state = vault
    _roster(run)

    path = tmp_path / "genesis_members.json"
    body = json.loads(path.read_text(encoding="utf-8"))
    hexed = body["chain"][1]["pubkey"]
    body["chain"][1]["pubkey"] = ("00" if hexed[:2] != "00" else "11") + hexed[2:]
    path.write_text(json.dumps(body), encoding="utf-8")

    tampered = StateStore(state_dir=tmp_path)
    assert tampered.list_genesis_members_full() == {}
    unreadable = tampered.list_unreadable_genesis_members()
    assert unreadable, "a tampered chain must report a REASON, not silence"
    assert "chain" in " ".join(unreadable).lower() or "<chain>" in unreadable


def test_the_writer_cannot_extend_a_broken_chain(vault, tmp_path):
    """Validating only the appended entry would let a writer put one
    honest-looking entry on the end of a tampered chain."""
    run, state = vault
    _, alpha_pub = _keypair()
    _, beta_pub = _keypair()
    run(kind="alpha", pubkey=alpha_pub.hex(), genesis=True)

    path = tmp_path / "genesis_members.json"
    body = json.loads(path.read_text(encoding="utf-8"))
    body["chain"][0]["kind"] = "swapped"
    body["chain"].append({
        "seq": 1, "op": "add", "kind": "beta", "pubkey": beta_pub.hex(),
        "algorithm": "ed25519", "prev": "0" * 64, "signatures": [],
    })
    path.write_text(json.dumps(body), encoding="utf-8")

    with pytest.raises(ChainError):
        StateStore(state_dir=tmp_path).append_genesis_chain_entry({
            "seq": 2, "op": "add", "kind": "gamma", "pubkey": beta_pub.hex(),
            "algorithm": "ed25519", "prev": "0" * 64, "signatures": [],
        })


def test_an_unparseable_file_is_never_read_as_no_chain(vault, tmp_path):
    """"I cannot read it" and "there is none" are opposite facts. Conflating
    them here would let the writer lay a fresh genesis over a chain it could
    not see -- the worst thing this command could do."""
    run, _ = vault
    _, pub = _keypair()
    (tmp_path / "genesis_members.json").write_text("{ not json", encoding="utf-8")

    rc, _, err = run(kind="alpha", pubkey=pub.hex(), genesis=True)
    assert rc != 0
    assert "cannot be read" in err
    with pytest.raises(ChainError):
        StateStore(state_dir=tmp_path).read_genesis_chain()


# ---------------------------------------------------------------------------
# STARTING A CHAIN, AND THE MIGRATION FROM A PRE-CHAIN VAULT
# ---------------------------------------------------------------------------

def test_entry_zero_must_be_asked_for_explicitly(vault):
    run, _ = vault
    _, pub = _keypair()
    rc, _, err = run(kind="alpha", pubkey=pub.hex())
    assert rc != 0
    assert "--genesis" in err and "--adopt-existing" in err


def test_a_fresh_genesis_over_sealed_flat_members_is_refused(vault):
    """Once a chain exists the flat store is never read again, so this would
    orphan a member that IS sealed -- on the live vault, the one member that
    cannot be re-created."""
    run, state = vault
    _, sealed = _keypair()
    _, other = _keypair()
    state.put_genesis_member("passphrase", sealed, "ed25519")

    rc, _, err = run(kind="alpha", pubkey=other.hex(), genesis=True)
    assert rc != 0
    assert "orphan" in err
    assert "--adopt-existing" in err


def test_adopt_existing_brings_the_sealed_member_into_the_chain(vault):
    run, state = vault
    _, sealed = _keypair()
    state.put_genesis_member("passphrase", sealed, "ed25519")

    rc, out, err = run(kind="passphrase", adopt_existing=True)
    assert rc == 0, err
    members = state.list_genesis_members_full()
    assert sorted(members) == ["passphrase"]
    assert members["passphrase"].pubkey == sealed
    assert len(state.read_genesis_chain()) == 1


def test_adopt_existing_requires_kind_to_name_a_sealed_member(vault):
    """No "there is only one, so they must have meant that one" fallback:
    adoption chooses the root of the entire chain."""
    run, state = vault
    _, sealed = _keypair()
    state.put_genesis_member("passphrase", sealed, "ed25519")

    rc, _, err = run(kind="recovery-phone", adopt_existing=True)
    assert rc != 0
    assert "passphrase" in err
    assert state.read_genesis_chain() == []


def test_adopt_existing_says_which_members_it_is_leaving_behind(vault):
    run, state = vault
    _, one = _keypair()
    _, two = _keypair()
    state.put_genesis_member("passphrase", one, "ed25519")
    state.put_genesis_member("recovery-phone", two, "ed25519")

    rc, out, err = run(kind="passphrase", adopt_existing=True)
    assert rc == 0, err
    assert "recovery-phone" in out, \
        "silently dropping a sealed member is the failure this note prevents"
    assert sorted(state.list_genesis_members_full()) == ["passphrase"]


def test_genesis_flags_are_refused_once_a_chain_exists(vault):
    run, _ = vault
    _, pub = _keypair()
    run(kind="alpha", pubkey=pub.hex(), genesis=True)
    for flags in ({"genesis": True}, {"adopt_existing": True}):
        rc, _, err = run(kind="beta", pubkey=pub.hex(), **flags)
        assert rc != 0
        assert "already exists" in err


def test_entry_zero_cannot_be_a_removal(vault):
    run, _ = vault
    rc, _, err = run(kind="alpha", remove=True, genesis=True)
    assert rc != 0
    assert "no member yet" in err


# ---------------------------------------------------------------------------
# USAGE FAILURES THAT MUST NOT LOOK LIKE SUCCESS
# ---------------------------------------------------------------------------

def test_no_signatures_prints_the_challenge_but_exits_nonzero(vault):
    """Exiting 0 here would let a script "enrol" a member and write nothing."""
    run, state = vault
    alpha, alpha_pub = _keypair()
    _, beta_pub = _keypair()
    run(kind="passphrase", pubkey=alpha_pub.hex(), genesis=True)

    rc, out, err = run(kind="beta", pubkey=beta_pub.hex())
    assert rc != 0
    assert "Bytes to sign" in out, "the operator still needs the challenge"
    assert "nothing was written" in err
    assert sorted(state.list_genesis_members_full()) == ["passphrase"]


def test_show_challenge_writes_nothing(vault):
    run, state = vault
    alpha, alpha_pub = _keypair()
    _, beta_pub = _keypair()
    run(kind="passphrase", pubkey=alpha_pub.hex(), genesis=True)
    before = state.read_genesis_chain()
    rc, out, _ = run(kind="beta", pubkey=beta_pub.hex(), show_challenge=True)
    assert rc == 0
    assert state.read_genesis_chain() == before


def test_adding_without_a_pubkey_is_refused(vault):
    run, _ = vault
    _, pub = _keypair()
    run(kind="passphrase", pubkey=pub.hex(), genesis=True)
    rc, _, err = run(kind="beta")
    assert rc != 0
    assert "adding a member needs --pubkey" in err


def test_a_bad_kind_is_refused(vault):
    run, _ = vault
    _, pub = _keypair()
    rc, _, err = run(kind="not a kind!", pubkey=pub.hex(), genesis=True)
    assert rc != 0
    assert "alphanumeric" in err


def test_a_non_hex_pubkey_is_refused(vault):
    run, _ = vault
    rc, _, err = run(kind="alpha", pubkey="zzzz", genesis=True)
    assert rc != 0
    assert "hex" in err


def test_a_non_base64_signature_is_refused(vault):
    run, state = vault
    _, alpha_pub = _keypair()
    _, beta_pub = _keypair()
    run(kind="passphrase", pubkey=alpha_pub.hex(), genesis=True)
    rc, _, err = run(kind="beta", pubkey=beta_pub.hex(), signature=["!!!!not b64!!!!"])
    assert rc != 0
    assert sorted(state.list_genesis_members_full()) == ["passphrase"]


# ---------------------------------------------------------------------------
# THE DECLARED GAP
# ---------------------------------------------------------------------------

def test_the_file_store_declares_chain_support(tmp_path):
    assert StateStore(state_dir=tmp_path).supports_genesis_chain() is True


def test_a_backend_without_a_chain_says_so_rather_than_pretending():
    """Postgres is the MULTI-INSTANCE production backend and has no chain, so
    the deployment shape that most needs membership-tamper detection is the
    one without it. That is a roadmap entry, and this test is what keeps it
    from becoming a silent one: the base class must DECLARE the absence, not
    return an empty chain that reads as 'no tampering here'.
    """
    from recto.bootloader.state_postgres import PostgresStateStore

    store = object.__new__(PostgresStateStore)  # no connection needed
    assert store.supports_genesis_chain() is False
    with pytest.raises(NotImplementedError):
        store.read_genesis_chain()
    with pytest.raises(NotImplementedError):
        store.append_genesis_chain_entry({})
