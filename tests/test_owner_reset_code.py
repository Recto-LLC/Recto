"""The owner reset's code (hard rule 14.7): sixteen characters by default, never burned by wrong guesses; six digits
behind an explicit switch for one release, burned as before. The form is inside the arm the passphrase signs."""

from __future__ import annotations

import io
import json
import logging
import time
from pathlib import Path

import pytest

pytest.importorskip("cryptography", reason="recto[v0_4] not installed")

from recto import cli  # noqa: E402
from recto import top_plane_cli as tp  # noqa: E402
from recto.bootloader import device_codes, top_plane  # noqa: E402
from recto.bootloader.state import StateStore  # noqa: E402
from tests.test_bootloader_slots import Phone, _http  # noqa: E402
from tests.test_top_plane_e2e import _arm, _host, plane  # noqa: E402, F401 - `plane` is the fixture
from tests.test_top_plane_faults import _edit_reset, _leg, _post_arm, _sign_pp, _start_reset  # noqa: E402

VECTORS = json.loads((Path(__file__).parent / "reset_code_vectors.json").read_text(encoding="utf-8"))
PUBLIC = "CF-Connecting-IP"


def _redeem(ctx, code: str, *, client: str | None = None):
    from urllib.parse import quote
    headers = {PUBLIC: client} if client else None
    return _http("GET", f"{ctx['base_url']}/v0.4/registration_challenge?code={quote(code, safe='')}", headers=headers)


def _armed(ctx, **kw) -> tuple[str, dict]:
    iid = _start_reset(ctx)
    time.sleep(2.2)
    return iid, _arm(ctx, iid, **kw)


# --- the form, with no server ---------------------------------------------------------------------------------------

class TestTheCodesForm:

    @pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda v: ascii(v["input"]))
    def test_the_shared_vectors(self, vector) -> None:
        """The phone app runs the same file: both sides read a typed code the same way."""
        shaped = top_plane.normalize_reset_code(vector["input"])
        if vector["form"] is None:
            assert shaped is None
        else:
            assert shaped == (vector["form"], vector["canonical"])
            assert top_plane.display_reset_code(shaped[1]) == vector["display"]

    def test_the_alphabet_is_the_test_device_codes(self) -> None:
        assert VECTORS["alphabet"] == device_codes.ALPHABET and len(device_codes.ALPHABET) == 32
        assert not set("ILOU") & set(device_codes.ALPHABET)

    def test_a_long_code_is_eighty_bits_from_the_alphabet(self) -> None:
        codes = {top_plane.mint_reset_code("long") for _ in range(200)}
        assert len(codes) == 200
        assert all(len(c) == 16 and set(c) <= set(device_codes.ALPHABET) for c in codes)
        assert 32 ** top_plane.RESET_CODE_LONG_LENGTH == 2 ** 80
        # Every character of the alphabet turns up: no position is stuck.
        assert set("".join(codes)) == set(device_codes.ALPHABET)

    def test_six_digits_are_six_digits(self) -> None:
        assert all(len(c) == 6 and c.isdigit() and c.isascii()
                   for c in (top_plane.mint_reset_code("digits") for _ in range(50)))

    def test_no_other_form_is_minted(self) -> None:
        with pytest.raises(ValueError):
            top_plane.mint_reset_code("words")

    def test_an_arm_that_names_no_form_is_digits(self) -> None:
        assert top_plane.reset_code_form({"intent_id": "x"}) == "digits"
        assert top_plane.reset_code_form({"code_form": "long"}) == "long"
        for bad in ("LONG", "", None, 16, ["long"], "words"):
            with pytest.raises(ValueError):
                top_plane.reset_code_form({"code_form": bad})

    def test_the_form_is_inside_what_the_passphrase_signs(self) -> None:
        arm = dict(_leg(), intent_id="reset-x", slot="primary")
        assert top_plane.reset_arm_digest({**arm, "code_form": "long"}) != top_plane.reset_arm_digest(
            {**arm, "code_form": "digits"})
        assert top_plane.reset_arm_digest({**arm, "code_form": "digits"}) != top_plane.reset_arm_digest(arm)

    def test_test_device_codes_are_read_as_before(self) -> None:
        assert device_codes.normalize("abcde-fghjk") == "ABCDEFGHJK"
        assert device_codes.normalize("ABCDEFGHJKMNPQRS") is None
        assert device_codes.normalize("ABCDEFGHJKMNPQRS", 16) == "ABCDEFGHJKMNPQRS"


# --- the long code at the pairing door ------------------------------------------------------------------------------

class TestTheLongCode:

    def test_the_default_arm_is_the_long_form(self, plane) -> None:
        iid, armed = _armed(plane)
        assert armed["code_form"] == "long"
        shown = armed["code"]
        assert len(shown) == 19 and shown.count("-") == 3, "shown in four groups of four"
        assert top_plane.normalize_reset_code(shown) == ("long", shown.replace("-", ""))
        rec = plane["state"].get_top_plane_record(iid)
        assert rec["code_form"] == "long" and rec["state"] == "armed"

    def test_it_redeems_typed_in_lower_case_with_dashes_and_spaces(self, plane) -> None:
        iid, armed = _armed(plane)
        canonical = armed["code"].replace("-", "")
        # As a person might type it: lower case, a space for a dash, and the letters that look like 1 and 0.
        typed = " ".join(canonical[i:i + 4] for i in range(0, 16, 4)).lower().replace("1", "l").replace("0", "o")
        status, chal = _redeem(plane, f" {typed}- ")
        assert status == 200 and chal["challenge_b64u"].startswith(f"recto-reset-v1:{iid}:"), chal

    def test_it_redeems_in_its_canonical_form_and_only_once(self, plane) -> None:
        _, armed = _armed(plane)
        canonical = armed["code"].replace("-", "")
        status, chal = _redeem(plane, canonical)
        assert status == 200, chal
        # The same code again, however it is spelled, is told it was used - and opens nothing.
        for again in (canonical, armed["code"], canonical.lower()):
            status, body = _redeem(plane, again)
            assert status != 200 and "already used" in json.dumps(body), body

    def test_wrong_guesses_never_burn_it(self, plane) -> None:
        """Fifty wrong codes over the public edge, in both shapes, from many clients: the operator's code still opens."""
        iid, armed = _armed(plane)
        canonical = armed["code"].replace("-", "")
        for i in range(25):
            client = f"198.51.100.{i + 1}"
            wrong_long = top_plane.mint_reset_code("long")
            assert wrong_long != canonical
            assert _redeem(plane, wrong_long, client=client)[0] != 200
            assert _redeem(plane, f"{i:06d}", client=client)[0] != 200
        rec = plane["state"].get_top_plane_record(iid)
        assert rec["code_hash"] and int(rec.get("code_attempts", 0)) == 0, "nothing was counted against it"
        status, chal = _redeem(plane, armed["code"], client="203.0.113.9")
        assert status == 200 and chal["challenge_b64u"].startswith("recto-reset-v1:"), chal

    def test_a_wrong_long_code_still_counts_against_its_own_client(self, plane) -> None:
        _, armed = _armed(plane)
        client = "198.51.100.77"
        for _ in range(5):
            status, body = _redeem(plane, top_plane.mint_reset_code("long"), client=client)
            assert status != 200 and body.get("error") != "too_many_wrong_codes", body
        status, body = _redeem(plane, top_plane.mint_reset_code("long"), client=client)
        assert status == 429 and body["error"] == "too_many_wrong_codes", body
        # That client is held off even with the right code; another network is not.
        assert _redeem(plane, armed["code"], client=client)[0] == 429
        assert _redeem(plane, armed["code"], client="203.0.113.10")[0] == 200

    def test_it_is_refused_after_its_window(self, plane) -> None:
        iid, armed = _armed(plane)
        _edit_reset(plane["state"], iid, code_expires_at=int(time.time()) - 1)
        status, body = _redeem(plane, armed["code"])
        assert status != 200 and "challenge_b64u" not in body, body
        assert plane["state"].get_top_plane_record(iid).get("challenge_mac") is None

    def test_six_digits_never_open_a_long_arm(self, plane) -> None:
        """A reset armed long is matched only against long codes: no six-digit guess can be its code."""
        iid, armed = _armed(plane)
        rec = plane["state"].get_top_plane_record(iid)
        from recto.bootloader.server import BootloaderHandler
        handler = BootloaderHandler.__new__(BootloaderHandler)
        digits = "123456"
        _edit_reset(plane["state"], iid, code_hash=handler._code_mac(digits))    # as if its MAC were a digit code's
        assert _redeem(plane, digits)[0] != 200
        _edit_reset(plane["state"], iid, code_hash=rec["code_hash"])
        assert _redeem(plane, armed["code"])[0] == 200

    def test_neither_the_record_nor_the_log_holds_the_code(self, plane, caplog) -> None:
        with caplog.at_level(logging.DEBUG):
            iid, armed = _armed(plane)
            canonical = armed["code"].replace("-", "")
            on_disk = (Path(plane["tmp"]) / "top_plane.json").read_text(encoding="utf-8")
            assert _redeem(plane, top_plane.mint_reset_code("long"), client="198.51.100.5")[0] != 200
            assert _redeem(plane, armed["code"])[0] == 200
        after = (Path(plane["tmp"]) / "top_plane.json").read_text(encoding="utf-8")
        logged = "\n".join(r.getMessage() for r in caplog.records)
        for where in (on_disk, after, logged):
            for spelled in (canonical, armed["code"], canonical.lower()):
                assert spelled not in where
        assert f"owner reset {iid} ARMED" in logged

    def test_a_store_reads_a_record_that_names_its_form(self, plane) -> None:
        iid, _ = _armed(plane)
        again = StateStore(state_dir=Path(plane["tmp"]))
        assert again.get_top_plane_record(iid)["code_form"] == "long"


# --- the form is the signer's ---------------------------------------------------------------------------------------

class TestTheFormIsSigned:

    def test_a_form_changed_after_signing_is_refused(self, plane) -> None:
        iid = _start_reset(plane)
        time.sleep(2.2)
        arm = dict(_leg(nonce="f" * 24), intent_id=iid, slot="primary", code_form="long")
        swapped = dict(arm, code_form="digits")
        status, body = _http("POST", f"{plane['base_url']}/v0.4/owner/reset/arm", {
            "arm": swapped, "passphrase_signature_b64u": _sign_pp(top_plane.reset_arm_digest(arm))})
        assert status == 403 and body["error"] == "top_plane_passphrase_invalid" and "code" not in body, body
        assert plane["state"].get_top_plane_record(iid)["state"] == "waiting"

    def test_an_arm_that_names_no_form_mints_six_digits(self, plane) -> None:
        """A host one release older signs an arm with no code_form: it gets the code it can show."""
        iid = _start_reset(plane)
        time.sleep(2.2)
        status, body = _post_arm(plane, dict(_leg(nonce="g" * 24), intent_id=iid, slot="primary"))
        assert status == 200 and body["code_form"] == "digits", body
        assert len(body["code"]) == 6 and body["code"].isdigit()
        assert plane["state"].get_top_plane_record(iid)["code_form"] == "digits"

    def test_an_unknown_form_arms_nothing(self, plane) -> None:
        iid = _start_reset(plane)
        time.sleep(2.2)
        for form in ("words", "", None, 16):
            arm = dict(_leg(nonce="h" * 24), intent_id=iid, slot="primary", code_form=form)
            status, body = _post_arm(plane, arm)
            assert status == 400 and body["error"] == "owner_reset_invalid" and "code" not in body, body
        rec = plane["state"].get_top_plane_record(iid)
        assert rec["state"] == "waiting" and not rec.get("code_hash")
        # The refused arm spent nothing: the same nonce still arms with a form the bootloader mints.
        status, body = _post_arm(plane, dict(_leg(nonce="h" * 24), intent_id=iid, slot="primary", code_form="long"))
        assert status == 200 and body["code_form"] == "long" and len(body["code"]) == 16, body

    def test_a_long_code_never_opens_a_six_digit_arm_and_the_reverse(self, plane) -> None:
        iid, armed = _armed(plane, six_digits=True)
        assert armed["code_form"] == "digits" and plane["state"].get_top_plane_record(iid)["code_form"] == "digits"
        assert _redeem(plane, top_plane.mint_reset_code("long"))[0] != 200
        assert _redeem(plane, armed["code"])[0] == 200


# --- six digits, kept for one release -------------------------------------------------------------------------------

class TestSixDigitsStillBurn:

    def test_five_public_wrong_codes_burn_a_six_digit_arm(self, plane) -> None:
        iid, armed = _armed(plane, six_digits=True)
        for i in range(5):
            wrong = f"{(int(armed['code']) + 1 + i) % 1000000:06d}"
            _redeem(plane, wrong, client=f"198.51.100.{i + 1}")
        rec = plane["state"].get_top_plane_record(iid)
        assert rec["code_hash"] is None and int(rec["code_attempts"]) == 5
        assert _redeem(plane, armed["code"])[0] != 200

    def test_wrong_long_codes_count_against_a_six_digit_arm_too(self, plane) -> None:
        """Any public code that opens nothing counts against a six-digit arm, whatever its shape."""
        iid, armed = _armed(plane, six_digits=True)
        for i in range(5):
            _redeem(plane, top_plane.mint_reset_code("long"), client=f"198.51.100.{i + 1}")
        assert plane["state"].get_top_plane_record(iid)["code_hash"] is None
        assert _redeem(plane, armed["code"])[0] != 200


# --- the host's terminal --------------------------------------------------------------------------------------------

class TestTheHostsTerminal:

    def test_the_code_is_shown_once_grouped_and_not_inside_the_answer(self, plane) -> None:
        iid = _start_reset(plane)
        time.sleep(2.2)
        rc, out, err = _host(tp.reset_arm, plane, arm=iid, slot="primary", phone_url="https://bootloader.example.com")
        assert rc == 0, err
        lines = [line.strip() for line in out.splitlines()]
        shown = [line for line in lines if line.startswith("Reset code:")]
        assert len(shown) == 1
        code = shown[0].split(":", 1)[1].strip()
        answer = json.loads(next(line for line in lines if line.startswith("{")))
        assert "code" not in answer and answer["code_form"] == "long"
        assert out.count(code) == 1 and code.replace("-", "") not in out.replace(code, "")
        assert "sixteen characters" in out and "wrong codes never burn it" in out
        assert _redeem(plane, code)[0] == 200

    def test_six_digits_is_said_before_it_is_signed(self, plane) -> None:
        iid = _start_reset(plane)
        time.sleep(2.2)
        rc, out, err = _host(tp.reset_arm, plane, arm=iid, slot="primary", six_digits=True)
        assert rc == 0, err
        assert "SIX DIGITS" in out and out.index("SIX DIGITS") < out.index("Reset code:")

    def test_no_qr_for_a_loopback_address(self, plane) -> None:
        iid = _start_reset(plane)
        time.sleep(2.2)
        rc, out, err = _host(tp.reset_arm, plane, arm=iid, slot="primary")
        assert rc == 0, err
        assert "No QR: name the address the phone reaches this bootloader at with --phone-url." in out

    def test_the_qr_is_the_pairing_link(self, monkeypatch) -> None:
        pytest.importorskip("qrcode")
        from recto.qr.pair import build_bootloader_pair_url
        seen: list[str] = []
        real = tp._terminal_qr
        monkeypatch.setattr(tp, "_terminal_qr", lambda text: seen.append(text) or real(text))
        out = io.StringIO()
        args = type("A", (), {"phone_url": "https://bootloader.example.com/"})()
        tp._show_reset_code(args, "http://127.0.0.1:8765", "ABCDEFGHJKMNPQRS", "long", out=out)
        assert seen == [build_bootloader_pair_url("ABCDEFGHJKMNPQRS", "https://bootloader.example.com")]
        assert seen[0] == ("recto://pair?code=ABCDEFGHJKMNPQRS&bootloader=https%3A%2F%2Fbootloader.example.com"
                           "&kind=bootloader")
        assert "Reset code: ABCD-EFGH-JKMN-PQRS" in out.getvalue() and len(out.getvalue().splitlines()) > 10

    def test_without_the_qr_extra_the_code_is_still_shown(self, monkeypatch) -> None:
        monkeypatch.setattr(tp, "_terminal_qr", lambda text: None)
        out = io.StringIO()
        args = type("A", (), {"phone_url": "https://bootloader.example.com"})()
        tp._show_reset_code(args, "http://127.0.0.1:8765", "ABCDEFGHJKMNPQRS", "long", out=out)
        assert "Reset code: ABCD-EFGH-JKMN-PQRS" in out.getvalue() and "pip install recto[qr]" in out.getvalue()

    def test_an_older_bootloaders_six_digits_are_named(self) -> None:
        out = io.StringIO()
        tp._show_reset_code(object(), "http://127.0.0.1:8765", "482915", "long", out=out)
        assert "Reset code: 482915" in out.getvalue() and "mints six digits only" in out.getvalue()

    @pytest.mark.parametrize("base,reachable", [
        ("http://127.0.0.1:8765", False), ("http://localhost:8765", False), ("http://[::1]:8765", False),
        ("https://bootloader.example.com", True), ("http://10.0.0.5:8765", True),
    ])
    def test_a_loopback_address_is_not_one_a_phone_reaches(self, base, reachable) -> None:
        assert (tp._reachable(base) is not None) is reachable

    @pytest.mark.parametrize("extra", [["--six-digits"], ["--phone-url", "https://bootloader.example.com"]])
    def test_the_arm_switches_go_with_arm(self, extra) -> None:
        out, err = io.StringIO(), io.StringIO()
        rc = cli.main(["bootloader", "owner-reset", "--start", "--slot", "primary", *extra], stdout=out, stderr=err)
        assert rc == 2 and "go with --arm" in err.getvalue()


# --- the pairing link ------------------------------------------------------------------------------------------------

class TestThePairingLink:

    def test_a_reset_code_rides_the_bootloader_link(self) -> None:
        from recto.qr.pair import build_bootloader_pair_url
        assert build_bootloader_pair_url("ABCDEFGHJKMNPQRS", "https://bootloader.example.com") == (
            "recto://pair?code=ABCDEFGHJKMNPQRS&bootloader=https%3A%2F%2Fbootloader.example.com&kind=bootloader")
        assert "code=314159&" in build_bootloader_pair_url("314159", "https://bootloader.example.com")

    @pytest.mark.parametrize("code", [
        "1234567", "12345", "ABCDEFGHJKMNPQR", "ABCDEFGHJKMNPQRST", "ABCDEFGHJKMNPQRU", "ABCDEFGHJKMNPQRI",
        "ABCD-EFGH-JKMN-PQRS", "abcdefghjkmnpqrs", "ABCDEFGHJKMNPQRS"+chr(10),
    ])
    def test_the_link_carries_the_canonical_form_only_and_never_repeats_a_refused_code(self, code) -> None:
        from recto.qr.pair import build_bootloader_pair_url
        with pytest.raises(ValueError) as caught:
            build_bootloader_pair_url(code, "https://bootloader.example.com")
        assert code.strip() not in str(caught.value)

    def test_a_service_link_never_carries_a_reset_code(self) -> None:
        from recto.qr.pair import build_service_pair_url
        with pytest.raises(ValueError):
            build_service_pair_url("ABCDEFGHJKMNPQRS")

    def test_every_minted_code_fits_the_link(self) -> None:
        from recto.qr.pair import build_bootloader_pair_url
        for _ in range(100):
            build_bootloader_pair_url(top_plane.mint_reset_code("long"), "https://bootloader.example.com")
            build_bootloader_pair_url(top_plane.mint_reset_code("digits"), "https://bootloader.example.com")
