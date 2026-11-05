"""The in-process fuzzer runs on every build (small N, fixed seeds); `python -m devenv.fuzz 20000 <seed>` runs long.
Plus the regressions it found."""
import json

import pytest

from devenv import fuzz
from gate import Reject, load_pack, parse

PACK = load_pack("helpdesk")
U = "d02cbf80-c4a5-4c86-9912-27a5a18fb8cd"


@pytest.mark.parametrize("seed", [1, 2])
def test_fuzz_finds_nothing(tmp_path, seed):
    results = fuzz.run_all(n=600, seed=seed, tmp=str(tmp_path))
    for res in results:
        assert res.get("n_failures", 0) == 0, (res["target"], res.get("failures"))
        assert not res.get("rejected"), res["rejected"]           # no false rejections of known-legitimate requests


@pytest.mark.parametrize("body", [
    {"type": "password", "temporary": 1},          # found by the fuzzer: 1 == True in Python
    {"type": "password", "temporary": 1.0},
    {"type": "password", "temporary": "true"},
])
def test_enum_fields_are_type_exact(body):
    with pytest.raises(Reject):
        parse(PACK, "PUT", f"/admin/realms/corp/users/{U}/reset-password", json.dumps(body).encode())


@pytest.mark.parametrize("email", ["jordan@corp.example\n", "jordan@corp.example\r", "jordan@corp.example\n\n"])
def test_regex_fields_do_not_accept_a_trailing_newline(email):
    """re.match with '$' matches before a trailing newline: a mail-header-injection shape."""
    with pytest.raises(Reject):
        parse(PACK, "PUT", f"/admin/realms/corp/users/{U}", json.dumps({"email": email}).encode())


def test_the_legitimate_forms_still_pass():
    assert parse(PACK, "PUT", f"/admin/realms/corp/users/{U}/reset-password",
                 b'{"type":"password","temporary":true}').name == "reset_password"
    assert parse(PACK, "PUT", f"/admin/realms/corp/users/{U}", b'{"email":"jordan.new@corp.example"}').name \
        == "change_email"
