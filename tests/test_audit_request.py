from __future__ import annotations

import pytest
from pydantic import ValidationError

from cdp_audit.audit_request import AuditRequest, describe_validation_error


def _form(**overrides: object) -> dict:
    form: dict = {
        "site_name": "London-HQ",
        "seeds": "10.0.0.1, 10.0.0.2",
        "primary_user": "netadmin",
        "primary_pass": "s3cret",
        "answer_user": "",
        "answer_pass": "",
        "jump_host": "",
        "ip_filter": "",
    }
    form.update(overrides)
    return form


def _error(**overrides: object) -> str:
    with pytest.raises(ValidationError) as caught:
        AuditRequest.model_validate(_form(**overrides))
    return describe_validation_error(caught.value)


def test_valid_form_is_normalised() -> None:
    request = AuditRequest.model_validate(
        _form(site_name="  London-HQ  ", jump_host=" bastion.example.test ")
    )

    assert request.site_name == "London-HQ"
    assert request.seeds == ["10.0.0.1", "10.0.0.2"]
    assert request.jump_host == "bastion.example.test"
    assert request.answer_user is None and request.answer_pass is None
    assert not request.ip_filter
    assert not request.has_fallback


def test_password_is_masked_in_repr() -> None:
    request = AuditRequest.model_validate(_form(primary_pass="hunter2"))

    assert "hunter2" not in repr(request)
    assert request.primary_pass.get_secret_value() == "hunter2"


def test_password_whitespace_is_preserved() -> None:
    request = AuditRequest.model_validate(_form(primary_pass=" pass "))

    assert request.primary_pass.get_secret_value() == " pass "


def test_seeds_accept_pasted_lists() -> None:
    request = AuditRequest.model_validate(
        _form(seeds="10.0.0.1;10.0.0.2  core-sw01\t2001:DB8::1")
    )

    assert request.seeds == ["10.0.0.1", "10.0.0.2", "core-sw01", "2001:db8::1"]


@pytest.mark.parametrize(
    "overrides,expected",
    [
        ({"site_name": "   "}, "Site name: is required"),
        ({"site_name": "x" * 51}, "Site name: must be 50"),
        ({"seeds": " , "}, "Seed devices: at least one"),
        ({"seeds": ",".join(f"10.0.{i // 250}.{i % 250 + 1}" for i in range(501))},
         "max 500"),
        ({"seeds": "10.0.0.1, 0.0.0.0"}, "unspecified"),
        ({"seeds": "10.0.0.1, bad!host"}, "not a valid IP address or hostname"),
        ({"primary_user": ""}, "Primary username: is required"),
        ({"primary_pass": ""}, "Primary password: is required"),
        ({"answer_user": "answer"}, "both a fallback username and password"),
        ({"jump_host": "admin@bastion"}, "Jump host:"),
        ({"ip_filter": "10.0.0.9-10.0.0.1"}, "IP filter:"),
    ],
)
def test_invalid_form_values_are_explained(overrides: dict, expected: str) -> None:
    assert expected in _error(**overrides)


def test_fallback_pair_is_accepted() -> None:
    request = AuditRequest.model_validate(
        _form(answer_user="answer", answer_pass="fallback")
    )

    assert request.has_fallback
    assert request.answer_pass is not None
    assert request.answer_pass.get_secret_value() == "fallback"


def test_ip_filter_is_parsed() -> None:
    request = AuditRequest.model_validate(_form(ip_filter="10.0.0.0/24"))

    assert "10.0.0.7" in request.ip_filter
    assert "10.0.1.7" not in request.ip_filter
