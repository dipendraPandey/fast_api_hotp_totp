import pytest
from unittest.mock import patch
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from app.hazmat_helpers import get_totp


def test_get_totp_success():
    key = b"1234567890123456"
    totp = get_totp(key=key, length=6, time_step=30)
    assert isinstance(totp, TOTP)


def test_get_totp_invalid_key_value_error():
    key = b"short"
    with pytest.raises(ValueError, match="Invalid length or Invalid key."):
        get_totp(key=key)


def test_get_totp_invalid_length_value_error():
    key = b"1234567890123456"
    with pytest.raises(ValueError, match="Invalid length or Invalid key."):
        get_totp(key=key, length=4)


def test_get_totp_type_error():
    key = b"1234567890123456"
    with patch("app.hazmat_helpers.TOTP", side_effect=TypeError("Mocked TypeError")):
        with pytest.raises(ValueError, match="Invalid Algorithm."):
            get_totp(key=key)
