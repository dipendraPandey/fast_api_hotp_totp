import pytest
from unittest.mock import patch
from cryptography.hazmat.primitives.twofactor.hotp import HOTP
from app.hazmat_helpers import get_hotp


def test_get_hotp_success():
    key = b"12345678901234567890"
    hotp = get_hotp(key=key, length=6)
    assert isinstance(hotp, HOTP)
    assert hotp._length == 6


def test_get_hotp_value_error_invalid_length():
    key = b"12345678901234567890"
    with pytest.raises(ValueError, match="Length of HOTP has to be between 6 and 8"):
        get_hotp(key=key, length=4)


def test_get_hotp_type_error_raised_as_value_error():
    key = b"12345678901234567890"
    with patch("app.hazmat_helpers.HOTP", side_effect=TypeError("Type error in HOTP creation")):
        with pytest.raises(ValueError, match="Invalid Algorithm."):
            get_hotp(key=key)
