from unittest.mock import MagicMock, patch
import pytest
from cryptography.hazmat.primitives.twofactor import InvalidToken
from app.hazmat_helpers import (
    HOTPBuilder,
    TOTPBuilder,
    KeyBuilder,
    get_hotp,
    get_totp,
    generate_random_character,
)


def test_hotp_builder_verify_success():
    key = b"12345678901234567890"
    builder = HOTPBuilder(key=key, counter=1)
    # Generate hotp using builder
    hotp_token, counter = builder.generate()
    assert counter > 0
    # verify should return True for the generated token
    assert builder.verify(hotp_token) is True


def test_hotp_builder_verify_failure():
    key = b"12345678901234567890"
    builder = HOTPBuilder(key=key, counter=1)
    # Token with wrong OTP digits
    invalid_hotp = "X999999"
    assert builder.verify(invalid_hotp) is False


def test_hotp_builder_verify_counter_zero():
    key = b"12345678901234567890"
    builder = HOTPBuilder(key=key, counter=0)
    with pytest.raises(ValueError, match="Invalid counter key."):
        builder.verify("A123456")


def test_hotp_builder_verify_raises_invalid_token():
    key = b"12345678901234567890"
    builder = HOTPBuilder(key=key, counter=1)
    with patch.object(builder.hotp, "generate", side_effect=InvalidToken()):
        with pytest.raises(InvalidToken):
            builder.verify("A123456")


def test_hotp_builder_generate_and_get_key():
    key = b"12345678901234567890"
    builder = HOTPBuilder(key=key)
    hotp_token, counter = builder.generate()
    assert isinstance(hotp_token, str)
    assert len(hotp_token) == 7  # 1 prefix char + 6 digits
    assert builder.counter == counter

    # Test get_key
    builder.key = None
    retrieved_key = builder.get_key()
    assert retrieved_key is not None
