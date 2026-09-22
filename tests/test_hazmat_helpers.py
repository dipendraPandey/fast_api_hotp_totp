import pytest
import os
import time
from unittest.mock import patch
from string import ascii_uppercase
from cryptography.hazmat.primitives.twofactor.hotp import HOTP
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from cryptography.hazmat.primitives.twofactor import InvalidToken
from hypothesis import given, strategies as st

from app.hazmat_helpers import (
    generate_random_character,
    get_hotp,
    get_totp,
    verify_totp,
    HOTPBuilder,
    TOTPBuilder,
    KeyBuilder,
)


def test_generate_random_character():
    character, code = generate_random_character()
    assert isinstance(character, str)
    assert len(character) == 1
    assert character in ascii_uppercase
    assert code == ord(character)


def test_get_hotp_valid():
    key = os.urandom(32)
    hotp = get_hotp(key=key, length=6)
    assert isinstance(hotp, HOTP)


def test_get_hotp_invalid_key_value_error():
    # Key too short for SHA512 HOTP
    short_key = b"short"
    with pytest.raises(ValueError):
        get_hotp(key=short_key)


def test_get_hotp_type_error_conversion():
    # Passing an invalid type (e.g., int) should trigger TypeError in cryptography library and raise ValueError("Invalid Algorithm.")
    with pytest.raises(ValueError, match="Invalid Algorithm."):
        get_hotp(key=12345)


def test_get_totp_valid():
    key = os.urandom(32)
    totp = get_totp(key=key, length=6, time_step=30)
    assert isinstance(totp, TOTP)


def test_get_totp_invalid_key_value_error():
    short_key = b"short"
    with pytest.raises(ValueError, match="Invalid length or Invalid key."):
        get_totp(key=short_key)


def test_get_totp_type_error_conversion():
    with pytest.raises(ValueError, match="Invalid Algorithm."):
        get_totp(key=12345)


def test_verify_totp_function():
    key = os.urandom(32)
    totp = get_totp(key)
    now = int(time.time())
    otp_bytes = totp.generate(now)

    # verify_totp calls totp.verify directly which returns None on success
    verify_totp(totp, otp_bytes, now)

    # Calling verify_totp with invalid OTP should raise InvalidToken
    with pytest.raises(InvalidToken):
        verify_totp(totp, b"000000", now)


class TestHOTPBuilder:
    def test_hotp_builder_init_and_generate(self):
        key = os.urandom(32)
        builder = HOTPBuilder(key=key, counter=0, length=6)
        hotp_str, counter = builder.generate()

        assert isinstance(hotp_str, str)
        assert len(hotp_str) == 7  # 1 character prefix + 6 digit OTP
        assert hotp_str[0] in ascii_uppercase
        assert counter == ord(hotp_str[0])
        assert builder.counter == counter

    def test_hotp_builder_verify_success(self):
        key = os.urandom(32)
        builder = HOTPBuilder(key=key, counter=0, length=6)
        hotp_str, counter = builder.generate()

        assert builder.verify(hotp_str) is True

    def test_hotp_builder_verify_counter_zero(self):
        key = os.urandom(32)
        builder = HOTPBuilder(key=key, counter=0, length=6)
        with pytest.raises(ValueError, match="Invalid counter key."):
            builder.verify("A123456")

    def test_hotp_builder_verify_mismatch(self):
        key = os.urandom(32)
        builder = HOTPBuilder(key=key, counter=0, length=6)
        builder.generate()
        # Invalid OTP for current counter
        assert builder.verify("A000000") is False

    def test_hotp_builder_get_key(self):
        key = os.urandom(32)
        builder = HOTPBuilder(key=key, counter=0, length=6)
        # Attribute 'key' is not set in __init__, so calling get_key generates a key via KeyBuilder
        generated_key = builder.get_key()
        assert isinstance(generated_key, bytes)
        assert builder.get_key() == generated_key


class TestTOTPBuilder:
    def test_totp_builder_init_and_generate(self):
        key = os.urandom(32)
        t_val = time.time()
        builder = TOTPBuilder(key=key, length=6, time_step=30, time_value=t_val)

        otp_str, returned_time = builder.generate()
        assert isinstance(otp_str, str)
        assert len(otp_str) == 6
        assert returned_time == t_val

    def test_totp_builder_verify_success(self):
        key = os.urandom(32)
        t_val = time.time()
        builder = TOTPBuilder(key=key, length=6, time_step=30, time_value=t_val)
        otp_str, _ = builder.generate()

        assert builder.verify(otp_str) is True

    def test_totp_builder_verify_invalid_otp(self):
        key = os.urandom(32)
        t_val = time.time()
        builder = TOTPBuilder(key=key, length=6, time_step=30, time_value=t_val)

        assert builder.verify("000000") is False

    def test_totp_builder_get_key(self):
        key = os.urandom(32)
        builder = TOTPBuilder(key=key)
        assert builder.get_key() == key


class TestKeyBuilder:
    def test_key_builder_generate(self):
        kb = KeyBuilder()
        key1 = kb.get_key()
        assert isinstance(key1, bytes)
        assert len(key1) > 0


# Property-based testing with Hypothesis
@given(st.integers(min_value=1, max_value=1000))
def test_hypothesis_hotp_builder_counter_generation(seed_counter):
    key = b"12345678901234567890123456789012"
    builder = HOTPBuilder(key=key, counter=seed_counter)
    counter = builder.generate_counter()
    assert 65 <= counter <= 90  # ASCII uppercase range A-Z
    assert builder.character == chr(counter)
