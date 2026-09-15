import pytest
from datetime import timedelta
import base64
from jose import jwt, JWTError
from hypothesis import given, strategies as st
from app.jwt_helpers import (
    get_password_hash,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_base64_jwt,
    verify_jwt_token,
    SECRET_KEY,
    ALGORITHM
)

def test_password_hashing():
    password = "supersecretpassword123!"
    hashed = get_password_hash(password)
    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("wrongpassword", hashed) is False

def test_create_access_token():
    data = {"sub": "testuser"}
    token = create_access_token(data)
    # Token should be base64 encoded
    decoded = decode_base64_jwt(token)
    payload = jwt.decode(decoded, SECRET_KEY, algorithms=[ALGORITHM])
    assert payload["sub"] == "testuser"
    assert "exp" in payload
    assert payload["type"] == "access"

def test_create_refresh_token():
    data = {"sub": "testuser"}
    token = create_refresh_token(data)
    # Token should be base64 encoded
    decoded = decode_base64_jwt(token)
    payload = jwt.decode(decoded, SECRET_KEY, algorithms=[ALGORITHM])
    assert payload["sub"] == "testuser"
    assert "exp" in payload
    assert payload["type"] == "refresh"

def test_verify_jwt_token_valid():
    data = {"sub": "validuser"}
    token = create_access_token(data)
    payload = verify_jwt_token(token, expected_type="access")
    assert payload["sub"] == "validuser"

def test_verify_jwt_token_invalid_type():
    data = {"sub": "invalidtype"}
    token = create_access_token(data) # type is access
    with pytest.raises(JWTError, match="Invalid token type"):
        verify_jwt_token(token, expected_type="refresh")

def test_verify_jwt_token_expired():
    data = {"sub": "expireduser"}
    # create token that is already expired
    token = create_access_token(data, expires_delta=timedelta(seconds=-1))
    with pytest.raises(JWTError):
        verify_jwt_token(token)

def test_verify_jwt_token_invalid_base64():
    invalid_token = "this_is_not_base64"
    with pytest.raises(JWTError, match="Invalid base64 encoding"):
        verify_jwt_token(invalid_token)

def test_verify_jwt_token_invalid_signature():
    data = {"sub": "badsignature"}
    # Create valid JWT then re-encode it with bad key
    to_encode = data.copy()
    encoded_jwt = jwt.encode(to_encode, "wrong_key", algorithm=ALGORITHM)
    b64_jwt = base64.b64encode(encoded_jwt.encode('utf-8')).decode('utf-8')
    with pytest.raises(JWTError):
        verify_jwt_token(b64_jwt)

# Hypothesis tests for property-based testing
@given(st.text(min_size=1, max_size=50))
def test_hypothesis_encode_decode(sub):
    data = {"sub": sub}
    token = create_access_token(data)
    payload = verify_jwt_token(token)
    assert payload["sub"] == sub
