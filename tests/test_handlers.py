import base64
from datetime import timedelta
import pytest
from jose import jwt

from app.domain import commands
from app.jwt_helpers import (
    create_access_token,
    create_refresh_token,
    SECRET_KEY,
    ALGORITHM,
)
from app.service_layer.handlers import (
    refresh_token,
    InvalidTokenException,
    UserNotFoundException,
)
from app.service_layer.unit_of_work import InMemoryUnitOfWork


def test_refresh_token_invalid_jwt():
    uow = InMemoryUnitOfWork(db={})

    # Test 1: Completely invalid / malformed base64 token string
    cmd_invalid = commands.RefreshTokenCommand(refresh_token="invalid_token_string")
    with pytest.raises(InvalidTokenException, match="Invalid or expired refresh token"):
        refresh_token(cmd_invalid, uow)

    # Test 2: Expired refresh token
    expired_token = create_refresh_token({"sub": "user1"}, expires_delta=timedelta(seconds=-1))
    cmd_expired = commands.RefreshTokenCommand(refresh_token=expired_token)
    with pytest.raises(InvalidTokenException, match="Invalid or expired refresh token"):
        refresh_token(cmd_expired, uow)

    # Test 3: Access token passed instead of refresh token
    access_tok = create_access_token({"sub": "user1"})
    cmd_wrong_type = commands.RefreshTokenCommand(refresh_token=access_tok)
    with pytest.raises(InvalidTokenException, match="Invalid or expired refresh token"):
        refresh_token(cmd_wrong_type, uow)


def test_refresh_token_missing_sub():
    uow = InMemoryUnitOfWork(db={})

    # Create a refresh token without a "sub" claim
    payload = {"type": "refresh"}
    encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    b64_jwt = base64.b64encode(encoded_jwt.encode('utf-8')).decode('utf-8')

    cmd = commands.RefreshTokenCommand(refresh_token=b64_jwt)
    with pytest.raises(InvalidTokenException, match="Invalid token"):
        refresh_token(cmd, uow)


def test_refresh_token_user_not_found():
    uow = InMemoryUnitOfWork(db={})

    # Create a valid refresh token for a user not in uow
    refresh_tok = create_refresh_token({"sub": "non_existent_user"})
    cmd = commands.RefreshTokenCommand(refresh_token=refresh_tok)
    with pytest.raises(UserNotFoundException, match="User not found"):
        refresh_token(cmd, uow)
