import base64
from datetime import timedelta
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from jose import jwt
from sqlmodel import SQLModel
from app.main import app
from app.jwt_helpers import create_access_token, create_refresh_token, SECRET_KEY, ALGORITHM
from app.service_layer.unit_of_work import create_db_and_tables, engine

@pytest_asyncio.fixture(autouse=True)
def setup_db():
    SQLModel.metadata.drop_all(engine)
    create_db_and_tables()

@pytest_asyncio.fixture
async def async_client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client

@pytest.mark.asyncio
async def test_register_login_flow(async_client):
    user_id = "test_user_flow"
    password = "securepassword"

    # Register
    register_resp = await async_client.post("/register", json={"user_id": user_id, "password": password})
    assert register_resp.status_code == 200
    assert register_resp.json()["user_id"] == user_id

    # Login
    login_resp = await async_client.post("/login", json={"user_id": user_id, "password": password})
    assert login_resp.status_code == 200
    data = login_resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    access_token = data["access_token"]
    refresh_token = data["refresh_token"]

    # Access Protected Route
    headers = {"Authorization": f"Bearer {access_token}"}
    protected_resp = await async_client.get("/protected", headers=headers)
    assert protected_resp.status_code == 200
    assert protected_resp.json()["user_id"] == user_id

    # Refresh Token
    refresh_resp = await async_client.post("/refresh", json={"refresh_token": refresh_token})
    assert refresh_resp.status_code == 200
    refresh_data = refresh_resp.json()
    assert "access_token" in refresh_data
    assert "refresh_token" in refresh_data
    new_access_token = refresh_data["access_token"]

    # Access Protected Route with new token
    headers_new = {"Authorization": f"Bearer {new_access_token}"}
    protected_resp_new = await async_client.get("/protected", headers=headers_new)
    assert protected_resp_new.status_code == 200
    assert protected_resp_new.json()["user_id"] == user_id

@pytest.mark.asyncio
async def test_login_invalid_credentials(async_client):
    user_id = "test_invalid"
    password = "securepassword"

    # Register
    await async_client.post("/register", json={"user_id": user_id, "password": password})

    # Login with wrong password
    login_resp = await async_client.post("/login", json={"user_id": user_id, "password": "wrongpassword"})
    assert login_resp.status_code == 400

    # Login with wrong user_id
    login_resp_2 = await async_client.post("/login", json={"user_id": "nonexistent", "password": password})
    assert login_resp_2.status_code == 400

@pytest.mark.asyncio
async def test_protected_route_invalid_token(async_client):
    headers = {"Authorization": "Bearer invalid_token_here"}
    protected_resp = await async_client.get("/protected", headers=headers)
    assert protected_resp.status_code == 401

@pytest.mark.asyncio
async def test_refresh_token_invalid_or_expired(async_client):
    # Case 1: Malformed token
    resp_malformed = await async_client.post("/refresh", json={"refresh_token": "not_a_valid_token"})
    assert resp_malformed.status_code == 401
    assert resp_malformed.json()["detail"] == "Invalid or expired refresh token"

    # Case 2: Expired token
    expired_tok = create_refresh_token({"sub": "user_expired"}, expires_delta=timedelta(seconds=-1))
    resp_expired = await async_client.post("/refresh", json={"refresh_token": expired_tok})
    assert resp_expired.status_code == 401
    assert resp_expired.json()["detail"] == "Invalid or expired refresh token"

    # Case 3: Wrong token type (access token instead of refresh token)
    access_tok = create_access_token({"sub": "user_wrong_type"})
    resp_access = await async_client.post("/refresh", json={"refresh_token": access_tok})
    assert resp_access.status_code == 401
    assert resp_access.json()["detail"] == "Invalid or expired refresh token"

@pytest.mark.asyncio
async def test_refresh_token_missing_sub(async_client):
    payload = {"type": "refresh"}
    encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    b64_jwt = base64.b64encode(encoded_jwt.encode('utf-8')).decode('utf-8')

    resp = await async_client.post("/refresh", json={"refresh_token": b64_jwt})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid token"

@pytest.mark.asyncio
async def test_refresh_token_user_not_found(async_client):
    refresh_tok = create_refresh_token({"sub": "non_existent_user"})

    resp = await async_client.post("/refresh", json={"refresh_token": refresh_tok})
    assert resp.status_code == 404
    assert resp.json()["detail"] == "User not found"
