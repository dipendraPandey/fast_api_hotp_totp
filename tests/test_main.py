import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlmodel import SQLModel
from app.main import app
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
async def test_protected_route_missing_sub(async_client, monkeypatch):
    monkeypatch.setattr("app.main.verify_jwt_token", lambda token: {"type": "access"})
    headers = {"Authorization": "Bearer dummy_token"}
    response = await async_client.get("/protected", headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid token"

@pytest.mark.asyncio
async def test_protected_route_jwt_error(async_client, monkeypatch):
    from jose import JWTError
    def mock_verify_jwt_token(token):
        raise JWTError("Invalid JWT token")
    monkeypatch.setattr("app.main.verify_jwt_token", mock_verify_jwt_token)
    headers = {"Authorization": "Bearer dummy_token"}
    response = await async_client.get("/protected", headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired token"

@pytest.mark.asyncio
async def test_protected_route_user_not_found(async_client, monkeypatch):
    monkeypatch.setattr("app.main.verify_jwt_token", lambda token: {"sub": "non_existent_user", "type": "access"})
    headers = {"Authorization": "Bearer dummy_token"}
    response = await async_client.get("/protected", headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "User not found"

def test_get_current_user_direct_unit_tests(monkeypatch):
    from fastapi import HTTPException
    from fastapi.security import HTTPAuthorizationCredentials
    from jose import JWTError
    from app.main import get_current_user

    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="dummy_token")

    # 1. Missing sub
    monkeypatch.setattr("app.main.verify_jwt_token", lambda token: {})
    with pytest.raises(HTTPException) as exc_info:
        get_current_user(credentials)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid token"

    # 2. JWTError
    def mock_jwt_error(token):
        raise JWTError("Invalid or expired")
    monkeypatch.setattr("app.main.verify_jwt_token", mock_jwt_error)
    with pytest.raises(HTTPException) as exc_info:
        get_current_user(credentials)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid or expired token"

    # 3. User not found in database
    monkeypatch.setattr("app.main.verify_jwt_token", lambda token: {"sub": "non_existent_id"})
    with pytest.raises(HTTPException) as exc_info:
        get_current_user(credentials)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "User not found"
