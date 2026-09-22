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
async def test_verify_totp_flow(async_client):
    user_id = "test_totp_user"
    password = "totppassword"

    # Register user first
    await async_client.post("/register", json={"user_id": user_id, "password": password})

    # Generate TOTP
    gen_resp = await async_client.post("/generate/totp", json={"user_id": user_id})
    assert gen_resp.status_code == 200
    otp = gen_resp.json()["otp"]
    assert isinstance(otp, str)

    # Verify correct TOTP
    verify_resp = await async_client.post("/verify/totp", json={"user_id": user_id, "otp": otp})
    assert verify_resp.status_code == 200
    assert verify_resp.json()["is_valid"] is True

    # Verify invalid TOTP
    verify_invalid_resp = await async_client.post("/verify/totp", json={"user_id": user_id, "otp": "000000"})
    assert verify_invalid_resp.status_code == 200
    assert verify_invalid_resp.json()["is_valid"] is False

@pytest.mark.asyncio
async def test_totp_nonexistent_user(async_client):
    nonexistent_user = "nonexistent_totp_user"

    # Generate TOTP for non-existent user
    gen_resp = await async_client.post("/generate/totp", json={"user_id": nonexistent_user})
    assert gen_resp.status_code == 404

    # Verify TOTP for non-existent user
    verify_resp = await async_client.post("/verify/totp", json={"user_id": nonexistent_user, "otp": "123456"})
    assert verify_resp.status_code == 404
