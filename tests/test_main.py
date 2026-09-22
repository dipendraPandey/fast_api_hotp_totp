from unittest.mock import AsyncMock, patch
import httpx
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


def mock_opa_response(status_code: int, json_data: dict) -> httpx.Response:
    request = httpx.Request("POST", "http://localhost:8181/v1/data/app/rbac/allow")
    return httpx.Response(status_code, json=json_data, request=request)


@pytest.mark.asyncio
async def test_get_finance_report_permitted(async_client):
    mock_client = AsyncMock()
    mock_client.post.return_value = mock_opa_response(200, {"result": True})

    with patch("app.main.http_client", mock_client):
        response = await async_client.get("/finance/report-123?user_id=finance_user")

    assert response.status_code == 200
    assert response.json() == {
        "report_id": "report-123",
        "data": "Confidential financial data",
        "accessed_by": "finance_user",
    }
    mock_client.post.assert_called_once()
    args, kwargs = mock_client.post.call_args
    assert kwargs["json"] == {
        "input": {
            "user": "finance_user",
            "action": "read",
            "resource": "finance",
        }
    }


@pytest.mark.asyncio
async def test_get_finance_report_forbidden(async_client):
    mock_client = AsyncMock()
    mock_client.post.return_value = mock_opa_response(200, {"result": False})

    with patch("app.main.http_client", mock_client):
        response = await async_client.get("/finance/report-123?user_id=marketing_user")

    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}


@pytest.mark.asyncio
async def test_get_finance_report_authorization_service_error(async_client):
    mock_client = AsyncMock()
    mock_client.post.return_value = mock_opa_response(500, {"error": "OPA Error"})

    with patch("app.main.http_client", mock_client):
        response = await async_client.get("/finance/report-123?user_id=finance_user")

    assert response.status_code == 503
    assert response.json() == {"detail": "Service Unavailable: Authorization service unreachable"}


@pytest.mark.asyncio
async def test_get_finance_report_authorization_service_unreachable(async_client):
    mock_client = AsyncMock()
    mock_client.post.side_effect = httpx.ConnectError("Connection refused")

    with patch("app.main.http_client", mock_client):
        response = await async_client.get("/finance/report-123?user_id=finance_user")

    assert response.status_code == 503
    assert response.json() == {"detail": "Service Unavailable: Authorization service unreachable"}


@pytest.mark.asyncio
async def test_get_finance_report_client_not_initialized(async_client):
    with patch("app.main.http_client", None):
        response = await async_client.get("/finance/report-123?user_id=finance_user")

    assert response.status_code == 503
    assert response.json() == {"detail": "Service Unavailable: HTTP client not initialized"}
