import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi import HTTPException
import httpx
from httpx import AsyncClient, ASGITransport

from app.main import app, verify_permission, http_client

@pytest.mark.asyncio
async def test_verify_permission_http_client_none():
    """Test verify_permission raises 503 when http_client is None."""
    with patch("app.main.http_client", None):
        dep = verify_permission(action="read", resource_type="finance")
        with pytest.raises(HTTPException) as exc_info:
            await dep(user_id="user1")
        assert exc_info.value.status_code == 503
        assert exc_info.value.detail == "Service Unavailable: HTTP client not initialized"

@pytest.mark.asyncio
async def test_verify_permission_allowed():
    """Test verify_permission returns user_id when OPA returns result=True."""
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"result": True}
    mock_client.post.return_value = mock_response

    with patch("app.main.http_client", mock_client):
        dep = verify_permission(action="read", resource_type="finance")
        res = await dep(user_id="finance_user")
        assert res == "finance_user"

        mock_client.post.assert_called_once()
        args, kwargs = mock_client.post.call_args
        assert kwargs["json"] == {
            "input": {
                "user": "finance_user",
                "action": "read",
                "resource": "finance"
            }
        }

@pytest.mark.asyncio
async def test_verify_permission_forbidden():
    """Test verify_permission raises 403 when OPA returns result=False."""
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"result": False}
    mock_client.post.return_value = mock_response

    with patch("app.main.http_client", mock_client):
        dep = verify_permission(action="read", resource_type="finance")
        with pytest.raises(HTTPException) as exc_info:
            await dep(user_id="unauthorized_user")
        assert exc_info.value.status_code == 403
        assert exc_info.value.detail == "Forbidden"

@pytest.mark.asyncio
async def test_verify_permission_request_error():
    """Test verify_permission raises 503 when httpx raises RequestError."""
    mock_client = AsyncMock()
    mock_client.post.side_effect = httpx.RequestError("Connection failed")

    with patch("app.main.http_client", mock_client):
        dep = verify_permission(action="read", resource_type="finance")
        with pytest.raises(HTTPException) as exc_info:
            await dep(user_id="user1")
        assert exc_info.value.status_code == 503
        assert exc_info.value.detail == "Service Unavailable: Authorization service unreachable"

@pytest.mark.asyncio
async def test_finance_endpoint_integration():
    """Test GET /finance/{report_id} endpoint with mocked http_client."""
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"result": True}
    mock_client.post.return_value = mock_response

    with patch("app.main.http_client", mock_client):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/finance/1234?user_id=finance_user")
            assert resp.status_code == 200
            assert resp.json() == {
                "report_id": "1234",
                "data": "Confidential financial data",
                "accessed_by": "finance_user"
            }
