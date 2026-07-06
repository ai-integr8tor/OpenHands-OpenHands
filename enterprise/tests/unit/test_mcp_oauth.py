import json
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
import pytest
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from pydantic import SecretStr

from openhands.app_server.user.user_context import UserContext
from openhands.app_server.services.jwt_service import JwtService
from openhands.app_server.utils.encryption_key import EncryptionKey
from fastmcp.mcp_config import MCPConfig
from openhands.app_server.settings.settings_models import Settings
from openhands.app_server.app_conversation.app_conversation_models import SandboxGroupingStrategy

# Create a mock JWT service for decryption
def _make_jwt_service() -> JwtService:
    key = EncryptionKey(kid='test', key=SecretStr('test_secret_for_settings'), active=True)
    return JwtService(keys=[key])


@pytest.fixture(autouse=True)
def mock_jwt_svc():
    jwt_svc = _make_jwt_service()
    with patch('storage.encrypt_utils.get_jwt_service', return_value=jwt_svc):
        # Reset cached globals
        import storage.encrypt_utils as encrypt_utils
        encrypt_utils._jwt_service = jwt_svc
        encrypt_utils._fernet = None
        yield jwt_svc


@pytest.fixture
def mock_user_context():
    mock_ctx = MagicMock()
    mock_ctx.get_user_id = AsyncMock(return_value="test-user-id")
    mock_ctx.get_user_email = AsyncMock(return_value="test@example.com")
    # Make it callable so Depends(user_dependency) returns mock_ctx
    mock_ctx.__call__ = lambda: mock_ctx
    return mock_ctx


@pytest.fixture
def app(mock_user_context) -> FastAPI:
    from server.routes.mcp_oauth import mcp_oauth_router
    from openhands.app_server.config import get_global_config

    fastapi_app = FastAPI()
    user_injector = get_global_config().user
    if user_injector:
        fastapi_app.dependency_overrides[user_injector.depends] = lambda: mock_user_context
    fastapi_app.include_router(mcp_oauth_router)
    return fastapi_app


@pytest.fixture
def client(app) -> TestClient:
    return TestClient(app)


@pytest.mark.asyncio
async def test_init_oauth_flow_and_callback(app):
    from server.routes.mcp_oauth import FLOWS
    from httpx import AsyncClient

    # Mock the background connection task run_cloud_oauth_flow to trigger redirect_handler and simulate connection success
    async def fake_run_cloud_oauth_flow(url, transport_type, redirect_uri, flow_entry):
        # 1. Simulate redirect_handler being called
        flow_entry.state = "test-state-key"
        flow_entry.authorization_url = f"https://example.com/oauth/authorize?state={flow_entry.state}&code_challenge=foo"
        FLOWS[flow_entry.state] = flow_entry
        flow_entry.init_ready_event.set()

        # 2. Wait for callback to complete
        await flow_entry.callback_completed_event.wait()

        # 3. Simulate success response from provider
        flow_entry.result = {
            "tokens": {
                "access_token": "mock-access-token",
                "refresh_token": "mock-refresh-token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "scope": "all",
            },
            "client_info": {
                "client_id": "mock-client-id",
                "client_secret": "mock-client-secret",
            }
        }

    with patch("server.routes.mcp_oauth.run_cloud_oauth_flow", side_effect=fake_run_cloud_oauth_flow):
        import httpx
        async with AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
            # 1. Initialize flow
            response = await client.post("/api/v1/mcp/oauth/init", json={
                "name": "notion",
                "url": "https://mcp.notion.com",
                "type": "sse"
            })
            assert response.status_code == 200
            data = response.json()
            assert data["state"] == "test-state-key"
            assert "authorization_url" in data

            # 2. Query status (should be pending)
            status_resp = await client.get(f"/api/v1/mcp/oauth/status/{data['state']}")
            assert status_resp.status_code == 200
            assert status_resp.json() == {"status": "pending"}

            # 3. Callback from OAuth provider
            callback_resp = await client.get(f"/api/v1/mcp/oauth/callback?code=mock-code&state={data['state']}")
            assert callback_resp.status_code == 200
            assert "Authentication Successful!" in callback_resp.text

            # Yield to let fake background task complete
            await asyncio.sleep(0.1)

            # 4. Check status again (should be success with encrypted credentials)
            status_resp = await client.get(f"/api/v1/mcp/oauth/status/{data['state']}")
            assert status_resp.status_code == 200
            status_data = status_resp.json()
            assert status_data["status"] == "success"
            assert status_data["server"]["auth"] == "oauth"
            assert "oauth_credentials" in status_data["server"]
            assert status_data["server"]["oauth_credentials"].startswith("gAAAAA")


@pytest.mark.asyncio
async def test_merge_custom_mcp_config_transformation():
    from openhands.app_server.app_conversation.live_status_app_conversation_service import (
        LiveStatusAppConversationService,
    )
    from storage.encrypt_utils import get_cipher

    cipher = get_cipher()
    raw_creds = {
        "tokens": {
            "access_token": "mock-refreshed-access-token",
            "refresh_token": "mock-refresh-token",
        },
        "client_info": {
            "client_id": "mock-client-id",
        }
    }
    encrypted_creds = cipher.encrypt(SecretStr(json.dumps(raw_creds)))

    # Construct dummy settings with one oauth server and one API key server
    mcp_config_data = {
        "mcpServers": {
            "Notion": {
                "url": "https://mcp.notion.com",
                "auth": "oauth",
                "oauth_credentials": encrypted_creds,
            },
            "Tavily": {
                "url": "https://mcp.tavily.com",
                "auth": "my-tavily-api-key",
            }
        }
    }

    # Set up mocks
    mock_user = MagicMock()
    mock_user.id = "test-user-id"
    mock_user.agent_settings = MagicMock()
    mock_user.agent_settings.mcp_config = MCPConfig.model_validate(mcp_config_data)

    mock_ctx = MagicMock()
    mock_ctx.get_user_id = AsyncMock(return_value="test-user-id")
    mock_ctx.get_user_email = AsyncMock(return_value="test@example.com")

    service = LiveStatusAppConversationService(
        user_context=mock_ctx,
        app_conversation_info_service=AsyncMock(),
        app_conversation_start_task_service=AsyncMock(),
        event_callback_service=AsyncMock(),
        event_service=AsyncMock(),
        sandbox_service=AsyncMock(),
        sandbox_spec_service=AsyncMock(),
        jwt_service=AsyncMock(),
        pending_message_service=AsyncMock(),
        sandbox_startup_timeout=30,
        sandbox_startup_poll_frequency=1,
        max_num_conversations_per_sandbox=1,
        httpx_client=AsyncMock(),
        web_url="http://localhost",
        openhands_provider_base_url="http://localhost",
        access_token_hard_timeout=None,
        init_git_in_empty_workspace=False,
    )

    # Mock _refresh_oauth_tokens to return refreshed tokens directly without connecting
    async def mock_refresh(url, transport_type, tokens, client_info):
        return {"tokens": {"access_token": "mock-refreshed-access-token"}}

    with patch.object(service, "_refresh_oauth_tokens", side_effect=mock_refresh):
        mcp_servers = {}
        await service._merge_custom_mcp_config(mcp_servers, mock_user)

        # Notion auth must be transformed to the Bearer token string
        assert mcp_servers["Notion"]["auth"] == "mock-refreshed-access-token"
        assert "oauth_credentials" not in mcp_servers["Notion"]

        # Tavily should remain unchanged
        assert mcp_servers["Tavily"]["auth"] == "my-tavily-api-key"
