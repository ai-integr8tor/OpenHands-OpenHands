import asyncio
import logging
import uuid
import json
from typing import Any, Literal
from urllib.parse import urlparse, parse_qs

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from openhands.app_server.config import depends_user_context
from openhands.app_server.user.user_context import UserContext
from openhands.sdk.utils.cipher import Cipher
from storage.encrypt_utils import get_cipher

from fastmcp import Client
from fastmcp.client.auth.oauth import OAuth, TokenStorageAdapter
from fastmcp.client.transports.sse import SSETransport
from fastmcp.client.transports.http import StreamableHttpTransport
from mcp.shared.auth import OAuthClientMetadata, OAuthClientInformationFull
from key_value.aio.stores.memory import MemoryStore

logger = logging.getLogger(__name__)

mcp_oauth_router = APIRouter(prefix='/api/v1/mcp/oauth', tags=['MCP OAuth'])
user_dependency = depends_user_context()


class FlowEntry:
    def __init__(self):
        self.init_ready_event = asyncio.Event()
        self.callback_completed_event = asyncio.Event()
        self.authorization_url: str | None = None
        self.code: str | None = None
        self.state: str | None = None
        self.error: Exception | None = None
        self.result: dict | None = None


# Global store for active OAuth flows
FLOWS: dict[str, FlowEntry] = {}


class CloudOAuthProvider(OAuth):
    def __init__(self, redirect_uri: str, flows_dict: dict, flow_entry: FlowEntry, *args, **kwargs):
        self.cloud_redirect_uri = redirect_uri
        self.flows_dict = flows_dict
        self.flow_entry = flow_entry
        self.state_key = None
        super().__init__(*args, **kwargs)

    def _bind(self, mcp_url: str) -> None:
        if self._bound:
            return

        mcp_url = mcp_url.rstrip("/")
        redirect_uri = self.cloud_redirect_uri

        scopes_str: str
        if isinstance(self._scopes, list):
            scopes_str = " ".join(self._scopes)
        elif self._scopes is not None:
            scopes_str = str(self._scopes)
        else:
            scopes_str = ""

        from pydantic import AnyHttpUrl
        client_metadata = OAuthClientMetadata(
            client_name=self._client_name,
            redirect_uris=[AnyHttpUrl(redirect_uri)],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope=scopes_str,
            **(self._additional_client_metadata or {}),
        )

        if self._client_id:
            metadata = client_metadata.model_dump(exclude_none=True)
            if "token_endpoint_auth_method" not in metadata:
                metadata["token_endpoint_auth_method"] = (
                    "client_secret_post" if self._client_secret else "none"
                )
            self._static_client_info = OAuthClientInformationFull(
                client_id=self._client_id,
                client_secret=self._client_secret,
                **metadata,
            )

        token_storage = self._token_storage or MemoryStore()
        self.token_storage_adapter = TokenStorageAdapter(
            async_key_value=token_storage, server_url=mcp_url
        )

        self.mcp_url = mcp_url

        # Call grandparent OAuthClientProvider.__init__ directly
        super(OAuth, self).__init__(
            server_url=mcp_url,
            client_metadata=client_metadata,
            storage=self.token_storage_adapter,
            redirect_handler=self.redirect_handler,
            callback_handler=self.callback_handler,
            client_metadata_url=self._client_metadata_url,
        )
        self._bound = True

    async def redirect_handler(self, authorization_url: str) -> None:
        """Capture the authorization url and wait for callback completion."""
        parsed = urlparse(authorization_url)
        mcp_state = parse_qs(parsed.query).get("state", [None])[0]
        if not mcp_state:
            raise ValueError("No state parameter found in authorization URL")

        self.state_key = mcp_state
        self.flows_dict[mcp_state] = self.flow_entry

        self.flow_entry.authorization_url = authorization_url
        self.flow_entry.state = mcp_state
        self.flow_entry.init_ready_event.set()

        await self.flow_entry.callback_completed_event.wait()
        if self.flow_entry.error:
            raise self.flow_entry.error

    async def callback_handler(self) -> tuple[str, str | None]:
        """Return the captured code and state."""
        if self.flow_entry and self.flow_entry.code:
            return self.flow_entry.code, self.flow_entry.state
        raise RuntimeError("OAuth callback code was not captured")


class MCPInitRequest(BaseModel):
    name: str = Field(..., description="Name of the MCP server")
    url: str = Field(..., description="URL of the MCP server")
    type: Literal["sse", "http", "shttp"] = Field("sse", description="Transport type")


def encrypt_credentials(result: dict) -> str:
    cipher = get_cipher()
    plaintext = json.dumps(result)
    from pydantic import SecretStr
    return cipher.encrypt(SecretStr(plaintext))


async def run_cloud_oauth_flow(
    url: str,
    transport_type: str,
    redirect_uri: str,
    flow_entry: FlowEntry
) -> None:
    try:
        transport = (
            SSETransport(url=url)
            if transport_type == "sse"
            else StreamableHttpTransport(url=url)
        )

        provider = CloudOAuthProvider(
            redirect_uri=redirect_uri,
            flows_dict=FLOWS,
            flow_entry=flow_entry,
            client_name="OpenHands Client"
        )

        client = Client(
            transport=transport,
            auth=provider,
            auto_initialize=True
        )

        async with client:
            tokens = await provider.token_storage_adapter.get_tokens()
            client_info = await provider.token_storage_adapter.get_client_info()

            result = {
                "tokens": {
                    "access_token": tokens.access_token,
                    "refresh_token": tokens.refresh_token,
                    "expires_in": tokens.expires_in,
                    "token_type": tokens.token_type,
                    "scope": tokens.scope,
                } if tokens else None,
                "client_info": {
                    "client_id": client_info.client_id,
                    "client_secret": client_info.client_secret,
                } if client_info else None,
            }
            flow_entry.result = result
    except Exception as e:
        logger.exception("MCP OAuth flow failed")
        flow_entry.error = e
        flow_entry.init_ready_event.set()


@mcp_oauth_router.post('/init')
async def init_mcp_oauth(
    request: Request,
    body: MCPInitRequest,
    user_context: UserContext = user_dependency,
) -> JSONResponse:
    user_id = await user_context.get_user_id()
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not authenticated"
        )

    # Build SaaS web redirect URL
    from server.utils.url_utils import get_web_url
    web_url = get_web_url(request)
    redirect_uri = f"{web_url}/api/v1/mcp/oauth/callback"

    flow_entry = FlowEntry()
    asyncio.create_task(
        run_cloud_oauth_flow(
            url=body.url,
            transport_type=body.type,
            redirect_uri=redirect_uri,
            flow_entry=flow_entry
        )
    )

    # Wait for the flow to start and generate authorization URL
    try:
        async with asyncio.timeout(15.0):
            await flow_entry.init_ready_event.wait()
    except TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_504_TIMEOUT,
            detail="OAuth flow initialization timed out"
        )

    if flow_entry.error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(flow_entry.error)
        )

    return JSONResponse(
        content={
            "state": flow_entry.state,
            "authorization_url": flow_entry.authorization_url,
        }
    )


@mcp_oauth_router.get('/callback', response_class=HTMLResponse)
async def mcp_oauth_callback(
    code: str = '',
    state: str = '',
    error: str = '',
    error_description: str = '',
) -> HTMLResponse:
    if not state:
        return HTMLResponse(
            content="<h1>Authentication Failed</h1><p>Missing state parameter.</p>",
            status_code=400
        )

    entry = FLOWS.get(state)
    if not entry:
        return HTMLResponse(
            content="<h1>Authentication Failed</h1><p>Active flow not found or expired.</p>",
            status_code=404
        )

    if error:
        entry.error = RuntimeError(f"OAuth error: {error_description or error}")
        entry.callback_completed_event.set()
        return HTMLResponse(
            content=f"<h1>Authentication Failed</h1><p>{error_description or error}</p>",
            status_code=400
        )

    entry.code = code
    entry.callback_completed_event.set()

    success_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>OpenHands MCP OAuth</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                background-color: #0f1115;
                color: #e3e3e3;
                display: flex;
                align-items: center;
                justify-content: center;
                height: 100vh;
                margin: 0;
            }
            .card {
                background-color: #1a1d24;
                border: 1px solid #2d3139;
                border-radius: 8px;
                padding: 32px;
                text-align: center;
                max-width: 400px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            }
            h1 {
                color: #4ade80;
                margin-top: 0;
            }
            p {
                color: #a3a3a3;
                font-size: 14px;
            }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Authentication Successful!</h1>
            <p>You have authorized OpenHands to access this MCP server.</p>
            <p>You can safely close this browser tab now.</p>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=success_html)


@mcp_oauth_router.get('/status/{state}')
async def get_mcp_oauth_status(
    state: str,
    user_context: UserContext = user_dependency,
) -> JSONResponse:
    user_id = await user_context.get_user_id()
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not authenticated"
        )

    entry = FLOWS.get(state)
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="OAuth flow not found or expired"
        )

    if entry.error:
        FLOWS.pop(state, None)
        return JSONResponse(
            content={
                "status": "failed",
                "error": str(entry.error),
            }
        )

    if entry.result:
        FLOWS.pop(state, None)
        encrypted_credentials = encrypt_credentials(entry.result)
        
        return JSONResponse(
            content={
                "status": "success",
                "server": {
                    "transport": "sse",
                    "auth": "oauth",
                    "oauth_credentials": encrypted_credentials,
                }
            }
        )

    return JSONResponse(content={"status": "pending"})
