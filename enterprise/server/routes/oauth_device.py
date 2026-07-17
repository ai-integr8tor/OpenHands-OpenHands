"""OAuth 2.0 Device Flow endpoints for CLI authentication."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from server.utils.url_utils import get_cookie_domain, get_cookie_samesite, get_web_url
from storage.api_key_store import ApiKeyStore
from storage.device_code_store import DeviceCodeStore

from openhands.analytics import get_analytics_service, resolve_analytics_context
from openhands.app_server.user_auth import get_user_id
from openhands.app_server.utils.logger import openhands_logger as logger

# Name of the cookie that stores the user's API key for browser clients of the
# device flow. The auth middleware reads this cookie as a fallback credential,
# so any write here MUST match what ``get_api_key_from_header`` looks up.
API_KEY_COOKIE_NAME = 'api_key'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEVICE_CODE_EXPIRES_IN = 600  # 10 minutes
DEVICE_TOKEN_POLL_INTERVAL = 5  # seconds

API_KEY_NAME = 'Device Link Access Key'
KEY_EXPIRATION_TIME = timedelta(days=7)  # Key expires in a week

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class DeviceAuthorizationResponse(BaseModel):
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int


class DeviceTokenResponse(BaseModel):
    access_token: str  # This will be the user's API key
    token_type: str = 'Bearer'
    expires_in: Optional[int] = None  # API keys may not have expiration


class DeviceCookieResponse(BaseModel):
    """Response for the cookie-based device token endpoint.

    The API key is intentionally NOT included in the body; clients receive it
    via the ``api_key`` HttpOnly cookie instead so it never lands in JS,
    browser history, or proxy logs.
    """

    success: bool = True
    user_id: str


class DeviceTokenErrorResponse(BaseModel):
    error: str
    error_description: Optional[str] = None
    interval: Optional[int] = None  # Required for slow_down error


@dataclass(frozen=True)
class DeviceFlowResult:
    """Result of resolving a device-code poll into a usable API key.

    Exactly one of the two cases holds:

    - Success: ``error`` is ``None``, and ``api_key`` / ``user_id`` are
      populated with the per-device API key and its owning Keycloak user id.
    - Error:   ``error`` carries the ``JSONResponse`` to return to the
      client, and ``api_key`` / ``user_id`` are empty strings (the caller
      must not look at them).

    The dataclass is frozen and validates the invariant in ``__post_init__``
    so a future maintainer cannot construct a half-populated result.
    """

    api_key: str
    user_id: str
    error: Optional[JSONResponse] = None

    def __post_init__(self) -> None:
        if self.error is None and (not self.api_key or not self.user_id):
            raise ValueError(
                'DeviceFlowResult requires both api_key and user_id when error is None.'
            )
        if self.error is not None and (self.api_key or self.user_id):
            raise ValueError(
                'DeviceFlowResult.api_key and user_id must be empty when error is set.'
            )


# ---------------------------------------------------------------------------
# Router + stores
# ---------------------------------------------------------------------------

oauth_device_router = APIRouter(prefix='/oauth/device')
device_code_store = DeviceCodeStore()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _oauth_error(
    status_code: int,
    error: str,
    description: str,
    interval: Optional[int] = None,
) -> JSONResponse:
    """Return a JSON OAuth-style error response."""
    return JSONResponse(
        status_code=status_code,
        content=DeviceTokenErrorResponse(
            error=error,
            error_description=description,
            interval=interval,
        ).model_dump(),
    )


async def _resolve_device_api_key(device_code: str) -> DeviceFlowResult:
    """Run the shared device-flow validation and return the resolved API key.

    Both ``/token`` and ``/cookie`` need to enforce exactly the same
    rate-limit, status, and lookup semantics. Centralising it here keeps the
    two endpoints in lock-step and avoids drifting error responses when one
    endpoint grows new checks.

    The result is a :class:`DeviceFlowResult`; callers check ``result.error``
    and return it directly, or read ``result.api_key`` / ``result.user_id``
    on success. The dataclass enforces the "exactly one of success / error
    is populated" invariant, so the caller cannot accidentally read the
    wrong field.

    The helper also performs the side effect of updating the device code
    store's poll-time state for rate limiting, so each call counts as one
    poll on the client's behalf. The store fetch is done once here and
    ``user_id`` is returned alongside ``api_key`` so the caller does not
    have to re-read the device-code entry.
    """
    device_code_entry = await device_code_store.get_by_device_code(device_code)

    if not device_code_entry:
        return DeviceFlowResult(
            api_key='',
            user_id='',
            error=_oauth_error(
                status.HTTP_400_BAD_REQUEST,
                'invalid_grant',
                'Invalid device code',
            ),
        )

    # Check rate limiting (RFC 8628 section 3.5)
    is_too_fast, current_interval = device_code_entry.check_rate_limit()
    if is_too_fast:
        await device_code_store.update_poll_time(device_code, increase_interval=True)
        logger.warning(
            'Client polling too fast, returning slow_down error',
            extra={
                'device_code': device_code[:8] + '...',  # Log partial for privacy
                'new_interval': current_interval,
            },
        )
        return DeviceFlowResult(
            api_key='',
            user_id='',
            error=_oauth_error(
                status.HTTP_400_BAD_REQUEST,
                'slow_down',
                f'Polling too frequently. Wait at least {current_interval} seconds between requests.',
                interval=current_interval,
            ),
        )

    # Update poll time for successful rate limit check
    await device_code_store.update_poll_time(device_code, increase_interval=False)

    if device_code_entry.is_expired():
        return DeviceFlowResult(
            api_key='',
            user_id='',
            error=_oauth_error(
                status.HTTP_400_BAD_REQUEST,
                'expired_token',
                'Device code has expired',
            ),
        )

    if device_code_entry.status == 'denied':
        return DeviceFlowResult(
            api_key='',
            user_id='',
            error=_oauth_error(
                status.HTTP_400_BAD_REQUEST,
                'access_denied',
                'User denied the authorization request',
            ),
        )

    if device_code_entry.status == 'pending':
        return DeviceFlowResult(
            api_key='',
            user_id='',
            error=_oauth_error(
                status.HTTP_400_BAD_REQUEST,
                'authorization_pending',
                'User has not yet completed authorization',
            ),
        )

    if device_code_entry.status == 'authorized':
        if not device_code_entry.keycloak_user_id:
            logger.error(
                'Authorized device code missing user_id',
                extra={'user_code': device_code_entry.user_code},
            )
            return DeviceFlowResult(
                api_key='',
                user_id='',
                error=_oauth_error(
                    status.HTTP_500_INTERNAL_SERVER_ERROR,
                    'server_error',
                    'User identification missing',
                ),
            )

        api_key_store = ApiKeyStore.get_instance()
        device_key_name = f'{API_KEY_NAME} ({device_code_entry.user_code})'
        device_api_key = await api_key_store.retrieve_api_key_by_name(
            device_code_entry.keycloak_user_id, device_key_name
        )

        if not device_api_key:
            logger.error(
                'No device API key found for authorized device',
                extra={
                    'user_id': device_code_entry.keycloak_user_id,
                    'user_code': device_code_entry.user_code,
                },
            )
            return DeviceFlowResult(
                api_key='',
                user_id='',
                error=_oauth_error(
                    status.HTTP_500_INTERNAL_SERVER_ERROR,
                    'server_error',
                    'API key not found',
                ),
            )

        return DeviceFlowResult(
            api_key=device_api_key,
            user_id=device_code_entry.keycloak_user_id,
        )

    # Fallback for unexpected status values
    logger.error(
        'Unknown device code status',
        extra={'status': device_code_entry.status},
    )
    return DeviceFlowResult(
        api_key='',
        user_id='',
        error=_oauth_error(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            'server_error',
            'Unknown device code status',
        ),
    )


def _set_api_key_cookie(response: Response, request: Request, api_key: str) -> None:
    """Attach the device API key to ``response`` as the ``api_key`` cookie.

    The cookie attributes match the security note in
    ``enterprise/server/auth/saas_user_auth.py`` — ``HttpOnly`` so it is not
    reachable from JS, ``Secure`` outside localhost so it is never sent over
    plain HTTP in production, and ``SameSite=Strict`` (or ``Lax`` in
    local/staging) for CSRF protection.

    The lifetime is pinned to :data:`KEY_EXPIRATION_TIME` (7 days) so the
    browser never holds an API key that the server has already invalidated;
    a session cookie would silently keep the user "signed in" past the
    server-side expiry. ``path='/'`` ensures the cookie is sent to every
    ``/api/...`` route, not just the path the response was served from.

    Cross-site fetch flows (CHIPS / partitioned cookies): the device flow is
    commonly driven by a ``fetch()`` from a separate frontend origin (e.g.
    the endpoint lives on ``app.all-hands.dev`` but the embedded CLI page is
    served from ``localhost:8001``). In that case the response is a
    third-party cookie, which modern browsers reject unless the cookie is
    explicitly marked ``Partitioned``; ``SameSite=Strict``/``Lax`` would
    also cause the browser to drop the ``Set-Cookie`` from a cross-site
    response. To support both same-site and cross-site flows over HTTPS we
    switch to ``SameSite=None; Secure; Partitioned`` — the browser stores
    the cookie in a per-top-level-site jar, so the embedded frontend can
    send it back on subsequent API calls but a different site cannot read
    it. Partitioned is gated on ``Secure`` because the CHIPS spec requires
    it, so on ``localhost`` we fall back to the non-cross-site attributes.

    The API key is a short opaque token (well under the 4096-byte single
    cookie cap), so a plain ``set_cookie`` is sufficient and avoids the
    chunked-cookie machinery used for the much larger Keycloak JWS.
    """
    secure = request.url.hostname != 'localhost'
    partitioned = secure  # CHIPS requires Secure; only partition over HTTPS.
    response.set_cookie(
        key=API_KEY_COOKIE_NAME,
        value=api_key,
        max_age=int(KEY_EXPIRATION_TIME.total_seconds()),
        path='/',
        domain=get_cookie_domain(),
        secure=secure,
        httponly=True,
        samesite='none' if partitioned else get_cookie_samesite(),
    )
    if partitioned:
        # The stdlib ``http.cookies`` Morsel (and Starlette's
        # ``set_cookie`` on top of it) refuse the ``Partitioned``
        # attribute on Python < 3.14, but this project still supports
        # 3.12-3.13. Append the attribute to the ``Set-Cookie`` header
        # that ``set_cookie`` just wrote so the browser actually
        # accepts the cookie as a third-party partitioned cookie.
        for idx, (k, v) in enumerate(response.raw_headers):
            if k.lower() == b'set-cookie':
                response.raw_headers[idx] = (k, v + b'; Partitioned')
                break


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@oauth_device_router.post('/authorize', response_model=DeviceAuthorizationResponse)
async def device_authorization(
    http_request: Request,
) -> DeviceAuthorizationResponse:
    """Start device flow by generating device and user codes."""
    try:
        device_code_entry = await device_code_store.create_device_code(
            expires_in=DEVICE_CODE_EXPIRES_IN,
        )

        base_url = get_web_url(http_request)
        verification_uri = f'{base_url}/oauth/device/verify'
        verification_uri_complete = (
            f'{verification_uri}?user_code={device_code_entry.user_code}'
        )

        logger.info(
            'Device authorization initiated',
            extra={'user_code': device_code_entry.user_code},
        )

        return DeviceAuthorizationResponse(
            device_code=device_code_entry.device_code,
            user_code=device_code_entry.user_code,
            verification_uri=verification_uri,
            verification_uri_complete=verification_uri_complete,
            expires_in=DEVICE_CODE_EXPIRES_IN,
            interval=device_code_entry.current_interval,
        )
    except Exception as e:
        logger.exception('Error in device authorization: %s', str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Internal server error',
        ) from e


@oauth_device_router.post('/token')
async def device_token(device_code: str = Form(...)):
    """Poll for a token until the user authorizes or the code expires."""
    try:
        result = await _resolve_device_api_key(device_code)
        if result.error is not None:
            return result.error
        return DeviceTokenResponse(access_token=result.api_key)

    except Exception as e:
        logger.exception('Error in device token: %s', str(e))
        return _oauth_error(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            'server_error',
            'Internal server error',
        )


@oauth_device_router.post('/cookie', response_model=DeviceCookieResponse)
async def device_cookie(
    http_request: Request,
    device_code: str = Form(...),
):
    """Poll for a token and deliver it via the ``api_key`` HttpOnly cookie.

    Mirrors :func:`device_token` end-to-end (rate limiting, status checks,
    API key lookup) so browser-based clients see the same error semantics,
    but writes the API key into the ``api_key`` cookie instead of returning
    it in the response body. The body only contains a small success marker
    so the secret never touches JS, browser history, or proxy logs.

    Security note: the cookie MUST be marked ``Secure; HttpOnly;
    SameSite=Strict`` (or ``Lax``) — see ``get_api_key_from_header`` for the
    matching read path and the matching requirement note in
    ``enterprise/server/auth/saas_user_auth.py``.
    """
    try:
        result = await _resolve_device_api_key(device_code)
        if result.error is not None:
            return result.error

        response = JSONResponse(
            status_code=status.HTTP_200_OK,
            content=DeviceCookieResponse(user_id=result.user_id).model_dump(),
        )
        _set_api_key_cookie(response, http_request, result.api_key)
        return response

    except Exception as e:
        logger.exception('Error in device cookie: %s', str(e))
        return _oauth_error(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            'server_error',
            'Internal server error',
        )


@oauth_device_router.post('/verify-authenticated')
async def device_verification_authenticated(
    user_code: str = Form(...),
    user_id: str = Depends(get_user_id),
):
    """Process device verification for authenticated users (called by frontend)."""
    try:
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Authentication required',
            )

        # Validate device code
        device_code_entry = await device_code_store.get_by_user_code(user_code)
        if not device_code_entry:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='The device code is invalid or has expired.',
            )

        if not device_code_entry.is_pending():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='This device code has already been processed.',
            )

        # First, authorize the device code
        success = await device_code_store.authorize_device_code(
            user_code=user_code,
            user_id=user_id,
        )

        if not success:
            logger.error(
                'Failed to authorize device code',
                extra={'user_code': user_code, 'user_id': user_id},
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail='Failed to authorize the device. Please try again.',
            )

        # Only create API key AFTER successful authorization
        api_key_store = ApiKeyStore.get_instance()
        try:
            # Create a unique API key for this device using user_code in the name
            device_key_name = f'{API_KEY_NAME} ({user_code})'
            await api_key_store.create_api_key(
                user_id,
                name=device_key_name,
                expires_at=datetime.now(UTC) + KEY_EXPIRATION_TIME,
            )
            logger.info(
                'Created new device API key for user after successful authorization',
                extra={'user_id': user_id, 'user_code': user_code},
            )
        except Exception as e:
            logger.exception(
                'Failed to create device API key after authorization: %s', str(e)
            )

            # Clean up: revert the device authorization since API key creation failed
            # This prevents the device from being in an authorized state without an API key
            try:
                await device_code_store.deny_device_code(user_code)
                logger.info(
                    'Reverted device authorization due to API key creation failure',
                    extra={'user_code': user_code, 'user_id': user_id},
                )
            except Exception as cleanup_error:
                logger.exception(
                    'Failed to revert device authorization during cleanup: %s',
                    str(cleanup_error),
                )

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail='Failed to create API key for device access.',
            )

        logger.info(
            'Device code authorized with API key successfully',
            extra={'user_code': user_code, 'user_id': user_id},
        )

        # Server-side identity tracking for device auth flow
        analytics = get_analytics_service()
        if analytics:
            try:
                ctx = await resolve_analytics_context(user_id)

                # Load current org name for identify_user
                from storage.org_store import OrgStore

                current_org = (
                    await OrgStore.get_org_by_id(ctx.user.current_org_id)
                    if ctx.user and ctx.user.current_org_id
                    else None
                )

                analytics.identify_user(
                    ctx=ctx,
                    org_name=current_org.name if current_org else None,
                    idp='device_auth',
                )

                analytics.track_user_logged_in(
                    ctx=ctx,
                    idp='device_auth',
                )
            except Exception:
                logger.exception(
                    'oauth_device:analytics:failed',
                    extra={'user_id': user_id},
                )

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={'message': 'Device authorized successfully!'},
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception('Error in device verification: %s', str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='An unexpected error occurred. Please try again.',
        )
