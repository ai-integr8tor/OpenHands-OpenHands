from __future__ import annotations

import secrets
import string
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from storage.api_key import ApiKey, ApiKeyScope
from storage.database import a_session_maker
from storage.user_store import UserStore

from openhands.app_server.utils.logger import openhands_logger as logger

# Implicit scope carried by keys that have no explicit scope rows. Storing no
# rows (rather than a literal "full" row) keeps legacy keys unchanged and lets
# `full` remain a reserved, OpenHands-owned sentinel rather than a grantable
# namespaced scope.
FULL_SCOPE = 'full'


@dataclass
class ApiKeyValidationResult:
    """Result of API key validation containing user and organization info."""

    user_id: str
    org_id: UUID | None  # None for legacy API keys without org binding
    key_id: int
    key_name: str | None
    # Opaque, namespaced scope strings attached to the key. Defaults to
    # ``[FULL_SCOPE]`` for keys without explicit scopes (legacy + back-compat).
    # OpenHands does not interpret these; resource servers enforce them.
    scopes: list[str] = field(default_factory=lambda: [FULL_SCOPE])


@dataclass
class ApiKeyStore:
    API_KEY_PREFIX = 'sk-oh-'
    # Prefix for system keys created by internal services (e.g., automations)
    # Keys with this prefix are hidden from users and cannot be deleted by users
    SYSTEM_KEY_NAME_PREFIX = '__SYSTEM__:'

    def generate_api_key(self, length: int = 32) -> str:
        """Generate a random API key with the sk-oh- prefix."""
        alphabet = string.ascii_letters + string.digits
        random_part = ''.join(secrets.choice(alphabet) for _ in range(length))
        return f'{self.API_KEY_PREFIX}{random_part}'

    @classmethod
    def is_system_key_name(cls, name: str | None) -> bool:
        """Check if a key name indicates a system key."""
        return name is not None and name.startswith(cls.SYSTEM_KEY_NAME_PREFIX)

    @classmethod
    def make_system_key_name(cls, name: str) -> str:
        """Create a system key name with the appropriate prefix.

        Format: __SYSTEM__:<name>
        """
        return f'{cls.SYSTEM_KEY_NAME_PREFIX}{name}'

    @staticmethod
    def _normalize_scopes(scopes: list[str] | None) -> list[str]:
        """Normalize a requested scope list into rows to persist.

        - ``None`` or empty -> ``[]`` (no rows; key carries the implicit
          ``full`` scope, preserving legacy behavior).
        - The reserved ``full`` sentinel is dropped: a fully-privileged key is
          represented by the *absence* of scope rows, not by a ``full`` row.
        - Duplicates are removed while preserving order.
        """
        if not scopes:
            return []
        normalized: list[str] = []
        for raw in scopes:
            scope = raw.strip()
            if not scope or scope == FULL_SCOPE:
                continue
            if scope not in normalized:
                normalized.append(scope)
        return normalized

    @staticmethod
    async def _add_scope_rows(
        session: AsyncSession, api_key_id: int, scopes: list[str]
    ) -> None:
        """Persist normalized scope rows for a key within an open session."""
        for scope in scopes:
            session.add(ApiKeyScope(api_key_id=api_key_id, scope=scope))

    @staticmethod
    async def _load_scopes(session: AsyncSession, api_key_id: int) -> list[str]:
        """Load scope strings for a key, defaulting to ``[FULL_SCOPE]``."""
        result = await session.execute(
            select(ApiKeyScope.scope).filter(ApiKeyScope.api_key_id == api_key_id)
        )
        scopes = list(result.scalars().all())
        return scopes if scopes else [FULL_SCOPE]

    @staticmethod
    async def _ensure_scope_rows(
        session: AsyncSession, api_key_id: int, scopes: list[str]
    ) -> None:
        """Idempotently add any missing scope rows to an existing key.

        Additive only — it never removes scopes a key already has. This lets an
        internal caller *tighten* an already-existing system key by attaching a
        scope (e.g. a ``openhands:role:member`` cap) so the reduced-privilege
        guarantee also covers keys minted before scopes existed. Enforcement
        combines role-cap scopes to the least-privileged one, so adding a cap can
        only narrow, never widen, the key's effective role.
        """
        if not scopes:
            return
        result = await session.execute(
            select(ApiKeyScope.scope).filter(ApiKeyScope.api_key_id == api_key_id)
        )
        existing = set(result.scalars().all())
        for scope in scopes:
            if scope not in existing:
                session.add(ApiKeyScope(api_key_id=api_key_id, scope=scope))

    async def create_api_key(
        self,
        user_id: str,
        name: str | None = None,
        expires_at: datetime | None = None,
        org_id: UUID | None = None,
        scopes: list[str] | None = None,
    ) -> str:
        """Create a new API key for a user.

        Args:
            user_id: The ID of the user to create the key for
            name: Optional name for the key
            expires_at: Expiration datetime in UTC. Timezone info is stripped before
                writing to the TIMESTAMP WITHOUT TIME ZONE column.
            org_id: Optional explicit org binding. When omitted, falls back
                to the user's persisted ``current_org_id``. Callers in
                request context should pass the effective org id (see
                ``SaasUserAuth.get_effective_org_id``).
            scopes: Optional opaque, namespaced scope strings to attach to the
                key. When omitted/empty the key carries the implicit ``full``
                scope (no behavior change). OpenHands stores these verbatim and
                does not interpret them; resource servers enforce meaning.

        Returns:
            The generated API key
        """
        api_key = self.generate_api_key()
        if org_id is None:
            user = await UserStore.get_user_by_id(user_id)
            if user is None:
                raise ValueError(f'User not found: {user_id}')
            org_id = user.current_org_id

        # Column is TIMESTAMP WITHOUT TIME ZONE; strip tzinfo before writing.
        if expires_at is not None and expires_at.tzinfo is not None:
            expires_at = expires_at.replace(tzinfo=None)

        normalized_scopes = self._normalize_scopes(scopes)

        async with a_session_maker() as session:
            key_record = ApiKey(
                key=api_key,
                user_id=user_id,
                org_id=org_id,
                name=name,
                expires_at=expires_at,
            )
            session.add(key_record)
            await session.flush()
            await self._add_scope_rows(session, key_record.id, normalized_scopes)
            await session.commit()

        return api_key

    async def get_or_create_system_api_key(
        self,
        user_id: str,
        org_id: UUID,
        name: str,
        scopes: list[str] | None = None,
    ) -> str:
        """Get or create a system API key for a user on behalf of an internal service.

        If a key with the given name already exists for this user/org and is not expired,
        returns the existing key. Otherwise, creates a new key (and deletes any expired one).

        System keys are:
        - Not visible to users in their API keys list (filtered by name prefix)
        - Not deletable by users (protected by name prefix check)
        - Associated with a specific org (not the user's current org)
        - Never expire (no expiration date)

        Args:
            user_id: The ID of the user to create the key for
            org_id: The organization ID to associate the key with
            name: Required name for the key (will be prefixed with __SYSTEM__:)
            scopes: Optional opaque, namespaced scope strings. For a *new* key
                they are attached at creation. For an already-existing,
                non-expired key they are reconciled **additively** (missing rows
                are added; nothing is removed) so an internal caller can tighten
                an existing key — e.g. attach a ``openhands:role:member`` cap.
                Omitted/empty means the implicit ``full`` scope (no behavior
                change).

        Returns:
            The API key (existing or newly created)
        """
        # Create system key name with prefix
        system_key_name = self.make_system_key_name(name)
        normalized_scopes = self._normalize_scopes(scopes)

        async with a_session_maker() as session:
            # Check if key already exists for this user/org/name
            result = await session.execute(
                select(ApiKey).filter(
                    ApiKey.user_id == user_id,
                    ApiKey.org_id == org_id,
                    ApiKey.name == system_key_name,
                )
            )
            existing_key = result.scalars().first()

            if existing_key:
                # Check if expired
                if existing_key.expires_at:
                    now = datetime.now(UTC)
                    expires_at = existing_key.expires_at
                    if expires_at.tzinfo is None:
                        expires_at = expires_at.replace(tzinfo=UTC)

                    if expires_at < now:
                        # Key is expired, delete it and create new one
                        logger.info(
                            'System API key expired, re-issuing',
                            extra={
                                'user_id': user_id,
                                'org_id': str(org_id),
                                'key_name': system_key_name,
                            },
                        )
                        await session.delete(existing_key)
                        await session.commit()
                    else:
                        # Key exists and is not expired, return it (tightening
                        # any requested scopes onto it first).
                        logger.debug(
                            'Returning existing system API key',
                            extra={
                                'user_id': user_id,
                                'org_id': str(org_id),
                                'key_name': system_key_name,
                            },
                        )
                        await self._ensure_scope_rows(
                            session, existing_key.id, normalized_scopes
                        )
                        await session.commit()
                        return existing_key.key
                else:
                    # Key exists and has no expiration, return it (tightening
                    # any requested scopes onto it first).
                    logger.debug(
                        'Returning existing system API key',
                        extra={
                            'user_id': user_id,
                            'org_id': str(org_id),
                            'key_name': system_key_name,
                        },
                    )
                    await self._ensure_scope_rows(
                        session, existing_key.id, normalized_scopes
                    )
                    await session.commit()
                    return existing_key.key

        # Create new key (no expiration)
        api_key = self.generate_api_key()

        async with a_session_maker() as session:
            key_record = ApiKey(
                key=api_key,
                user_id=user_id,
                org_id=org_id,
                name=system_key_name,
                expires_at=None,  # System keys never expire
            )
            session.add(key_record)
            await session.flush()
            await self._add_scope_rows(session, key_record.id, normalized_scopes)
            await session.commit()

        logger.info(
            'Created system API key',
            extra={
                'user_id': user_id,
                'org_id': str(org_id),
                'key_name': system_key_name,
            },
        )

        return api_key

    async def validate_api_key(self, api_key: str) -> ApiKeyValidationResult | None:
        """Validate an API key and return the associated user_id and org_id if valid.

        Returns:
            ApiKeyValidationResult if the key is valid, None otherwise.
            The org_id may be None for legacy API keys that weren't bound to an organization.
        """
        now = datetime.now(UTC)

        async with a_session_maker() as session:
            result = await session.execute(select(ApiKey).filter(ApiKey.key == api_key))
            key_record = result.scalars().first()

            if not key_record:
                return None

            # expires_at is stored as naive UTC; re-attach tzinfo for comparison.
            if key_record.expires_at:
                expires_at = key_record.expires_at
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=UTC)

                if expires_at < now:
                    logger.info(f'API key has expired: {key_record.id}')
                    return None

            # Update last_used_at timestamp
            await session.execute(
                update(ApiKey)
                .where(ApiKey.id == key_record.id)
                .values(last_used_at=now.replace(tzinfo=None))
            )

            scopes = await self._load_scopes(session, key_record.id)
            await session.commit()

            return ApiKeyValidationResult(
                user_id=key_record.user_id,
                org_id=key_record.org_id,
                key_id=key_record.id,
                key_name=key_record.name,
                scopes=scopes,
            )

    async def delete_api_key(self, api_key: str) -> bool:
        """Delete an API key by the key value."""
        async with a_session_maker() as session:
            result = await session.execute(select(ApiKey).filter(ApiKey.key == api_key))
            key_record = result.scalars().first()

            if not key_record:
                return False

            await session.delete(key_record)
            await session.commit()

            return True

    async def delete_api_key_by_id(
        self, key_id: int, allow_system: bool = False
    ) -> bool:
        """Delete an API key by its ID.

        Args:
            key_id: The ID of the key to delete
            allow_system: If False (default), system keys cannot be deleted

        Returns:
            True if the key was deleted, False if not found or is a protected system key
        """
        async with a_session_maker() as session:
            result = await session.execute(select(ApiKey).filter(ApiKey.id == key_id))
            key_record = result.scalars().first()

            if not key_record:
                return False

            # Protect system keys from deletion unless explicitly allowed
            if self.is_system_key_name(key_record.name) and not allow_system:
                logger.warning(
                    'Attempted to delete system API key',
                    extra={'key_id': key_id, 'user_id': key_record.user_id},
                )
                return False

            await session.delete(key_record)
            await session.commit()

            return True

    async def list_api_keys(
        self, user_id: str, org_id: UUID | None = None
    ) -> list[ApiKey]:
        """List all user-visible API keys for a user in the given org.

        Args:
            user_id: User to list keys for.
            org_id: Explicit org to scope to. When omitted, falls back to
                the user's persisted ``current_org_id`` (legacy behavior).
                Request-context callers should pass the effective org id.

        This excludes:
        - System keys (name starts with __SYSTEM__:) - created by internal services
        - MCP_API_KEY - internal MCP key
        """
        if org_id is None:
            user = await UserStore.get_user_by_id(user_id)
            if user is None:
                raise ValueError(f'User not found: {user_id}')
            org_id = user.current_org_id

        async with a_session_maker() as session:
            result = await session.execute(
                select(ApiKey).filter(
                    ApiKey.user_id == user_id,
                    ApiKey.org_id == org_id,
                )
            )
            keys = result.scalars().all()
            # Filter out system keys and MCP_API_KEY
            return [
                key
                for key in keys
                if key.name != 'MCP_API_KEY' and not self.is_system_key_name(key.name)
            ]

    async def retrieve_mcp_api_key(
        self, user_id: str, org_id: UUID | None = None
    ) -> str | None:
        if org_id is None:
            user = await UserStore.get_user_by_id(user_id)
            if user is None:
                raise ValueError(f'User not found: {user_id}')
            org_id = user.current_org_id

        async with a_session_maker() as session:
            result = await session.execute(
                select(ApiKey).filter(
                    ApiKey.user_id == user_id, ApiKey.org_id == org_id
                )
            )
            keys = result.scalars().all()
            for key in keys:
                if key.name == 'MCP_API_KEY':
                    return key.key

        return None

    async def retrieve_api_key_by_name(self, user_id: str, name: str) -> str | None:
        """Retrieve an API key by name for a specific user."""
        async with a_session_maker() as session:
            result = await session.execute(
                select(ApiKey).filter(ApiKey.user_id == user_id, ApiKey.name == name)
            )
            key_record = result.scalars().first()
            return key_record.key if key_record else None

    async def delete_api_key_by_name(
        self,
        user_id: str,
        name: str,
        org_id: UUID | None = None,
        allow_system: bool = False,
    ) -> bool:
        """Delete an API key by name for a specific user.

        Args:
            user_id: The ID of the user whose key to delete
            name: The name of the key to delete
            org_id: Optional organization ID to filter by (required for system keys)
            allow_system: If False (default), system keys cannot be deleted

        Returns:
            True if the key was deleted, False if not found or is a protected system key
        """
        async with a_session_maker() as session:
            # Build the query filters
            filters = [ApiKey.user_id == user_id, ApiKey.name == name]
            if org_id is not None:
                filters.append(ApiKey.org_id == org_id)

            result = await session.execute(select(ApiKey).filter(*filters))
            key_record = result.scalars().first()

            if not key_record:
                return False

            # Protect system keys from deletion unless explicitly allowed
            if self.is_system_key_name(key_record.name) and not allow_system:
                logger.warning(
                    'Attempted to delete system API key',
                    extra={'user_id': user_id, 'key_name': name},
                )
                return False

            await session.delete(key_record)
            await session.commit()

            return True

    @classmethod
    def get_instance(cls) -> ApiKeyStore:
        """Get an instance of the ApiKeyStore."""
        logger.debug('api_key_store.get_instance')
        return ApiKeyStore()
