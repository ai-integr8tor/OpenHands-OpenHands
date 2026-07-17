"""Store class for managing user authorizations."""

import os
from typing import Optional

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from storage.database import a_session_maker
from storage.user_authorization import UserAuthorization, UserAuthorizationType


class UserAuthorizationStore:
    """Store for managing user authorization rules."""

    @staticmethod
    async def _get_matching_authorizations(
        email: str,
        provider_type: str | None,
        session: AsyncSession,
    ) -> list[UserAuthorization]:
        """Get all authorization rules that match the given email and provider.

        Uses SQL LIKE for pattern matching:
        - email_pattern is NULL matches all emails
        - provider_type is NULL matches all providers
        - email LIKE email_pattern for pattern matching

        Args:
            email: The user's email address
            provider_type: The identity provider type (e.g., 'github', 'gitlab')
            session: Database session

        Returns:
            List of matching UserAuthorization objects
        """
        # Build query using SQLAlchemy ORM
        # We need: (email_pattern IS NULL OR LOWER(email) LIKE LOWER(email_pattern))
        #      AND (provider_type IS NULL OR provider_type = :provider_type)
        email_condition = or_(
            UserAuthorization.email_pattern.is_(None),
            func.lower(email).like(func.lower(UserAuthorization.email_pattern)),
        )
        provider_condition = or_(
            UserAuthorization.provider_type.is_(None),
            UserAuthorization.provider_type == provider_type,
        )

        query = select(UserAuthorization).where(email_condition, provider_condition)
        result = await session.execute(query)
        return list(result.scalars().all())

    @staticmethod
    async def get_matching_authorizations(
        email: str,
        provider_type: str | None,
        session: Optional[AsyncSession] = None,
    ) -> list[UserAuthorization]:
        """Get all authorization rules that match the given email and provider.

        Args:
            email: The user's email address
            provider_type: The identity provider type (e.g., 'github', 'gitlab')
            session: Optional database session

        Returns:
            List of matching UserAuthorization objects
        """
        if session is not None:
            return await UserAuthorizationStore._get_matching_authorizations(
                email, provider_type, session
            )
        async with a_session_maker() as new_session:
            return await UserAuthorizationStore._get_matching_authorizations(
                email, provider_type, new_session
            )

    @staticmethod
    async def get_authorization_type(
        email: str,
        provider_type: str | None,
        session: Optional[AsyncSession] = None,
    ) -> UserAuthorizationType | None:
        """Get the authorization type for the given email and provider.

        Checks matching authorization rules and returns the effective authorization
        type. Whitelist rules take precedence over blacklist rules.

        Args:
            email: The user's email address
            provider_type: The identity provider type (e.g., 'github', 'gitlab')
            session: Optional database session

        Returns:
            UserAuthorizationType.WHITELIST if a whitelist rule matches,
            UserAuthorizationType.BLACKLIST if a blacklist rule matches (and no whitelist),
            None if no rules match
        """
        authorizations = await UserAuthorizationStore.get_matching_authorizations(
            email, provider_type, session
        )

        has_whitelist = any(
            auth.type == UserAuthorizationType.WHITELIST.value
            for auth in authorizations
        )
        if has_whitelist:
            return UserAuthorizationType.WHITELIST

        has_blacklist = any(
            auth.type == UserAuthorizationType.BLACKLIST.value
            for auth in authorizations
        )
        if has_blacklist:
            return UserAuthorizationType.BLACKLIST

        return None

    @staticmethod
    async def _create_authorization(
        email_pattern: str | None,
        provider_type: str | None,
        auth_type: UserAuthorizationType,
        session: AsyncSession,
    ) -> UserAuthorization:
        """Create a new user authorization rule."""
        authorization = UserAuthorization(
            email_pattern=email_pattern,
            provider_type=provider_type,
            type=auth_type.value,
        )
        session.add(authorization)
        await session.flush()
        await session.refresh(authorization)
        return authorization

    @staticmethod
    async def create_authorization(
        email_pattern: str | None,
        provider_type: str | None,
        auth_type: UserAuthorizationType,
        session: Optional[AsyncSession] = None,
    ) -> UserAuthorization:
        """Create a new user authorization rule.

        Args:
            email_pattern: SQL LIKE pattern for email matching (e.g., '%@openhands.dev')
            provider_type: Provider type to match (e.g., 'github'), or None for all
            auth_type: WHITELIST or BLACKLIST
            session: Optional database session

        Returns:
            The created UserAuthorization object
        """
        if session is not None:
            return await UserAuthorizationStore._create_authorization(
                email_pattern, provider_type, auth_type, session
            )
        async with a_session_maker() as new_session:
            auth = await UserAuthorizationStore._create_authorization(
                email_pattern, provider_type, auth_type, new_session
            )
            await new_session.commit()
            return auth

    @staticmethod
    async def _delete_authorization(
        authorization_id: int,
        session: AsyncSession,
    ) -> bool:
        """Delete an authorization rule by ID."""
        result = await session.execute(
            select(UserAuthorization).where(UserAuthorization.id == authorization_id)
        )
        authorization = result.scalars().first()
        if authorization:
            await session.delete(authorization)
            return True
        return False

    @staticmethod
    async def delete_authorization(
        authorization_id: int,
        session: Optional[AsyncSession] = None,
    ) -> bool:
        """Delete an authorization rule by ID.

        Args:
            authorization_id: The ID of the authorization to delete
            session: Optional database session

        Returns:
            True if deleted, False if not found
        """
        if session is not None:
            return await UserAuthorizationStore._delete_authorization(
                authorization_id, session
            )
        async with a_session_maker() as new_session:
            deleted = await UserAuthorizationStore._delete_authorization(
                authorization_id, new_session
            )
            if deleted:
                await new_session.commit()
            return deleted

    @staticmethod
    async def _get_authorization_by_pattern(
        email_pattern: str | None,
        auth_type: UserAuthorizationType,
        session: AsyncSession,
    ) -> UserAuthorization | None:
        """Get an authorization rule by email pattern and type.

        Args:
            email_pattern: The email pattern to match
            auth_type: The authorization type (whitelist/blacklist)
            session: Database session

        Returns:
            The matching UserAuthorization or None
        """
        result = await session.execute(
            select(UserAuthorization).where(
                UserAuthorization.email_pattern == email_pattern,
                UserAuthorization.type == auth_type.value,
            )
        )
        return result.scalars().first()

    @staticmethod
    async def get_authorization_by_pattern(
        email_pattern: str | None,
        auth_type: UserAuthorizationType,
        session: Optional[AsyncSession] = None,
    ) -> UserAuthorization | None:
        """Get an authorization rule by email pattern and type.

        Args:
            email_pattern: The email pattern to match
            auth_type: The authorization type (whitelist/blacklist)
            session: Optional database session

        Returns:
            The matching UserAuthorization or None
        """
        if session is not None:
            return await UserAuthorizationStore._get_authorization_by_pattern(
                email_pattern, auth_type, session
            )
        async with a_session_maker() as new_session:
            return await UserAuthorizationStore._get_authorization_by_pattern(
                email_pattern, auth_type, new_session
            )

    @staticmethod
    async def _upsert_authorization(
        email_pattern: str | None,
        provider_type: str | None,
        auth_type: UserAuthorizationType,
        session: AsyncSession,
    ) -> UserAuthorization:
        """Insert or update a user authorization rule.

        If a rule with the same email_pattern and auth_type exists, do nothing.
        Otherwise, create a new rule.

        Args:
            email_pattern: SQL LIKE pattern for email matching
            provider_type: Provider type to match, or None for all
            auth_type: WHITELIST or BLACKLIST
            session: Database session

        Returns:
            The existing or newly created UserAuthorization
        """
        existing = await UserAuthorizationStore._get_authorization_by_pattern(
            email_pattern, auth_type, session
        )
        if existing:
            return existing

        authorization = UserAuthorization(
            email_pattern=email_pattern,
            provider_type=provider_type,
            type=auth_type.value,
        )
        session.add(authorization)
        await session.flush()
        await session.refresh(authorization)
        return authorization

    @staticmethod
    async def upsert_authorization(
        email_pattern: str | None,
        provider_type: str | None,
        auth_type: UserAuthorizationType,
        session: Optional[AsyncSession] = None,
    ) -> UserAuthorization:
        """Insert or update a user authorization rule.

        If a rule with the same email_pattern and auth_type exists, do nothing.
        Otherwise, create a new rule.

        Args:
            email_pattern: SQL LIKE pattern for email matching
            provider_type: Provider type to match, or None for all
            auth_type: WHITELIST or BLACKLIST
            session: Optional database session

        Returns:
            The existing or newly created UserAuthorization
        """
        if session is not None:
            return await UserAuthorizationStore._upsert_authorization(
                email_pattern, provider_type, auth_type, session
            )
        async with a_session_maker() as new_session:
            auth = await UserAuthorizationStore._upsert_authorization(
                email_pattern, provider_type, auth_type, new_session
            )
            await new_session.commit()
            return auth

    @staticmethod
    async def _get_all_patterns_by_type(
        auth_type: UserAuthorizationType,
        session: AsyncSession,
    ) -> list[UserAuthorization]:
        """Get all authorization rules of a specific type.

        Args:
            auth_type: The authorization type to filter by
            session: Database session

        Returns:
            List of matching UserAuthorization objects
        """
        result = await session.execute(
            select(UserAuthorization).where(
                UserAuthorization.type == auth_type.value
            )
        )
        return list(result.scalars().all())

    @staticmethod
    async def get_all_patterns_by_type(
        auth_type: UserAuthorizationType,
        session: Optional[AsyncSession] = None,
    ) -> list[UserAuthorization]:
        """Get all authorization rules of a specific type.

        Args:
            auth_type: The authorization type to filter by
            session: Optional database session

        Returns:
            List of matching UserAuthorization objects
        """
        if session is not None:
            return await UserAuthorizationStore._get_all_patterns_by_type(
                auth_type, session
            )
        async with a_session_maker() as new_session:
            return await UserAuthorizationStore._get_all_patterns_by_type(
                auth_type, new_session
            )

    @staticmethod
    async def reconcile_from_environment() -> dict[str, int]:
        """Reconcile user_authorizations table with environment variables.

        Reads EMAIL_PATTERN_BLACKLIST and EMAIL_PATTERN_WHITELIST from environment
        and ensures all patterns exist in the database. This is idempotent and can
        be called on every startup to ensure env var changes propagate.

        Returns:
            Dict with counts of 'whitelists_added' and 'blacklists_added'
        """
        blacklist_patterns = os.environ.get('EMAIL_PATTERN_BLACKLIST', '').strip()
        whitelist_patterns = os.environ.get('EMAIL_PATTERN_WHITELIST', '').strip()

        stats = {'whitelists_added': 0, 'blacklists_added': 0}

        async with a_session_maker() as session:
            # Upsert blacklist patterns
            if blacklist_patterns:
                for pattern in blacklist_patterns.split(','):
                    pattern = pattern.strip()
                    if pattern:
                        await UserAuthorizationStore._upsert_authorization(
                            email_pattern=pattern,
                            provider_type=None,
                            auth_type=UserAuthorizationType.BLACKLIST,
                            session=session,
                        )
                        stats['blacklists_added'] += 1

            # Upsert whitelist patterns
            if whitelist_patterns:
                for pattern in whitelist_patterns.split(','):
                    pattern = pattern.strip()
                    if pattern:
                        await UserAuthorizationStore._upsert_authorization(
                            email_pattern=pattern,
                            provider_type=None,
                            auth_type=UserAuthorizationType.WHITELIST,
                            session=session,
                        )
                        stats['whitelists_added'] += 1

            await session.commit()

        return stats
