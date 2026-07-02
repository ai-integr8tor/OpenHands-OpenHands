"""SAAS-specific user models that extend OSS UserInfo with organization fields."""

from pydantic import BaseModel

from openhands.app_server.integrations.service_types import ProviderType
from openhands.app_server.user.user_models import UserInfo


class SaasUserInfo(UserInfo):
    """User info model for SAAS mode with organization context.

    Extends the base UserInfo with SAAS-specific fields for organization
    membership, role, and permissions.
    """

    org_id: str | None = None
    org_name: str | None = None
    role: str | None = None
    permissions: list[str] | None = None
    # Opaque, namespaced scope strings carried by the API/session key used for
    # this request. None for non-API-key (e.g. cookie) auth. Resource servers
    # use this to enforce reduced-privilege credentials; OpenHands does not
    # interpret the strings.
    api_key_scopes: list[str] | None = None


class GitOrganizationsResponse(BaseModel):
    """Response model for the Git organizations the user belongs to on their active provider."""

    provider: ProviderType
    organizations: list[str]
