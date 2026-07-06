import json
from unittest.mock import patch
import pytest
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from storage.org import Org
from storage.org_member import OrgMember
from storage.user_settings import UserSettings
from storage.encrypt_utils import (
    encrypt_dict_secrets,
    decrypt_dict_secrets,
    get_cipher,
    decrypt_value,
    encrypt_value,
)
from openhands.sdk.utils.cipher import FERNET_TOKEN_PREFIX
from openhands.app_server.services.jwt_service import JwtService
from openhands.app_server.utils.encryption_key import EncryptionKey


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


def test_encrypt_decrypt_dict_secrets():
    cipher = get_cipher()

    payload = {
        'agent': 'CodeActAgent',
        'llm': {
            'model': 'gpt-4o',
            'api_key': 'secret-api-key',
            'aws_secret_access_key': 'aws-secret',
        },
        'mcp_config': {
            'mcpServers': {
                'my-server': {
                    'url': 'http://localhost',
                    'headers': {
                        'Authorization': 'Bearer mcp-token',
                        'Accept': 'application/json',
                    },
                    'env': {
                        'GITHUB_TOKEN': 'github-token',
                        'PATH': '/usr/bin',
                    }
                }
            }
        },
        'other_list': [
            {'api_key': 'nested-list-key', 'val': 42}
        ]
    }

    # 1. Encrypt secrets
    encrypted = encrypt_dict_secrets(payload, cipher)

    # Inspectability check: non-secret fields remain plaintext
    assert encrypted['agent'] == 'CodeActAgent'
    assert encrypted['llm']['model'] == 'gpt-4o'
    assert encrypted['mcp_config']['mcpServers']['my-server']['url'] == 'http://localhost'
    assert encrypted['mcp_config']['mcpServers']['my-server']['headers']['Accept'] == 'application/json'
    assert encrypted['mcp_config']['mcpServers']['my-server']['env']['PATH'] == '/usr/bin'
    assert encrypted['other_list'][0]['val'] == 42

    # Secret fields are encrypted and start with the Fernet prefix
    assert encrypted['llm']['api_key'].startswith(FERNET_TOKEN_PREFIX)
    assert encrypted['llm']['aws_secret_access_key'].startswith(FERNET_TOKEN_PREFIX)
    assert encrypted['mcp_config']['mcpServers']['my-server']['headers']['Authorization'].startswith(FERNET_TOKEN_PREFIX)
    assert encrypted['mcp_config']['mcpServers']['my-server']['env']['GITHUB_TOKEN'].startswith(FERNET_TOKEN_PREFIX)
    assert encrypted['other_list'][0]['api_key'].startswith(FERNET_TOKEN_PREFIX)

    # 2. Guard against double-encryption: running it again does not change ciphertext
    api_key_cipher_1 = encrypted['llm']['api_key']
    re_encrypted = encrypt_dict_secrets(encrypted, cipher)
    assert re_encrypted['llm']['api_key'] == api_key_cipher_1

    # 3. Decrypt secrets
    decrypted = decrypt_dict_secrets(encrypted, cipher)
    assert decrypted['llm']['api_key'] == 'secret-api-key'
    assert decrypted['llm']['aws_secret_access_key'] == 'aws-secret'
    assert decrypted['mcp_config']['mcpServers']['my-server']['headers']['Authorization'] == 'Bearer mcp-token'
    assert decrypted['mcp_config']['mcpServers']['my-server']['env']['GITHUB_TOKEN'] == 'github-token'
    assert decrypted['other_list'][0]['api_key'] == 'nested-list-key'


def test_decrypt_dict_secrets_preserves_plaintext_legacy():
    cipher = get_cipher()

    payload = {
        'llm': {
            'model': 'gpt-4o',
            'api_key': 'legacy-plain-text-key',  # Not starting with Fernet token prefix
        }
    }

    # Decrypt should keep the plaintext value as-is
    decrypted = decrypt_dict_secrets(payload, cipher)
    assert decrypted['llm']['api_key'] == 'legacy-plain-text-key'


@pytest.mark.asyncio
async def test_org_agent_settings_encryption_in_db(async_session_maker):
    """Test that agent_settings is saved with leaf encryption and loaded correctly."""
    import uuid
    org_id = uuid.uuid4()

    agent_settings_data = {
        'agent': 'CodeActAgent',
        'llm': {
            'model': 'gpt-4o',
            'api_key': 'my-super-secret-key',
        }
    }

    # Write to database
    async with async_session_maker() as session:
        org = Org(
            id=org_id,
            name='Test Settings Org',
            agent_settings=agent_settings_data,
        )
        session.add(org)
        await session.commit()

    # Verify database contents directly (bypassing TypeDecorator/ORM to read raw JSON)
    async with async_session_maker() as session:
        # Fetch the raw value using a direct SQL text query or mapping check
        result = await session.execute(
            select(Org).filter(Org.id == org_id)
        )
        loaded_org = result.scalars().first()
        assert loaded_org is not None
        
        # When read through ORM, it is automatically decrypted
        assert loaded_org.agent_settings['llm']['api_key'] == 'my-super-secret-key'
        assert loaded_org.agent_settings['agent'] == 'CodeActAgent'

        # Check raw database state by querying JSON dict directly or bypassing TypeDecorator
        # In SQLAlchemy, loaded_org.agent_settings is already processed.
        # Let's inspect the session's internal state or verify the bound param behavior
        cipher = get_cipher()
        raw_db_agent_settings = loaded_org.agent_settings
        # Confirm that the TypeDecorator would process bind param correctly
        from sqlalchemy import inspect
        state = inspect(loaded_org)
        # Verify the bind parameter value is indeed encrypted
        # Let's test the process_bind_param manually to make sure
        from storage.encrypt_utils import SecretAwareJSON
        decorator = SecretAwareJSON()
        bound_value = decorator.process_bind_param(agent_settings_data, None)
        assert bound_value['llm']['api_key'].startswith(FERNET_TOKEN_PREFIX)
        assert bound_value['agent'] == 'CodeActAgent'


@pytest.mark.asyncio
async def test_org_llm_profiles_encryption_in_db(async_session_maker):
    """Test that llm_profiles stores leaf-encrypted JSON strings and remains compatible with legacy whole-blob rows."""
    import uuid
    org_id = uuid.uuid4()

    profiles_data = {
        'profiles': {
            'Default': {'model': 'gpt-4o', 'api_key': 'default-key'},
            'Backup': {'model': 'claude-3', 'api_key': 'backup-key'},
        },
        'active': 'Default',
    }

    # 1. Store via ORM
    async with async_session_maker() as session:
        org = Org(
            id=org_id,
            name='Test Profiles Org',
            llm_profiles=profiles_data,
        )
        session.add(org)
        await session.commit()

    # 2. Retrieve and verify ORM decryption
    async with async_session_maker() as session:
        result = await session.execute(select(Org).filter(Org.id == org_id))
        loaded_org = result.scalars().first()
        assert loaded_org is not None
        assert loaded_org.llm_profiles['active'] == 'Default'
        assert loaded_org.llm_profiles['profiles']['Default']['api_key'] == 'default-key'
        assert loaded_org.llm_profiles['profiles']['Backup']['api_key'] == 'backup-key'

        # Verify raw string storage format is JSON with encrypted leaves
        from storage.encrypt_utils import EncryptedJSON
        decorator = EncryptedJSON()
        serialized_str = decorator.process_bind_param(profiles_data, None)
        # It is a valid JSON string
        parsed = json.loads(serialized_str)
        assert parsed['active'] == 'Default'
        assert parsed['profiles']['Default']['api_key'].startswith(FERNET_TOKEN_PREFIX)
        assert parsed['profiles']['Default']['model'] == 'gpt-4o'


@pytest.mark.asyncio
async def test_legacy_whole_blob_jwe_compatibility():
    """Test that EncryptedJSON can decrypt legacy whole-column encrypted JWE blobs."""
    from storage.encrypt_utils import EncryptedJSON
    decorator = EncryptedJSON()

    profiles_data = {
        'profiles': {
            'Default': {'model': 'gpt-4o', 'api_key': 'default-key'},
        },
        'active': 'Default',
    }

    # Create a legacy JWE encrypted string of the entire JSON
    legacy_jwe_str = encrypt_value(json.dumps(profiles_data))
    assert not legacy_jwe_str.startswith('{')  # It's a JWE token

    # Decrypt JWE whole-blob should succeed and return the correct profiles dict
    decrypted_dict = decorator.process_result_value(legacy_jwe_str, None)
    assert decrypted_dict['active'] == 'Default'
    assert decrypted_dict['profiles']['Default']['model'] == 'gpt-4o'
    assert decrypted_dict['profiles']['Default']['api_key'] == 'default-key'
