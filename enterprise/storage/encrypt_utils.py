import copy
import binascii
import hashlib
import json
from base64 import b64decode, b64encode
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel, SecretStr
from sqlalchemy import JSON, String, TypeDecorator
from sqlalchemy.engine.interfaces import Dialect

_jwt_service = None
_fernet = None


def encrypt_value(value: str | SecretStr) -> str:
    raw = value.get_secret_value() if isinstance(value, SecretStr) else value
    return get_jwt_service().encrypt_value(raw)


def decrypt_value(value: str | SecretStr) -> str:
    raw = value.get_secret_value() if isinstance(value, SecretStr) else value
    return get_jwt_service().decrypt_value(raw)


def get_jwt_service():
    from openhands.app_server.config import get_global_config

    global _jwt_service
    if _jwt_service is None:
        jwt_service_injector = get_global_config().jwt
        assert jwt_service_injector is not None
        _jwt_service = jwt_service_injector.get_jwt_service()
    return _jwt_service


def get_cipher():
    from openhands.sdk.utils.cipher import Cipher
    jwt_svc = get_jwt_service()
    default_key = jwt_svc.get_key(jwt_svc._default_key_id)
    secret = default_key.key.get_secret_value()
    return Cipher(secret)


def encrypt_dict_secrets(data: Any, cipher) -> Any:
    from openhands.sdk.utils.redact import is_secret_key
    from openhands.sdk.utils.cipher import FERNET_TOKEN_PREFIX
    if isinstance(data, dict):
        result = {}
        for k, v in data.items():
            if is_secret_key(k) and isinstance(v, str):
                if v.startswith(FERNET_TOKEN_PREFIX):
                    result[k] = v
                else:
                    encrypted = cipher.encrypt(SecretStr(v))
                    result[k] = encrypted
            else:
                result[k] = encrypt_dict_secrets(v, cipher)
        return result
    elif isinstance(data, list):
        return [encrypt_dict_secrets(item, cipher) for item in data]
    return data


def decrypt_dict_secrets(data: Any, cipher) -> Any:
    from openhands.sdk.utils.redact import is_secret_key
    from openhands.sdk.utils.cipher import FERNET_TOKEN_PREFIX
    if isinstance(data, dict):
        result = {}
        for k, v in data.items():
            if is_secret_key(k) and isinstance(v, str):
                if v.startswith(FERNET_TOKEN_PREFIX):
                    decrypted = cipher.try_decrypt_str(v)
                    result[k] = decrypted if decrypted is not None else v
                else:
                    result[k] = v
            else:
                result[k] = decrypt_dict_secrets(v, cipher)
        return result
    elif isinstance(data, list):
        return [decrypt_dict_secrets(item, cipher) for item in data]
    return data


def decrypt_legacy_model(decrypt_keys: list, model_instance) -> dict:
    return decrypt_legacy_kwargs(decrypt_keys, model_to_kwargs(model_instance))


def decrypt_legacy_kwargs(encrypt_keys: list, kwargs: dict) -> dict:
    for key, value in kwargs.items():
        try:
            if value is None:
                continue
            if key in encrypt_keys:
                value = decrypt_legacy_value(value)
                kwargs[key] = value
        except binascii.Error:
            pass  # Key is in legacy format...
        except InvalidToken:
            pass  # Key not encrypted...
    return kwargs


def decrypt_legacy_value(value: str | SecretStr) -> str:
    if isinstance(value, SecretStr):
        return (
            get_fernet().decrypt(b64decode(value.get_secret_value().encode())).decode()
        )
    else:
        return get_fernet().decrypt(b64decode(value.encode())).decode()


def encrypt_legacy_value(value: str | SecretStr) -> str:
    if isinstance(value, SecretStr):
        return b64encode(
            get_fernet().encrypt(value.get_secret_value().encode())
        ).decode()
    else:
        return b64encode(get_fernet().encrypt(value.encode())).decode()


def get_fernet():
    global _fernet
    if _fernet is None:
        jwt_svc = get_jwt_service()
        default_key = jwt_svc.get_key(jwt_svc._default_key_id)
        secret = default_key.key.get_secret_value()
        fernet_key = b64encode(hashlib.sha256(secret.encode()).digest())
        _fernet = Fernet(fernet_key)
    return _fernet


def model_to_kwargs(model_instance):
    return {
        column.name: getattr(model_instance, column.name)
        for column in model_instance.__table__.columns
    }


class SecretAwareJSON(TypeDecorator[dict[str, Any]]):
    """JSON column whose secret fields (leaves) are encrypted at rest.

    Compatible with legacy whole-column encrypted JWE blobs (if it is a JWE token).
    """

    impl = JSON
    cache_ok = True

    def process_bind_param(
        self, value: BaseModel | dict[str, Any] | None, dialect: Dialect
    ) -> Any:
        if value is None:
            return None
        if isinstance(value, BaseModel):
            value = value.model_dump(mode='json', context={'expose_secrets': True})
        else:
            value = copy.deepcopy(value)
        cipher = get_cipher()
        return encrypt_dict_secrets(value, cipher)

    def process_result_value(
        self, value: Any, dialect: Dialect
    ) -> dict[str, Any] | None:
        if value is None:
            return None

        # Handle legacy whole-column encrypted JWE blobs
        if isinstance(value, str):
            try:
                decrypted = decrypt_value(value)
                value = json.loads(decrypted)
            except Exception:
                try:
                    value = json.loads(value)
                except Exception:
                    pass

        cipher = get_cipher()
        return decrypt_dict_secrets(value, cipher)


class EncryptedJSON(TypeDecorator[dict[str, Any]]):
    """String column whose payload is a JSON dict with encrypted secret leaves.

    Matches sa.String underlying type to preserve compatibility with existing
    sa.String columns (e.g. llm_profiles) without database alter migration.
    Supports reading legacy JWE-encrypted whole columns and new leaf-encrypted JSON strings.
    """

    impl = String
    cache_ok = True

    def process_bind_param(
        self, value: BaseModel | dict[str, Any] | None, dialect: Dialect
    ) -> str | None:
        if value is None:
            return None
        if isinstance(value, BaseModel):
            value = value.model_dump(mode='json', context={'expose_secrets': True})
        else:
            value = copy.deepcopy(value)
        cipher = get_cipher()
        encrypted = encrypt_dict_secrets(value, cipher)
        return json.dumps(encrypted)

    def process_result_value(
        self, value: str | None, dialect: Dialect
    ) -> dict[str, Any] | None:
        if value is None:
            return None

        # Handle legacy whole-column encrypted JWE blobs or leaf-encrypted JSON string
        try:
            decrypted = decrypt_value(value)
            value_dict = json.loads(decrypted)
        except Exception:
            try:
                value_dict = json.loads(value)
            except Exception:
                return None

        cipher = get_cipher()
        return decrypt_dict_secrets(value_dict, cipher)
