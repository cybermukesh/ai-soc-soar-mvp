import base64

from app.core.settings import settings


def _key_bytes() -> bytes:
    return settings.jwt_secret.encode("utf-8")


def encrypt_secret(value: str) -> str:
    if not value:
        return ""
    data = value.encode("utf-8")
    key = _key_bytes()
    obfuscated = bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
    return base64.urlsafe_b64encode(obfuscated).decode("utf-8")


def decrypt_secret(value: str) -> str:
    if not value:
        return ""
    raw = base64.urlsafe_b64decode(value.encode("utf-8"))
    key = _key_bytes()
    plain = bytes([b ^ key[i % len(key)] for i, b in enumerate(raw)])
    return plain.decode("utf-8")
