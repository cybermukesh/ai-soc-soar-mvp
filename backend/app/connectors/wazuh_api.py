import os

import httpx


def wazuh_configured() -> bool:
    return all(os.getenv(key) for key in ["WAZUH_API_URL", "WAZUH_API_USER", "WAZUH_API_PASSWORD"])


async def check_wazuh_health(
    timeout: float = 10.0,
    base_url: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> tuple[bool, str]:
    base_url = (base_url or os.getenv("WAZUH_API_URL", "")).rstrip("/")
    user = username or os.getenv("WAZUH_API_USER", "")
    password = password or os.getenv("WAZUH_API_PASSWORD", "")
    if not (base_url and user and password):
        missing = [key for key in ["WAZUH_API_URL", "WAZUH_API_USER", "WAZUH_API_PASSWORD"] if not os.getenv(key)]
        return False, f"missing credentials: {', '.join(missing) if missing else 'base_url/username/password'}"

    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
            token_response = await client.get(
                f"{base_url}/security/user/authenticate?raw=true",
                auth=(user, password),
            )
            token_response.raise_for_status()
            token = token_response.text.strip()
            if not token:
                return False, "empty token from wazuh auth"

            status_response = await client.get(
                f"{base_url}/manager/status?pretty=true",
                headers={"Authorization": f"Bearer {token}"},
            )
            status_response.raise_for_status()
            return True, "manager status reachable"
    except Exception as exc:
        return False, f"connectivity failed: {exc}"
