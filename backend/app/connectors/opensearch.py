import os
from typing import Any

import httpx


def opensearch_configured() -> bool:
    return all(os.getenv(key) for key in ["OPENSEARCH_URL", "OPENSEARCH_USER", "OPENSEARCH_PASSWORD"])


async def check_opensearch_health(
    timeout: float = 10.0,
    base_url: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> tuple[bool, str]:
    base_url = (base_url or os.getenv("OPENSEARCH_URL", "")).rstrip("/")
    username = username or os.getenv("OPENSEARCH_USER", "")
    password = password or os.getenv("OPENSEARCH_PASSWORD", "")
    if not (base_url and username and password):
        missing = [key for key in ["OPENSEARCH_URL", "OPENSEARCH_USER", "OPENSEARCH_PASSWORD"] if not os.getenv(key)]
        return False, f"missing credentials: {', '.join(missing) if missing else 'base_url/username/password'}"
    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
            response = await client.get(
                f"{base_url}/_cluster/health",
                auth=(username, password),
            )
            if response.status_code == 403:
                index = os.getenv("OPENSEARCH_ALERT_INDEX", "wazuh-alerts-*")
                probe = await client.post(
                    f"{base_url}/{index}/_search",
                    auth=(username, password),
                    json={"size": 0, "query": {"match_all": {}}},
                )
                probe.raise_for_status()
                return True, "alerts index reachable; cluster health forbidden for read-only user"
            response.raise_for_status()
            payload = response.json()
            status = str(payload.get("status", "unknown"))
            return True, f"cluster={status}"
    except Exception as exc:
        return False, f"connectivity failed: {exc}"


async def fetch_recent_wazuh_alerts(
    limit: int = 25,
    base_url: str | None = None,
    username: str | None = None,
    password: str | None = None,
    index: str | None = None,
) -> dict[str, Any]:
    base_url = (base_url or os.getenv("OPENSEARCH_URL", "")).rstrip("/")
    username = username or os.getenv("OPENSEARCH_USER", "")
    password = password or os.getenv("OPENSEARCH_PASSWORD", "")
    if not (base_url and username and password):
        missing = [key for key in ["OPENSEARCH_URL", "OPENSEARCH_USER", "OPENSEARCH_PASSWORD"] if not os.getenv(key)]
        raise RuntimeError(f"OpenSearch credentials not configured: {', '.join(missing) if missing else 'base_url, username, password'}")

    index = index or os.getenv("OPENSEARCH_ALERT_INDEX", "wazuh-alerts-*")
    payload = {"size": limit, "sort": [{"timestamp": {"order": "desc"}}], "query": {"match_all": {}}}

    async with httpx.AsyncClient(verify=False, timeout=20) as client:
        response = await client.post(
            f"{base_url}/{index}/_search",
            auth=(username, password),
            json=payload,
        )
        response.raise_for_status()
        return response.json()
