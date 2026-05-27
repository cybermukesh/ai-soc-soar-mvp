import os
from typing import Any

import httpx


def opensearch_configured() -> bool:
    return all(os.getenv(key) for key in ["OPENSEARCH_URL", "OPENSEARCH_USER", "OPENSEARCH_PASSWORD"])


async def fetch_recent_wazuh_alerts(limit: int = 25) -> dict[str, Any]:
    if not opensearch_configured():
        missing = [key for key in ["OPENSEARCH_URL", "OPENSEARCH_USER", "OPENSEARCH_PASSWORD"] if not os.getenv(key)]
        raise RuntimeError(f"OpenSearch credentials not configured: {', '.join(missing)}")

    base_url = os.environ["OPENSEARCH_URL"].rstrip("/")
    index = os.getenv("OPENSEARCH_ALERT_INDEX", "wazuh-alerts-*")
    payload = {"size": limit, "sort": [{"timestamp": {"order": "desc"}}], "query": {"match_all": {}}}

    async with httpx.AsyncClient(verify=False, timeout=20) as client:
        response = await client.post(
            f"{base_url}/{index}/_search",
            auth=(os.environ["OPENSEARCH_USER"], os.environ["OPENSEARCH_PASSWORD"]),
            json=payload,
        )
        response.raise_for_status()
        return response.json()
