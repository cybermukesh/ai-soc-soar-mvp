import base64
import ipaddress
import json
import re
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from app.db.models import ThreatIntelProviderSetting
from app.models.alert import NormalizedAlert
from app.services.crypto import decrypt_secret


DEFAULT_BASE_URLS = {
    "virustotal": "https://www.virustotal.com/api/v3",
    "abuseipdb": "https://api.abuseipdb.com/api/v2",
    "otx": "https://otx.alienvault.com/api/v1",
}

HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _domain_allowed(value: str) -> bool:
    value = value.lower().strip(".")
    if not value or len(value) > 253:
        return False
    blocked_suffixes = (".local", ".internal", ".lan", ".corp", ".home", ".test", ".invalid")
    return "." in value and not value.endswith(blocked_suffixes)


def extract_external_indicators(alert: NormalizedAlert) -> dict[str, list[str]]:
    raw_text = json.dumps(alert.raw_event, default=str)
    urls = sorted({match.rstrip(").,]") for match in URL_RE.findall(raw_text)})[:5]
    url_domains = {
        parsed.netloc.lower().split("@")[-1].split(":")[0]
        for parsed in (urlparse(url) for url in urls)
        if parsed.netloc
    }
    candidate_domains = {
        alert.asset.hostname,
        *DOMAIN_RE.findall(raw_text),
        *url_domains,
    }
    domains = sorted({domain.lower().strip(".") for domain in candidate_domains if _domain_allowed(domain)})[:5]
    ips = sorted(
        {
            ip
            for ip in (alert.network.src_ip, alert.network.dst_ip, alert.asset.ip)
            if ip and _is_public_ip(ip)
        }
    )[:5]
    hashes = sorted({match.lower() for match in HASH_RE.findall(raw_text)})[:5]
    return {"ips": ips, "domains": domains, "hashes": hashes, "urls": urls}


def _severity_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 20:
        return "medium"
    if score > 0:
        return "low"
    return "none"


async def _get_json(
    client: httpx.AsyncClient,
    url: str,
    *,
    headers: dict[str, str],
    params: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    response = await client.get(url, headers=headers, params=params)
    if response.status_code == 404:
        return 404, {}
    response.raise_for_status()
    return response.status_code, response.json()


async def _post_json(
    client: httpx.AsyncClient,
    url: str,
    *,
    headers: dict[str, str],
    payload: dict[str, Any],
) -> tuple[int, dict[str, Any]]:
    response = await client.post(url, headers=headers, json=payload)
    if response.status_code == 404:
        return 404, {}
    response.raise_for_status()
    return response.status_code, response.json()


async def _virustotal_lookup(
    client: httpx.AsyncClient,
    base_url: str,
    api_key: str,
    indicators: dict[str, list[str]],
) -> dict[str, Any]:
    headers = {"x-apikey": api_key}
    matches = []
    for indicator_type, endpoint, values in (
        ("ip", "ip_addresses", indicators["ips"][:3]),
        ("domain", "domains", indicators["domains"][:3]),
        ("hash", "files", indicators["hashes"][:3]),
    ):
        for value in values:
            status, body = await _get_json(
                client, f"{base_url.rstrip('/')}/{endpoint}/{value}", headers=headers
            )
            if status == 404:
                matches.append(
                    {"indicator": value, "type": indicator_type, "found": False, "severity": "none"}
                )
                continue
            attrs = body.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0) or 0)
            suspicious = int(stats.get("suspicious", 0) or 0)
            score = min(100, malicious * 25 + suspicious * 10)
            matches.append(
                {
                    "indicator": value,
                    "type": indicator_type,
                    "found": True,
                    "severity": _severity_from_score(score),
                    "score": score,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "reputation": attrs.get("reputation", 0),
                    "summary": attrs.get("as_owner") or attrs.get("meaningful_name") or "",
                }
            )
    for value in indicators["urls"][:2]:
        url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        status, body = await _get_json(client, f"{base_url.rstrip('/')}/urls/{url_id}", headers=headers)
        if status == 404:
            matches.append({"indicator": value, "type": "url", "found": False, "severity": "none"})
            continue
        attrs = body.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        score = min(100, malicious * 25 + suspicious * 10)
        matches.append(
            {
                "indicator": value,
                "type": "url",
                "found": True,
                "severity": _severity_from_score(score),
                "score": score,
                "malicious": malicious,
                "suspicious": suspicious,
                "summary": attrs.get("title") or attrs.get("url") or "",
            }
        )
    return {"provider": "virustotal", "ok": True, "matches": matches}


async def _abuseipdb_lookup(
    client: httpx.AsyncClient,
    base_url: str,
    api_key: str,
    indicators: dict[str, list[str]],
) -> dict[str, Any]:
    headers = {"Key": api_key, "Accept": "application/json"}
    matches = []
    for value in indicators["ips"][:5]:
        status, body = await _get_json(
            client,
            f"{base_url.rstrip('/')}/check",
            headers=headers,
            params={"ipAddress": value, "maxAgeInDays": 90, "verbose": "true"},
        )
        if status == 404:
            matches.append({"indicator": value, "type": "ip", "found": False, "severity": "none"})
            continue
        data = body.get("data", {})
        score = int(data.get("abuseConfidenceScore", 0) or 0)
        matches.append(
            {
                "indicator": value,
                "type": "ip",
                "found": True,
                "severity": _severity_from_score(score),
                "score": score,
                "total_reports": data.get("totalReports", 0),
                "isp": data.get("isp", ""),
                "domain": data.get("domain", ""),
                "usage_type": data.get("usageType", ""),
                "is_whitelisted": data.get("isWhitelisted", False),
            }
        )
    return {"provider": "abuseipdb", "ok": True, "matches": matches}


async def _otx_lookup(
    client: httpx.AsyncClient,
    base_url: str,
    api_key: str,
    indicators: dict[str, list[str]],
) -> dict[str, Any]:
    headers = {"X-OTX-API-KEY": api_key}
    matches = []
    lookups = [
        ("ip", "IPv4", indicators["ips"][:3]),
        ("domain", "domain", indicators["domains"][:3]),
        ("hash", "file", indicators["hashes"][:3]),
    ]
    for indicator_type, otx_type, values in lookups:
        for value in values:
            status, body = await _get_json(
                client,
                f"{base_url.rstrip('/')}/indicators/{otx_type}/{value}/general",
                headers=headers,
            )
            if status == 404:
                matches.append(
                    {"indicator": value, "type": indicator_type, "found": False, "severity": "none"}
                )
                continue
            pulse_info = body.get("pulse_info", {})
            count = int(pulse_info.get("count", 0) or 0)
            pulses = pulse_info.get("pulses", [])[:5]
            score = min(100, count * 20)
            matches.append(
                {
                    "indicator": value,
                    "type": indicator_type,
                    "found": count > 0,
                    "severity": _severity_from_score(score),
                    "score": score,
                    "pulse_count": count,
                    "pulse_names": [pulse.get("name", "") for pulse in pulses if pulse.get("name")],
                }
            )
    return {"provider": "otx", "ok": True, "matches": matches}


async def _misp_lookup(
    client: httpx.AsyncClient,
    base_url: str,
    api_key: str,
    indicators: dict[str, list[str]],
) -> dict[str, Any]:
    headers = {"Authorization": api_key, "Accept": "application/json", "Content-Type": "application/json"}
    matches = []
    values = [*indicators["ips"][:3], *indicators["domains"][:3], *indicators["hashes"][:3]]
    for value in values:
        status, body = await _post_json(
            client,
            f"{base_url.rstrip('/')}/attributes/restSearch",
            headers=headers,
            payload={"value": value, "returnFormat": "json", "limit": 5},
        )
        if status == 404:
            matches.append({"indicator": value, "found": False, "severity": "none"})
            continue
        response = body.get("response", {})
        attributes = response.get("Attribute", []) if isinstance(response, dict) else []
        score = min(100, len(attributes) * 25)
        matches.append(
            {
                "indicator": value,
                "found": bool(attributes),
                "severity": _severity_from_score(score),
                "score": score,
                "match_count": len(attributes),
                "categories": sorted({item.get("category", "") for item in attributes if item.get("category")}),
            }
        )
    return {"provider": "misp", "ok": True, "matches": matches}


async def enrich_alert_with_external_intel(alert: NormalizedAlert, db: Session) -> dict[str, Any]:
    indicators = extract_external_indicators(alert)
    provider_rows = (
        db.query(ThreatIntelProviderSetting)
        .filter(ThreatIntelProviderSetting.enabled.is_(True))
        .order_by(ThreatIntelProviderSetting.provider.asc())
        .all()
    )
    provider_results = []
    async with httpx.AsyncClient(timeout=8.0) as client:
        for row in provider_rows:
            provider = row.provider.lower()
            if provider == "local_ioc":
                continue
            api_key = decrypt_secret(row.api_key_encrypted)
            if not api_key:
                provider_results.append(
                    {"provider": provider, "ok": False, "detail": "missing api key", "matches": []}
                )
                continue
            base_url = row.base_url or DEFAULT_BASE_URLS.get(provider, "")
            if not base_url:
                provider_results.append(
                    {"provider": provider, "ok": False, "detail": "missing base url", "matches": []}
                )
                continue
            try:
                if provider == "virustotal":
                    result = await _virustotal_lookup(client, base_url, api_key, indicators)
                elif provider == "abuseipdb":
                    result = await _abuseipdb_lookup(client, base_url, api_key, indicators)
                elif provider == "otx":
                    result = await _otx_lookup(client, base_url, api_key, indicators)
                elif provider == "misp":
                    result = await _misp_lookup(client, base_url, api_key, indicators)
                else:
                    result = {"provider": provider, "ok": False, "detail": "unsupported provider", "matches": []}
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                result = {
                    "provider": provider,
                    "ok": False,
                    "detail": f"provider returned HTTP {status}",
                    "matches": [],
                }
            except httpx.HTTPError as exc:
                result = {"provider": provider, "ok": False, "detail": str(exc), "matches": []}
            provider_results.append(result)
    matches = [match for provider in provider_results for match in provider.get("matches", [])]
    max_score = max((int(match.get("score", 0) or 0) for match in matches), default=0)
    high_confidence_hits = [
        match
        for match in matches
        if match.get("found") and match.get("severity") in {"high", "critical"}
    ]
    return {
        "indicators_checked": indicators,
        "external_provider_count": len(provider_results),
        "external_match_count": len([match for match in matches if match.get("found")]),
        "max_external_score": max_score,
        "max_external_severity": _severity_from_score(max_score),
        "high_confidence_hits": high_confidence_hits,
        "providers": provider_results,
        "privacy_guardrail": "Only public IPs, domains, URLs, and hashes are sent to external providers.",
    }
