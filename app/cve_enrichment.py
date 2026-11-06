"""Conservative CVE correlation from observed software versions to NVD data."""

from __future__ import annotations

import os
import re
import threading
import time
from typing import Any

import requests


NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()
MAX_TARGETS_PER_RUN = 10
_NVD_LOCK = threading.Lock()
_LAST_NVD_REQUEST = 0.0

_PRODUCT_ALIASES = {
    "apachehttpd": "httpserver",
    "apache2": "httpserver",
    "httpd": "httpserver",
    "openssh": "openssh",
    "openbsdopenssh": "openssh",
    "openssl": "openssl",
    "nginx": "nginx",
    "microsoftiis": "internetinformationservices",
    "iis": "internetinformationservices",
}


def normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def software_targets(observations: list[dict[str, Any]]) -> list[dict[str, str]]:
    targets: dict[tuple[str, str], dict[str, str]] = {}
    for observation in observations:
        entries = observation.get("software_details", [])
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            product = str(entry.get("product", "")).strip()[:120]
            version = str(entry.get("version", "")).strip()[:80]
            if not product or not version or version.lower() in {"synthetic", "unknown", "*", "-"}:
                continue
            key = (normalize_key(product), version.lower().lstrip("v"))
            if key[0] and key[1]:
                targets[key] = {"product": product, "version": version}
    return [targets[key] for key in sorted(targets)]


def _numeric_version(value: str) -> tuple[int, ...] | None:
    candidate = value.strip().lower().lstrip("v")
    if not re.fullmatch(r"\d+(?:\.\d+){0,7}", candidate):
        return None
    return tuple(int(part) for part in candidate.split("."))


def _version_le(left: tuple[int, ...], right: tuple[int, ...]) -> bool:
    width = max(len(left), len(right))
    return left + (0,) * (width - len(left)) <= right + (0,) * (width - len(right))


def _version_affected(version: str, match: dict[str, Any], cpe_version: str) -> bool:
    observed = version.strip().lower().lstrip("v")
    starts = match.get("versionStartIncluding") or match.get("versionStartExcluding")
    ends = match.get("versionEndIncluding") or match.get("versionEndExcluding")
    if not starts and not ends:
        if cpe_version in {"*", ""}:
            return True
        if cpe_version == "-":
            return False
        return observed == cpe_version.lower().lstrip("v")

    observed_parts = _numeric_version(version)
    if observed_parts is None:
        return False
    start_parts = _numeric_version(str(starts)) if starts else None
    end_parts = _numeric_version(str(ends)) if ends else None
    if starts and start_parts is None or ends and end_parts is None:
        return False
    if start_parts:
        if match.get("versionStartIncluding") and not _version_le(start_parts, observed_parts):
            return False
        if match.get("versionStartExcluding") and _version_le(observed_parts, start_parts):
            return False
    if end_parts:
        if match.get("versionEndIncluding") and not _version_le(observed_parts, end_parts):
            return False
        if match.get("versionEndExcluding"):
            if not _version_le(observed_parts, end_parts) or _version_le(end_parts, observed_parts):
                return False
    return True


def _node_match(node: dict[str, Any], accepted_products: set[str], version: str) -> tuple[bool, str | None]:
    if node.get("negate") is True:
        return False, None
    parts: list[tuple[bool, str | None]] = []
    for match in node.get("cpeMatch", []):
        if not isinstance(match, dict) or match.get("vulnerable") is not True:
            # The product/version alone cannot satisfy a non-vulnerable CPE condition.
            parts.append((False, None))
            continue
        criteria = str(match.get("criteria", ""))
        cpe_parts = criteria.split(":")
        if len(cpe_parts) < 6 or cpe_parts[0:2] != ["cpe", "2.3"]:
            parts.append((False, None))
            continue
        cpe_product = normalize_key(cpe_parts[4])
        mapped_product = _PRODUCT_ALIASES.get(cpe_product, cpe_product)
        applies = bool(cpe_product) and (mapped_product in accepted_products or cpe_product in accepted_products)
        applies = applies and _version_affected(version, match, cpe_parts[5])
        parts.append((applies, criteria if applies else None))
    for child in node.get("children", []):
        if isinstance(child, dict):
            parts.append(_node_match(child, accepted_products, version))
    if not parts:
        return False, None
    if str(node.get("operator", "OR")).upper() == "AND":
        if all(matched for matched, _ in parts):
            return True, next((criteria for _, criteria in parts if criteria), None)
        return False, None
    return next(((True, criteria) for matched, criteria in parts if matched and criteria), (False, None))


def _matching_criteria(cve: dict[str, Any], product: str, version: str) -> str | None:
    product_key = normalize_key(product)
    accepted = {product_key, _PRODUCT_ALIASES.get(product_key, "")}
    for configuration in cve.get("configurations", []):
        if not isinstance(configuration, dict):
            continue
        for node in configuration.get("nodes", []):
            if isinstance(node, dict):
                applies, criteria = _node_match(node, accepted, version)
                if applies and criteria:
                    return criteria
    return None


def _cvss31(cve: dict[str, Any]) -> dict[str, Any] | None:
    metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
    if not isinstance(metrics, list) or not metrics:
        return None
    metric = next((item for item in metrics if item.get("type") == "Primary"), metrics[0])
    data = metric.get("cvssData", {})
    try:
        score = float(data["baseScore"])
    except (KeyError, TypeError, ValueError):
        return None
    severity = str(data.get("baseSeverity") or metric.get("baseSeverity") or "").lower()
    if severity not in {"critical", "high", "medium", "low"}:
        severity = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    return {"score": score, "severity": severity, "vector": str(data.get("vectorString", ""))}


def _throttled_get(params: dict[str, Any]) -> requests.Response:
    global _LAST_NVD_REQUEST
    with _NVD_LOCK:
        wait_for = 6.1 - (time.monotonic() - _LAST_NVD_REQUEST)
        if _LAST_NVD_REQUEST and wait_for > 0:
            time.sleep(wait_for)
        headers = {"User-Agent": "IT4US-SOC-EASM/1.0"}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY
        response = requests.get(NVD_CVE_API, params=params, headers=headers, timeout=(4, 15))
        _LAST_NVD_REQUEST = time.monotonic()
        return response


def lookup_nvd(product: str, version: str) -> list[dict[str, Any]]:
    """Return only CVEs with a CVSS 3.1 score and an NVD CPE/version match."""
    response = _throttled_get({"keywordSearch": f"{product} {version}"[:100], "resultsPerPage": 100})
    response.raise_for_status()
    payload = response.json()
    output: dict[str, dict[str, Any]] = {}
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = str(cve.get("id", ""))
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id) or str(cve.get("vulnStatus", "")).lower() == "rejected":
            continue
        criteria = _matching_criteria(cve, product, version)
        cvss = _cvss31(cve)
        if not criteria or not cvss:
            continue
        description = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        output[cve_id] = {
            "cve_id": cve_id,
            "description": str(description)[:2000],
            "cvss_version": "3.1",
            "cvss_score": cvss["score"],
            "cvss_severity": cvss["severity"],
            "cvss_vector": cvss["vector"],
            "product": product,
            "version": version,
            "cpe_criteria": criteria,
            "match_status": "candidate_requires_soc_validation",
            "source": "NVD CVE API 2.0",
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }
    return list(output.values())
