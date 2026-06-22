import httpx
from src.config import settings
from src.models import Ecosystem, Vulnerability

ECOSYSTEM_MAP = {
    Ecosystem.PYTHON: "PyPI",
    Ecosystem.NODE: "npm",
}


def query_osv(package: str, version: str, ecosystem: Ecosystem) -> list[Vulnerability]:
    payload = {
        "package": {"name": package, "ecosystem": ECOSYSTEM_MAP[ecosystem]},
        "version": version,
    }
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.post(f"{settings.osv_api_url}/query", json=payload)
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, httpx.TimeoutException):
        return []

    vulns = []
    for v in data.get("vulns", []):
        severity = v.get("severity", [{}])[0]
        vulns.append(
            Vulnerability(
                id=v.get("id", "UNKNOWN"),
                summary=v.get("summary"),
                severity=severity.get("type") if isinstance(severity, dict) else None,
                cvss_score=_extract_cvss_score(v),
                fixed_version=_extract_fixed_version(v),
                aliases=v.get("aliases", []),
            )
        )
    return vulns


def _extract_fixed_version(vuln: dict) -> str | None:
    for affected in vuln.get("affected", []):
        for ranges in affected.get("ranges", []):
            for event in ranges.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


def _extract_cvss_score(vuln: dict) -> float | None:
    for sev in vuln.get("severity", []):
        if isinstance(sev, dict) and "score" in sev:
            try:
                return float(sev["score"])
            except (ValueError, TypeError):
                continue
    return None
