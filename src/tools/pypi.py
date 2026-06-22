import httpx
from src.config import settings
from src.models import MaintenanceScore


def fetch_pypi_metadata(package: str, version: str) -> dict:
    url = f"{settings.pypi_api_url}/{package}/{version}/json"
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.get(url)
            if resp.status_code == 404:
                return {}
            resp.raise_for_status()
            return resp.json()
    except (httpx.HTTPError, httpx.TimeoutException):
        return {}


def get_package_license(metadata: dict) -> str | None:
    info = metadata.get("info", {})
    license_field = info.get("license")
    if license_field and license_field.strip():
        return license_field.strip()
    for classifier in info.get("classifiers", []):
        if classifier.startswith("License :: "):
            return classifier.split(" :: ")[-1]
    return None


def score_maintenance(metadata: dict) -> MaintenanceScore | None:
    if not metadata:
        return None
    info = metadata.get("info", {})
    maintainers = info.get("maintainers")
    if maintainers:
        count = len(maintainers)
    else:
        # Fall back to author/maintainer strings when maintainers list is absent
        count = len(
            [x for x in [info.get("author"), info.get("maintainer")] if x]
        )
    if count == 0:
        return MaintenanceScore.ABANDONED
    if count == 1:
        return MaintenanceScore.RISKY_TRANSFER
    return MaintenanceScore.HEALTHY
