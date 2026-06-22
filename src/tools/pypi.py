import httpx
from datetime import datetime, timezone
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


def fetch_pypi_latest_metadata(package: str) -> dict:
    """Fetch metadata for the latest release of a package."""
    url = f"{settings.pypi_api_url}/{package}/json"
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


def _last_release_days(metadata: dict) -> int | None:
    urls = metadata.get("urls", [])
    if not urls:
        return None
    upload_time = urls[0].get("upload_time_iso_8601")
    if not upload_time:
        return None
    try:
        uploaded = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - uploaded).days
    except Exception:
        return None


def score_maintenance(metadata: dict) -> tuple[MaintenanceScore | None, int | None]:
    """Return (score, days_since_last_release) based on the latest release date."""
    if not metadata:
        return None, None
    days = _last_release_days(metadata)
    if days is None:
        return None, None
    if days > 730:
        return MaintenanceScore.ABANDONED, days
    if days > 365:
        return MaintenanceScore.STALE, days
    return MaintenanceScore.HEALTHY, days
