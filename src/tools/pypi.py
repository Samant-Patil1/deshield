import httpx
from src.config import settings
from src.models import MaintenanceScore, MaintenanceFinding


def fetch_pypi_metadata(package: str, version: str) -> dict:
    url = f"{settings.pypi_api_url}/{package}/{version}/json"
    with httpx.Client(timeout=30) as client:
        resp = client.get(url)
        if resp.status_code == 404:
            return {}
        resp.raise_for_status()
        return resp.json()


def score_maintenance(metadata: dict) -> MaintenanceScore:
    info = metadata.get("info", {})
    maintainers = len(info.get("maintainers") or [])
    if maintainers == 0:
        return MaintenanceScore.ABANDONED
    if maintainers == 1:
        return MaintenanceScore.RISKY_TRANSFER
    return MaintenanceScore.HEALTHY
