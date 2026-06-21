import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from src.config import settings

GITHUB_URL_RE = re.compile(r"^https://github\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+/?$")


def validate_repo_url(url: str) -> None:
    if not GITHUB_URL_RE.match(url):
        raise ValueError(f"Invalid GitHub repository URL: {url}")


def get_dir_size(path: Path) -> int:
    total = 0
    for entry in os.scandir(path):
        if entry.is_file():
            total += entry.stat().st_size
        elif entry.is_dir():
            total += get_dir_size(Path(entry.path))
    return total


def clone_repo(url: str, base_dir: Path | None = None) -> Path:
    validate_repo_url(url)
    base = Path(base_dir) if base_dir else Path(tempfile.mkdtemp(prefix="deshield_"))
    repo_name = url.rstrip("/").split("/")[-1]
    dest = base / repo_name
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", url, str(dest)],
            check=True,
            capture_output=True,
            text=True,
            timeout=settings.clone_timeout_seconds,
        )
        size_mb = get_dir_size(dest) / (1024 * 1024)
        if size_mb > settings.max_repo_size_mb:
            shutil.rmtree(dest, ignore_errors=True)
            raise RuntimeError(f"Repository too large: {size_mb:.1f} MB")
    except subprocess.TimeoutExpired:
        shutil.rmtree(dest, ignore_errors=True)
        raise RuntimeError("Repository cloning timed out")
    return dest
