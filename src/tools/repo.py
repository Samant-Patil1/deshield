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
    except subprocess.TimeoutExpired:
        shutil.rmtree(dest, ignore_errors=True)
        raise RuntimeError("Repository cloning timed out")
    return dest
