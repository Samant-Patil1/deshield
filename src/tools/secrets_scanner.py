import re
from pathlib import Path

from src.models import SecretFinding

SECRET_PATTERNS = {
    "AWS_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key": re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "github_token": re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    "generic_api_key": re.compile(r"(?i)api[_-]?key\s*=\s*['\"][a-zA-Z0-9_\-]{16,}['\"]"),
}

SKIP_DIRS = {
    ".git",
    "tests",
    "docs",
    "node_modules",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
}


def scan_secrets(repo_path: Path) -> list[SecretFinding]:
    findings = []
    for file_path in repo_path.rglob("*"):
        if not file_path.is_file() or file_path.stat().st_size > 1_000_000:
            continue
        rel_parts = file_path.relative_to(repo_path).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for rule_name, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(content):
                findings.append(
                    SecretFinding(
                        file=str(file_path.relative_to(repo_path)),
                        rule=rule_name,
                        entropy=0.0,
                    )
                )
    return findings
