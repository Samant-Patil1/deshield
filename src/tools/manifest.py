import re
from pathlib import Path
from src.models import Dependency, Ecosystem

REQUIREMENT_RE = re.compile(
    r"^([a-zA-Z0-9_.-]+)\s*(==?|>=|<=|~=|!=|>|<)\s*([a-zA-Z0-9_.*+-]+)"
)


def parse_requirements_txt(content: str) -> list[Dependency]:
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = REQUIREMENT_RE.match(line)
        if match:
            deps.append(
                Dependency(
                    name=match.group(1).lower(),
                    version=match.group(3),
                    ecosystem=Ecosystem.PYTHON,
                    depth=0,
                )
            )
    return deps


def detect_manifests(repo_path: Path) -> list[Path]:
    manifests = []
    for name in ["requirements.txt", "pyproject.toml", "package.json"]:
        path = repo_path / name
        if path.exists():
            manifests.append(path)
    return manifests
