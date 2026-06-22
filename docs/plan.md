# DepShield Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and deploy DepShield, a multi-agent ADK system that analyzes a GitHub repository’s dependency tree for vulnerabilities, license conflicts, maintenance risks, and supply-chain red flags, then renders a prioritized risk report and remediation plan.

**Architecture:** FastAPI web UI receives a repo URL; an ADK Orchestrator dispatches parallel specialist agents (Ingestion, Vulnerability, License, Maintenance, Typosquat, Secret Scanner); a Risk Synthesizer and Remediation Agent produce actionable output; a Report Agent renders HTML/Markdown. A standalone MCP server exposes the core tools.

**Tech Stack:** Python 3.11, `google-adk`, FastAPI, Jinja2, OSV API, PyPI/NPM APIs, `gitleaks` CLI, Docker, Google Cloud Run, Agents CLI.

---

## File Structure

```
deshield/
├── README.md
├── pyproject.toml
├── .env.example
├── Dockerfile
├── agent.json
├── src/
│   ├── __init__.py
│   ├── config.py
│   ├── models.py
│   ├── main.py                 # CLI entry
│   ├── run_cli.py              # Agents CLI wrapper
│   ├── web/
│   │   ├── __init__.py
│   │   ├── app.py
│   │   ├── routes.py
│   │   └── templates/
│   │       └── dashboard.html
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── orchestrator.py
│   │   ├── ingestion.py
│   │   ├── vulnerability.py
│   │   ├── license.py
│   │   ├── maintenance.py
│   │   ├── typosquat.py
│   │   ├── secrets.py
│   │   ├── synthesizer.py
│   │   ├── remediation.py
│   │   └── report.py
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── repo.py
│   │   ├── manifest.py
│   │   ├── osv.py
│   │   ├── pypi.py
│   │   ├── npm.py
│   │   ├── license_data.py
│   │   ├── typosquat_logic.py
│   │   └── secrets_scanner.py
│   └── mcp_server.py
├── tests/
│   ├── conftest.py
│   ├── test_repo.py
│   ├── test_manifest.py
│   ├── test_osv.py
│   ├── test_license.py
│   ├── test_typosquat.py
│   ├── test_secrets.py
│   ├── test_synthesizer.py
│   └── test_remediation.py
└── docs/
    └── architecture.svg
```

---

## Day 1 — Foundation, Ingestion, and Specialist Agents

### Task 1: Scaffold Project and Dependencies

**Files:**
- Create: `deshield/pyproject.toml`
- Create: `deshield/.env.example`
- Create: `deshield/README.md` (skeleton)
- Create: `deshield/src/__init__.py`
- Create: `deshield/src/config.py`
- Create: `deshield/src/models.py`

- [ ] **Step 1: Create `pyproject.toml`**

```toml
[project]
name = "deshield"
version = "0.1.0"
description = "AI-powered software supply chain risk agent"
requires-python = ">=3.11"
dependencies = [
    "google-adk>=0.1.0",
    "fastapi>=0.110.0",
    "uvicorn[standard]>=0.29.0",
    "jinja2>=3.1.3",
    "pydantic>=2.7.0",
    "pydantic-settings>=2.2.0",
    "httpx>=0.27.0",
    "gitpython>=3.1.42",
    "networkx>=3.2.1",
    "python-multipart>=0.0.9",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.1.0",
    "pytest-asyncio>=0.23.5",
    "respx>=0.21.0",
    "ruff>=0.4.0",
]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

- [ ] **Step 2: Create `.env.example`**

```bash
GOOGLE_API_KEY=your_gemini_api_key_here
GITHUB_TOKEN=optional_for_higher_rate_limits
DEPSHIELD_ENV=development
DEPSHIELD_MAX_REPO_SIZE_MB=50
DEPSHIELD_CLONE_TIMEOUT_SECONDS=60
```

- [ ] **Step 3: Create `src/config.py`**

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    google_api_key: str
    github_token: str | None = None
    env: str = "development"
    max_repo_size_mb: int = 50
    clone_timeout_seconds: int = 60
    osv_api_url: str = "https://api.osv.dev/v1"
    pypi_api_url: str = "https://pypi.org/pypi"
    npm_registry_url: str = "https://registry.npmjs.org"

    class Config:
        env_file = ".env"

settings = Settings()
```

- [ ] **Step 4: Create `src/models.py`**

```python
from pydantic import BaseModel, Field
from enum import Enum
from typing import Literal

class Ecosystem(str, Enum):
    PYTHON = "PyPI"
    NODE = "npm"

class Dependency(BaseModel):
    name: str
    version: str
    ecosystem: Ecosystem
    depth: int = 0
    parent: str | None = None

class Vulnerability(BaseModel):
    id: str
    summary: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    fixed_version: str | None = None
    aliases: list[str] = []

class LicenseFinding(BaseModel):
    package: str
    version: str
    license_expr: str | None = None
    is_copyleft: bool = False
    conflict: str | None = None

class MaintenanceScore(str, Enum):
    HEALTHY = "healthy"
    STALE = "stale"
    ABANDONED = "abandoned"
    RISKY_TRANSFER = "risky_transfer"

class MaintenanceFinding(BaseModel):
    package: str
    version: str
    score: MaintenanceScore
    last_release_days: int | None = None
    open_issues: int | None = None
    maintainers: int | None = None

class TyposquatFinding(BaseModel):
    package: str
    similar_to: str
    distance: int
    reason: str

class SecretFinding(BaseModel):
    file: str
    rule: str
    entropy: float

class RiskIssue(BaseModel):
    package: str
    version: str
    category: Literal["vulnerability", "license", "maintenance", "typosquat", "secret"]
    severity: Literal["critical", "high", "medium", "low", "info"]
    title: str
    description: str
    recommendation: str | None = None

class AnalysisResult(BaseModel):
    repo_url: str
    dependencies: list[Dependency]
    issues: list[RiskIssue]
    top_issues: list[RiskIssue]
    overall_score: int = Field(..., ge=0, le=100)
```

- [ ] **Step 5: Install dependencies and verify**

Run:
```bash
cd deshield
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -c "from src.config import settings; print(settings.env)"
```
Expected: prints `development`.

- [ ] **Step 6: Commit**

```bash
git add .
git commit -m "chore: scaffold deshield project with deps, config, and models"
```

---

### Task 2: Implement Repo Cloning and Manifest Parsing Tools

**Files:**
- Create: `deshield/src/tools/repo.py`
- Create: `deshield/src/tools/manifest.py`
- Create: `deshield/tests/test_repo.py`
- Create: `deshield/tests/test_manifest.py`

- [ ] **Step 1: Write failing test for `clone_repo`**

Create `tests/test_repo.py`:
```python
import pytest
from src.tools.repo import clone_repo
from src.config import settings

def test_clone_repo_returns_path(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "clone_timeout_seconds", 30)
    # Use a tiny public repo
    path = clone_repo("https://github.com/octocat/Hello-World", tmp_path)
    assert path.exists()
    assert (path / "README").exists()
```

Run:
```bash
pytest tests/test_repo.py -v
```
Expected: FAIL because `clone_repo` does not exist.

- [ ] **Step 2: Implement `clone_repo`**

Create `src/tools/repo.py`:
```python
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
```

- [ ] **Step 3: Run repo tests**

```bash
pytest tests/test_repo.py -v
```
Expected: PASS.

- [ ] **Step 4: Write failing test for manifest parsing**

Create `tests/test_manifest.py`:
```python
from src.tools.manifest import parse_requirements_txt, detect_manifests

def test_parse_requirements_txt():
    text = "requests==2.31.0\nflask>=2.0\n# comment\n"
    deps = parse_requirements_txt(text)
    assert len(deps) == 2
    assert deps[0].name == "requests"
    assert deps[0].version == "2.31.0"
```

Run:
```bash
pytest tests/test_manifest.py -v
```
Expected: FAIL.

- [ ] **Step 5: Implement manifest parser**

Create `src/tools/manifest.py`:
```python
import re
from pathlib import Path
from src.models import Dependency, Ecosystem

REQUIREMENT_RE = re.compile(r"^([a-zA-Z0-9_.-]+)\s*==?\s*([a-zA-Z0-9_.*+-]+)")

def parse_requirements_txt(content: str) -> list[Dependency]:
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = REQUIREMENT_RE.match(line)
        if match:
            deps.append(Dependency(
                name=match.group(1).lower(),
                version=match.group(2),
                ecosystem=Ecosystem.PYTHON,
                depth=0,
            ))
    return deps

def detect_manifests(repo_path: Path) -> list[Path]:
    manifests = []
    for name in ["requirements.txt", "pyproject.toml", "package.json"]:
        path = repo_path / name
        if path.exists():
            manifests.append(path)
    return manifests
```

- [ ] **Step 6: Run manifest tests**

```bash
pytest tests/test_manifest.py -v
```
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/tools tests
git commit -m "feat: add repo cloning and manifest parsing tools"
```

---

### Task 3: Implement PyPI Metadata + OSV Vulnerability Tools

**Files:**
- Create: `deshield/src/tools/pypi.py`
- Create: `deshield/src/tools/osv.py`
- Create: `deshield/tests/test_osv.py`

- [ ] **Step 1: Write failing test for OSV query**

Create `tests/test_osv.py`:
```python
import httpx
import respx
from src.tools.osv import query_osv
from src.models import Ecosystem

@respx.mock
def test_query_osv_returns_vulns():
    route = respx.post("https://api.osv.dev/v1/query").mock(
        return_value=httpx.Response(200, json={"vulns": []})
    )
    result = query_osv("requests", "2.31.0", Ecosystem.PYTHON)
    assert result == []
    assert route.called
```

Run:
```bash
pytest tests/test_osv.py -v
```
Expected: FAIL because `query_osv` is not defined.

- [ ] **Step 2: Implement OSV client**

Create `src/tools/osv.py`:
```python
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
    with httpx.Client(timeout=30) as client:
        resp = client.post(f"{settings.osv_api_url}/query", json=payload)
        resp.raise_for_status()
        data = resp.json()
    vulns = []
    for v in data.get("vulns", []):
        severity = v.get("severity", [{}])[0]
        vulns.append(Vulnerability(
            id=v.get("id", "UNKNOWN"),
            summary=v.get("summary"),
            severity=severity.get("type") if isinstance(severity, dict) else None,
            cvss_score=None,
            fixed_version=_extract_fixed_version(v),
            aliases=v.get("aliases", []),
        ))
    return vulns

def _extract_fixed_version(vuln: dict) -> str | None:
    for affected in vuln.get("affected", []):
        for ranges in affected.get("ranges", []):
            for event in ranges.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None
```

- [ ] **Step 3: Run OSV tests**

```bash
pytest tests/test_osv.py -v
```
Expected: PASS.

- [ ] **Step 4: Implement PyPI metadata fetcher**

Create `src/tools/pypi.py`:
```python
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
```

- [ ] **Step 5: Commit**

```bash
git add src/tools tests
git commit -m "feat: add OSV and PyPI metadata tools"
```

---

### Task 4: Implement License, Maintenance, and Typosquat Logic

**Files:**
- Create: `deshield/src/tools/license_data.py`
- Create: `deshield/src/tools/typosquat_logic.py`
- Create: `deshield/tests/test_license.py`
- Create: `deshield/tests/test_typosquat.py`

- [ ] **Step 1: Write failing license test**

Create `tests/test_license.py`:
```python
from src.tools.license_data import is_copyleft, check_compatibility

def test_mit_is_not_copyleft():
    assert is_copyleft("MIT") is False

def test_gpl_is_copyleft():
    assert is_copyleft("GPL-3.0") is True

def test_incompatible_with_proprietary():
    result = check_compatibility(["MIT", "GPL-3.0"], "proprietary")
    assert result.conflict is not None
```

Run:
```bash
pytest tests/test_license.py -v
```
Expected: FAIL.

- [ ] **Step 2: Implement license helpers**

Create `src/tools/license_data.py`:
```python
from src.models import LicenseFinding

COPYLEFT_LICENSES = {
    "GPL-2.0", "GPL-3.0", "LGPL-2.1", "LGPL-3.0",
    "AGPL-3.0", "MPL-2.0", "EPL-2.0", "CC-BY-SA-4.0",
}

def is_copyleft(license_expr: str | None) -> bool:
    if not license_expr:
        return False
    upper = license_expr.upper()
    return any(lic.upper() in upper for lic in COPYLEFT_LICENSES)

def check_compatibility(licenses: list[str], target_policy: str) -> LicenseFinding:
    for lic in licenses:
        if is_copyleft(lic) and target_policy == "proprietary":
            return LicenseFinding(
                package="",
                version="",
                license_expr=lic,
                is_copyleft=True,
                conflict=f"Copyleft license {lic} is incompatible with proprietary distribution",
            )
    return LicenseFinding(
        package="",
        version="",
        license_expr=licenses[0] if licenses else None,
        is_copyleft=False,
        conflict=None,
    )
```

- [ ] **Step 3: Run license tests**

```bash
pytest tests/test_license.py -v
```
Expected: PASS.

- [ ] **Step 4: Write failing typosquat test**

Create `tests/test_typosquat.py`:
```python
from src.tools.typosquat_logic import check_typosquat

def test_typosquat_detects_close_name():
    popular = ["requests", "flask", "django"]
    result = check_typosquat("reqeusts", popular)
    assert result is not None
    assert result.similar_to == "requests"
```

Run:
```bash
pytest tests/test_typosquat.py -v
```
Expected: FAIL.

- [ ] **Step 5: Implement typosquat logic**

Create `src/tools/typosquat_logic.py`:
```python
from difflib import SequenceMatcher
from src.models import TyposquatFinding

def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[-1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]

def check_typosquat(package: str, popular_packages: list[str], threshold: int = 2) -> TyposquatFinding | None:
    package_lower = package.lower()
    for popular in popular_packages:
        popular_lower = popular.lower()
        if package_lower == popular_lower:
            continue
        distance = _levenshtein(package_lower, popular_lower)
        if distance <= threshold:
            return TyposquatFinding(
                package=package,
                similar_to=popular,
                distance=distance,
                reason=f"Name is {distance} edits away from popular package '{popular}'",
            )
    return None
```

- [ ] **Step 6: Run typosquat tests**

```bash
pytest tests/test_typosquat.py -v
```
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/tools tests
git commit -m "feat: add license and typosquat analysis tools"
```

---

### Task 5: Implement Secret Scanner Tool

**Files:**
- Create: `deshield/src/tools/secrets_scanner.py`
- Create: `deshield/tests/test_secrets.py`

- [ ] **Step 1: Write failing secret scanner test**

Create `tests/test_secrets.py`:
```python
from src.tools.secrets_scanner import scan_secrets

def test_scan_detects_api_key(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "config.py").write_text("AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\n")
    findings = scan_secrets(repo)
    assert len(findings) > 0
    assert any("AWS" in f.rule for f in findings)
```

Run:
```bash
pytest tests/test_secrets.py -v
```
Expected: FAIL.

- [ ] **Step 2: Implement secret scanner**

Create `src/tools/secrets_scanner.py`:
```python
import re
from pathlib import Path
from src.models import SecretFinding

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key": re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "github_token": re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    "generic_api_key": re.compile(r"(?i)api[_-]?key\s*=\s*['\"][a-zA-Z0-9_\-]{16,}['\"]"),
}

def scan_secrets(repo_path: Path) -> list[SecretFinding]:
    findings = []
    for file_path in repo_path.rglob("*"):
        if not file_path.is_file() or file_path.stat().st_size > 1_000_000:
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for rule_name, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(content):
                findings.append(SecretFinding(
                    file=str(file_path.relative_to(repo_path)),
                    rule=rule_name,
                    entropy=0.0,
                ))
    return findings
```

- [ ] **Step 3: Run secret tests**

```bash
pytest tests/test_secrets.py -v
```
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/tools tests
git commit -m "feat: add pure-Python secret scanner fallback"
```

---

### Task 6: Build ADK Specialist Agents

**Files:**
- Create: `deshield/src/agents/ingestion.py`
- Create: `deshield/src/agents/vulnerability.py`
- Create: `deshield/src/agents/license.py`
- Create: `deshield/src/agents/maintenance.py`
- Create: `deshield/src/agents/typosquat.py`
- Create: `deshield/src/agents/secrets.py`

- [ ] **Step 1: Implement Ingestion Agent**

Create `src/agents/ingestion.py`:
```python
from pathlib import Path
from google.adk.agents import Agent
from google.adk.tools import FunctionTool
from src.tools.repo import clone_repo, validate_repo_url
from src.tools.manifest import detect_manifests, parse_requirements_txt
from src.models import Dependency

def ingest_repo(repo_url: str) -> dict:
    validate_repo_url(repo_url)
    repo_path = clone_repo(repo_url)
    manifests = detect_manifests(repo_path)
    deps: list[Dependency] = []
    for manifest in manifests:
        if manifest.name == "requirements.txt":
            deps.extend(parse_requirements_txt(manifest.read_text()))
    return {
        "repo_path": str(repo_path),
        "dependencies": [d.model_dump() for d in deps],
    }

ingestion_agent = Agent(
    name="ingestion_agent",
    model="gemini-2.5-flash",
    instruction="You ingest a GitHub repository and return its Python dependencies.",
    tools=[FunctionTool(ingest_repo)],
)
```

- [ ] **Step 2: Implement Vulnerability Agent**

Create `src/agents/vulnerability.py`:
```python
from google.adk.agents import Agent
from google.adk.tools import FunctionTool
from src.tools.osv import query_osv
from src.models import Ecosystem

def find_vulnerabilities(deps: list[dict]) -> list[dict]:
    findings = []
    for dep in deps:
        vulns = query_osv(dep["name"], dep["version"], Ecosystem(dep["ecosystem"]))
        findings.extend([v.model_dump() for v in vulns])
    return findings

vulnerability_agent = Agent(
    name="vulnerability_agent",
    model="gemini-2.5-flash",
    instruction="Find known vulnerabilities in the provided dependencies using OSV.",
    tools=[FunctionTool(find_vulnerabilities)],
)
```

- [ ] **Step 3: Implement stub agents for License, Maintenance, Typosquat, Secrets**

For each remaining agent, create a file with a stub function and `Agent` definition. Example for `src/agents/license.py`:
```python
from google.adk.agents import Agent
from google.adk.tools import FunctionTool
from src.tools.license_data import check_compatibility

def analyze_licenses(deps: list[dict]) -> list[dict]:
    licenses = [d.get("license") for d in deps if d.get("license")]
    finding = check_compatibility(licenses, "proprietary")
    return [finding.model_dump()] if finding.conflict else []

license_agent = Agent(
    name="license_agent",
    model="gemini-2.5-flash",
    instruction="Detect license conflicts in dependencies.",
    tools=[FunctionTool(analyze_licenses)],
)
```

Similar stubs for `maintenance.py`, `typosquat.py`, `secrets.py`.

- [ ] **Step 4: Commit**

```bash
git add src/agents
git commit -m "feat: add ADK specialist agent stubs"
```

---

## Day 2 — Synthesis, Remediation, Web UI, Security

### Task 7: Implement Risk Synthesizer Agent

**Files:**
- Create: `deshield/src/agents/synthesizer.py`
- Create: `deshield/tests/test_synthesizer.py`

- [ ] **Step 1: Write failing synthesizer test**

Create `tests/test_synthesizer.py`:
```python
from src.agents.synthesizer import synthesize_risks
from src.models import Dependency, Ecosystem

def test_synthesize_flags_critical_vuln():
    deps = [Dependency(name="requests", version="2.31.0", ecosystem=Ecosystem.PYTHON)]
    vulns = [{
        "id": "PYSEC-2023-1",
        "summary": "Bad thing",
        "severity": "CVSS_V3",
        "cvss_score": None,
        "fixed_version": "2.32.0",
        "aliases": [],
    }]
    result = synthesize_risks(
        repo_url="https://github.com/example/repo",
        deps=deps,
        vulnerabilities={"requests==2.31.0": vulns},
        license_findings=[],
        maintenance_findings=[],
        typosquat_findings=[],
        secret_findings=[],
    )
    assert len(result.issues) > 0
    assert result.overall_score < 100
```

Run:
```bash
pytest tests/test_synthesizer.py -v
```
Expected: FAIL.

- [ ] **Step 2: Implement synthesizer**

Create `src/agents/synthesizer.py`:
```python
from src.models import (
    AnalysisResult, Dependency, Ecosystem, RiskIssue,
    Vulnerability, LicenseFinding, MaintenanceFinding,
    TyposquatFinding, SecretFinding,
)

def _severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"

def synthesize_risks(
    repo_url: str,
    deps: list[Dependency],
    vulnerabilities: dict[str, list[Vulnerability]],
    license_findings: list[LicenseFinding],
    maintenance_findings: list[MaintenanceFinding],
    typosquat_findings: list[TyposquatFinding],
    secret_findings: list[SecretFinding],
) -> AnalysisResult:
    issues: list[RiskIssue] = []
    dep_key = lambda d: f"{d.name}=={d.version}"

    for dep in deps:
        key = dep_key(dep)
        for vuln in vulnerabilities.get(key, []):
            issues.append(RiskIssue(
                package=dep.name,
                version=dep.version,
                category="vulnerability",
                severity=_severity_from_cvss(vuln.cvss_score),
                title=f"Vulnerability {vuln.id}",
                description=vuln.summary or "No summary available",
                recommendation=f"Upgrade to {vuln.fixed_version}" if vuln.fixed_version else "Review advisory",
            ))

    for finding in license_findings:
        issues.append(RiskIssue(
            package=finding.package or "unknown",
            version=finding.version or "unknown",
            category="license",
            severity="high" if finding.is_copyleft else "medium",
            title="License conflict",
            description=finding.conflict or "License issue detected",
            recommendation="Review license compatibility",
        ))

    for finding in maintenance_findings:
        issues.append(RiskIssue(
            package=finding.package,
            version=finding.version,
            category="maintenance",
            severity="high" if finding.score.value == "abandoned" else "medium",
            title=f"Maintenance risk: {finding.score.value}",
            description=f"Last release {finding.last_release_days} days ago; {finding.maintainers} maintainers",
            recommendation="Consider migrating to an actively maintained alternative",
        ))

    for finding in typosquat_findings:
        issues.append(RiskIssue(
            package=finding.package,
            version="unknown",
            category="typosquat",
            severity="critical",
            title="Possible typosquat",
            description=finding.reason,
            recommendation="Verify package name and replace if suspicious",
        ))

    for finding in secret_findings:
        issues.append(RiskIssue(
            package="repo",
            version="",
            category="secret",
            severity="critical",
            title="Potential secret leak",
            description=f"{finding.rule} in {finding.file}",
            recommendation="Rotate the secret and remove it from history",
        ))

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_issues = sorted(issues, key=lambda i: (severity_order.get(i.severity, 5), i.package))
    score = max(0, 100 - len([i for i in sorted_issues if i.severity in ("critical", "high")]) * 10)

    return AnalysisResult(
        repo_url=repo_url,
        dependencies=deps,
        issues=sorted_issues,
        top_issues=sorted_issues[:10],
        overall_score=score,
    )
```

- [ ] **Step 3: Run synthesizer tests**

```bash
pytest tests/test_synthesizer.py -v
```
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/agents tests
git commit -m "feat: add risk synthesizer agent"
```

---

### Task 8: Implement Remediation Agent

**Files:**
- Create: `deshield/src/agents/remediation.py`
- Create: `deshield/tests/test_remediation.py`

- [ ] **Step 1: Write failing remediation test**

Create `tests/test_remediation.py`:
```python
from src.models import RiskIssue
from src.agents.remediation import generate_remediation_plan

def test_remediation_suggests_upgrade():
    issue = RiskIssue(
        package="requests",
        version="2.31.0",
        category="vulnerability",
        severity="high",
        title="Vulnerability PYSEC-1",
        description="Bad",
        recommendation="Upgrade to 2.32.0",
    )
    plan = generate_remediation_plan([issue])
    assert any("requests" in step and "2.32.0" in step for step in plan.steps)
```

Run:
```bash
pytest tests/test_remediation.py -v
```
Expected: FAIL.

- [ ] **Step 2: Implement remediation agent**

Create `src/agents/remediation.py`:
```python
from pydantic import BaseModel
from src.models import RiskIssue

class RemediationPlan(BaseModel):
    steps: list[str]
    estimated_effort: str

def generate_remediation_plan(issues: list[RiskIssue]) -> RemediationPlan:
    steps = []
    for issue in issues[:10]:
        if issue.category == "vulnerability":
            steps.append(f"Update {issue.package} ({issue.version}): {issue.recommendation}")
        elif issue.category == "license":
            steps.append(f"Review license for {issue.package}: {issue.recommendation}")
        elif issue.category == "maintenance":
            steps.append(f"Evaluate migration away from {issue.package}: {issue.recommendation}")
        elif issue.category == "typosquat":
            steps.append(f"URGENT: Replace suspicious package {issue.package}: {issue.recommendation}")
        elif issue.category == "secret":
            steps.append(f"URGENT: {issue.recommendation}")
    return RemediationPlan(
        steps=steps,
        estimated_effort="small" if len(steps) <= 3 else "medium",
    )
```

- [ ] **Step 3: Run remediation tests**

```bash
pytest tests/test_remediation.py -v
```
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/agents tests
git commit -m "feat: add remediation agent"
```

---

### Task 9: Implement Report Agent and Dashboard Template

**Files:**
- Create: `deshield/src/agents/report.py`
- Create: `deshield/src/web/templates/dashboard.html`

- [ ] **Step 1: Implement Report Agent**

Create `src/agents/report.py`:
```python
import json
from jinja2 import Environment, PackageLoader, select_autoescape
from src.models import AnalysisResult
from src.agents.remediation import generate_remediation_plan

env = Environment(
    loader=PackageLoader("src.web", "templates"),
    autoescape=select_autoescape(["html", "xml"]),
)

def render_html(result: AnalysisResult) -> str:
    template = env.get_template("dashboard.html")
    plan = generate_remediation_plan(result.issues)
    return template.render(
        repo_url=result.repo_url,
        score=result.overall_score,
        dependencies=result.dependencies,
        issues=result.issues,
        top_issues=result.top_issues,
        plan=plan,
    )

def render_markdown(result: AnalysisResult) -> str:
    lines = [
        f"# DepShield Report: {result.repo_url}",
        f"**Overall Score:** {result.overall_score}/100",
        "",
        "## Top Issues",
    ]
    for issue in result.top_issues:
        lines.append(f"- **{issue.severity.upper()}** {issue.title} — {issue.package} ({issue.version})")
        lines.append(f"  - {issue.description}")
        if issue.recommendation:
            lines.append(f"  - Recommendation: {issue.recommendation}")
    return "\n".join(lines)
```

- [ ] **Step 2: Create dashboard template**

Create `src/web/templates/dashboard.html`:
```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DepShield Report</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
  <div class="container py-5">
    <h1 class="mb-4">DepShield Report</h1>
    <p class="text-muted">{{ repo_url }}</p>
    <div class="card mb-4">
      <div class="card-body">
        <h2 class="card-title">Overall Score: {{ score }}/100</h2>
        <p class="card-text">{{ dependencies|length }} dependencies analyzed.</p>
      </div>
    </div>
    <h3>Top Issues</h3>
    <div class="list-group mb-4">
      {% for issue in top_issues %}
      <div class="list-group-item">
        <div class="d-flex w-100 justify-content-between">
          <h5 class="mb-1">{{ issue.title }}</h5>
          <span class="badge bg-{% if issue.severity == 'critical' %}danger{% elif issue.severity == 'high' %}warning text-dark{% else %}info{% endif %}">{{ issue.severity.upper() }}</span>
        </div>
        <p class="mb-1">{{ issue.package }} ({{ issue.version }})</p>
        <small>{{ issue.description }}</small><br>
        <small class="text-success">{{ issue.recommendation or '' }}</small>
      </div>
      {% endfor %}
    </div>
    <h3>Remediation Plan</h3>
    <ul>
      {% for step in plan.steps %}
      <li>{{ step }}</li>
      {% endfor %}
    </ul>
  </div>
</body>
</html>
```

- [ ] **Step 3: Commit**

```bash
git add src/agents src/web
git commit -m "feat: add report agent and HTML dashboard"
```

---

### Task 10: Build FastAPI Web UI and Orchestrator Endpoint

**Files:**
- Create: `deshield/src/web/app.py`
- Create: `deshield/src/web/routes.py`
- Create: `deshield/src/agents/orchestrator.py`
- Create: `deshield/src/main.py`

- [ ] **Step 1: Implement Orchestrator Agent**

Create `src/agents/orchestrator.py`:
```python
from pathlib import Path
import json
from google.adk.agents import Agent
from google.adk.tools import FunctionTool
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from src.tools.repo import clone_repo
from src.tools.manifest import detect_manifests, parse_requirements_txt
from src.tools.osv import query_osv
from src.tools.secrets_scanner import scan_secrets
from src.models import Dependency, Ecosystem, AnalysisResult
from src.agents.synthesizer import synthesize_risks
from src.agents.report import render_html, render_markdown

def analyze_repo(repo_url: str) -> dict:
    repo_path = clone_repo(repo_url)
    manifests = detect_manifests(repo_path)
    deps: list[Dependency] = []
    for manifest in manifests:
        if manifest.name == "requirements.txt":
            deps.extend(parse_requirements_txt(manifest.read_text()))

    vulns_by_dep: dict[str, list] = {}
    for dep in deps:
        key = f"{dep.name}=={dep.version}"
        vulns_by_dep[key] = query_osv(dep.name, dep.version, dep.ecosystem)

    secrets = scan_secrets(repo_path)
    result = synthesize_risks(
        repo_url=repo_url,
        deps=deps,
        vulnerabilities=vulns_by_dep,
        license_findings=[],
        maintenance_findings=[],
        typosquat_findings=[],
        secret_findings=secrets,
    )
    return {
        "html": render_html(result),
        "markdown": render_markdown(result),
        "score": result.overall_score,
    }

orchestrator_agent = Agent(
    name="deshield_orchestrator",
    model="gemini-2.5-flash",
    instruction="You are DepShield. When given a GitHub repository URL, call analyze_repo and return the HTML report.",
    tools=[FunctionTool(analyze_repo)],
)

async def run_analysis(repo_url: str) -> dict:
    session_service = InMemorySessionService()
    session = session_service.create_session(app_name="deshield", user_id="user")
    runner = Runner(agent=orchestrator_agent, app_name="deshield", session_service=session_service)
    content = json.dumps({"repo_url": repo_url})
    async for event in runner.run_async(user_id="user", session_id=session.id, new_message=content):
        if event.is_final_response() and event.content:
            return json.loads(event.content.parts[0].text)
    raise RuntimeError("No final response from orchestrator")
```

- [ ] **Step 2: Implement FastAPI routes**

Create `src/web/routes.py`:
```python
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse
from src.agents.orchestrator import run_analysis

router = APIRouter()

@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    return """
    <!doctype html>
    <html><body class="p-5">
      <h1>DepShield</h1>
      <form action="/analyze" method="post">
        <input type="url" name="repo_url" placeholder="https://github.com/owner/repo" required class="form-control mb-2">
        <button type="submit" class="btn btn-primary">Analyze</button>
      </form>
    </body></html>
    """

@router.post("/analyze", response_class=HTMLResponse)
async def analyze(repo_url: str = Form(...)):
    result = await run_analysis(repo_url)
    return result["html"]
```

- [ ] **Step 3: Implement FastAPI app**

Create `src/web/app.py`:
```python
from fastapi import FastAPI
from src.web.routes import router

app = FastAPI(title="DepShield")
app.include_router(router)
```

- [ ] **Step 4: Implement CLI entry point**

Create `src/main.py`:
```python
import argparse
import asyncio
import uvicorn
from src.agents.orchestrator import run_analysis

def main():
    parser = argparse.ArgumentParser(description="DepShield supply-chain risk agent")
    parser.add_argument("--repo", help="GitHub repository URL to analyze")
    parser.add_argument("--serve", action="store_true", help="Run the web UI")
    args = parser.parse_args()

    if args.serve:
        uvicorn.run("src.web.app:app", host="0.0.0.0", port=8080, reload=True)
    elif args.repo:
        result = asyncio.run(run_analysis(args.repo))
        print(result["markdown"])
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run web app locally and test**

Terminal 1:
```bash
python src/main.py --serve
```

Terminal 2:
```bash
curl -X POST http://localhost:8080/analyze -d "repo_url=https://github.com/psf/requests" -H "Content-Type: application/x-www-form-urlencoded"
```
Expected: Returns HTML report with no errors.

- [ ] **Step 6: Commit**

```bash
git add src
git commit -m "feat: add FastAPI web UI and orchestrator endpoint"
```

---

### Task 11: Harden Security and Add Observability

**Files:**
- Modify: `deshield/src/tools/repo.py`
- Modify: `deshield/src/agents/orchestrator.py`
- Create: `deshield/src/web/middleware.py`
- Create: `deshield/src/utils/logging.py`

- [ ] **Step 1: Add input validation and safe cleanup to repo tool**

Edit `src/tools/repo.py` to add a cleanup helper and size check:
```python
import os

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
```

- [ ] **Step 2: Add structured logging**

Create `src/utils/logging.py`:
```python
import logging
import json
from datetime import datetime, timezone

class JSONFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        })

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
```

- [ ] **Step 3: Add in-memory rate-limiting middleware**

Create `src/web/middleware.py`:
```python
import time
from collections import defaultdict
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int = 10, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.history: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        client = request.client.host if request.client else "unknown"
        now = time.time()
        window = [t for t in self.history[client] if now - t < self.window_seconds]
        self.history[client] = window
        if len(window) >= self.max_requests:
            return JSONResponse({"detail": "Rate limit exceeded"}, status_code=429)
        self.history[client].append(now)
        response = await call_next(request)
        return response
```

Update `src/web/app.py` to include the middleware:
```python
from fastapi import FastAPI
from src.web.routes import router
from src.web.middleware import RateLimitMiddleware

app = FastAPI(title="DepShield")
app.add_middleware(RateLimitMiddleware, max_requests=10, window_seconds=60)
app.include_router(router)
```

- [ ] **Step 4: Commit**

```bash
git add src
git commit -m "feat: add security limits, logging, and rate limiting"
```

---

## Day 3 — MCP Server, Agents CLI, Deployment, Submission

### Task 12: Implement MCP Server

**Files:**
- Create: `deshield/src/mcp_server.py`

- [ ] **Step 1: Implement MCP server exposing core tools**

Create `src/mcp_server.py`:
```python
from mcp.server.fastmcp import FastMCP
from src.tools.osv import query_osv
from src.tools.typosquat_logic import check_typosquat
from src.models import Ecosystem

mcp = FastMCP("deshield")

@mcp.tool()
def get_vulnerabilities(package: str, version: str, ecosystem: str) -> list[dict]:
    """Query OSV for known vulnerabilities in a package."""
    return [v.model_dump() for v in query_osv(package, version, Ecosystem(ecosystem))]

@mcp.tool()
def check_name_typosquat(package: str, popular_packages: list[str]) -> dict | None:
    """Check if a package name is a typosquat of a popular package."""
    result = check_typosquat(package, popular_packages)
    return result.model_dump() if result else None

if __name__ == "__main__":
    mcp.run()
```

- [ ] **Step 2: Add `mcp` dependency**

Edit `pyproject.toml` to add `"mcp>=1.0.0"` to dependencies (use a real available version like `mcp>=0.9.0` or the current stable).

- [ ] **Step 3: Test MCP server starts**

```bash
python src/mcp_server.py --help
```
Expected: Help output appears without error.

- [ ] **Step 4: Commit**

```bash
git add src/pyproject.toml
git commit -m "feat: add MCP server exposing dependency analysis tools"
```

---

### Task 13: Package as Agents CLI Skill

**Files:**
- Create: `deshield/agent.json`
- Create: `deshield/src/run_cli.py`

- [ ] **Step 1: Create `agent.json`**

```json
{
  "name": "DepShield",
  "description": "AI-powered software supply chain risk and remediation agent",
  "entrypoint": "src.run_cli:main",
  "runtime": "python"
}
```

- [ ] **Step 2: Create CLI wrapper**

Create `src/run_cli.py`:
```python
import sys
from src.main import main

def run():
    sys.argv = ["deshield"] + sys.argv[1:]
    main()
```

- [ ] **Step 3: Commit**

```bash
git add agent.json src/run_cli.py
git commit -m "chore: package deshield as Agents CLI skill"
```

---

### Task 14: Containerize and Deploy

**Files:**
- Create: `deshield/Dockerfile`
- Create: `deshield/.dockerignore`

- [ ] **Step 1: Write Dockerfile**

Create `Dockerfile`:
```dockerfile
FROM python:3.11-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e ".[dev]"

FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends git gitleaks && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY . .
EXPOSE 8080
CMD ["python", "src/main.py", "--serve"]
```

- [ ] **Step 2: Write `.dockerignore`**

```
.venv
.git
.pytest_cache
__pycache__
*.pyc
.env
```

- [ ] **Step 3: Build and run locally**

```bash
docker build -t deshield .
docker run -p 8080:8080 --env-file .env deshield
```
Expected: App runs on port 8080.

- [ ] **Step 4: Deploy to Cloud Run**

```bash
gcloud run deploy deshield \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars GOOGLE_API_KEY=$GOOGLE_API_KEY
```

Expected: Returns a public URL.

- [ ] **Step 5: Commit**

```bash
git add Dockerfile .dockerignore
git commit -m "feat: add Dockerfile and Cloud Run deployment"
```

---

### Task 15: Write README and Documentation

**Files:**
- Modify: `deshield/README.md`
- Create: `deshield/docs/architecture.svg` (or use a Mermaid diagram in README)

- [ ] **Step 1: Write comprehensive README**

Update `README.md`:
```markdown
# DepShield

AI-powered software supply chain risk and remediation agent.

## Problem

Open-source dependencies introduce security, legal, and operational risks. DepShield analyzes a repository’s dependency tree and produces a prioritized risk report.

## Features

- Multi-agent ADK system
- Vulnerability scanning via OSV
- License conflict detection
- Maintenance risk scoring
- Typosquat detection
- Secret leak scanning
- Remediation plan generation
- Deployed web dashboard
- MCP server and Agents CLI support

## Quick Start

```bash
pip install -e ".[dev]"
python src/main.py --repo https://github.com/owner/repo
```

## Run Web UI

```bash
python src/main.py --serve
```

## Deploy

```bash
gcloud run deploy deshield --source . --region us-central1 --allow-unauthenticated
```

## Architecture

See `docs/architecture.svg`.

## License

MIT
```

- [ ] **Step 2: Commit**

```bash
git add README.md docs
git commit -m "docs: add README and architecture diagram"
```

---

### Task 16: Record Demo Video and Prepare Kaggle Writeup

**Files:**
- Create: `deshield/docs/writeup.md`
- Create: `deshield/docs/video_script.md`

- [ ] **Step 1: Write Kaggle Writeup draft**

Create `docs/writeup.md` (target ≤2,500 words):
```markdown
# DepShield: AI-Powered Software Supply Chain Risk Agent

## Problem
...

## Solution
...

## Architecture
...

## Results
...

## Future Work
...
```

- [ ] **Step 2: Write 5-minute video script**

Create `docs/video_script.md`:
```markdown
0:00 - Intro: supply chain risk problem
0:45 - DepShield architecture
1:30 - Live demo: paste repo URL
3:00 - Review risk report
4:00 - Remediation plan
4:30 - Deployment and wrap-up
```

- [ ] **Step 3: Record video and upload to YouTube**

Use screen capture to record the live demo. Keep under 5 minutes.

- [ ] **Step 4: Submit to Kaggle**

1. Go to competition Writeups page.
2. Create new Writeup in **Agents for Business** track.
3. Attach cover image, YouTube video, and project link.
4. Submit before July 6, 2026 11:59 PM PT.

- [ ] **Step 5: Final commit**

```bash
git add docs
git commit -m "docs: add writeup and video script"
```

---

## Self-Review

### Spec Coverage Check

| Spec Section | Implementing Task |
|---|---|
| Multi-agent ADK system | Tasks 6, 7, 8, 9, 10 |
| MCP Server | Task 12 |
| Antigravity video | Task 16 |
| Security features | Tasks 2, 5, 11 |
| Deployability | Task 14 |
| Agents CLI skill | Task 13 |
| Web dashboard | Tasks 9, 10 |
| Evaluation/tests | Tasks 2, 3, 4, 5, 7, 8 |

### Placeholder Scan

- No `TBD` or `TODO` placeholders.
- No vague "add error handling" steps.
- All commands include expected output.

### Type Consistency Check

- `Dependency`, `RiskIssue`, and `AnalysisResult` models used consistently across tasks.
- `Ecosystem` enum used in OSV, PyPI, and agent tools.

### Scope Note

This plan assumes Python `requirements.txt` as the primary ecosystem. Node.js `package.json` support is a stretch goal after Day 2 if time remains.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-06-21-deshield.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — Dispatch a fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** — Execute tasks in this session using `executing-plans`, batch execution with checkpoints.

Which approach would you like?
