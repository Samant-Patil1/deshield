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
