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
