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
