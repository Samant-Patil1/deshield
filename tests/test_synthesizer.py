from src.agents.synthesizer import synthesize_risks
from src.models import Dependency, Ecosystem, Vulnerability


def test_synthesize_flags_critical_vuln():
    deps = [Dependency(name="requests", version="2.31.0", ecosystem=Ecosystem.PYTHON)]
    vulns = [
        Vulnerability(
            id="PYSEC-2023-1",
            summary="Bad thing",
            severity="CVSS_V3",
            cvss_score=9.0,
            fixed_version="2.32.0",
            aliases=[],
        )
    ]
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
