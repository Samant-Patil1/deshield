from src.models import (
    AnalysisResult,
    Dependency,
    Ecosystem,
    RiskIssue,
    Vulnerability,
    LicenseFinding,
    MaintenanceFinding,
    TyposquatFinding,
    SecretFinding,
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
            issues.append(
                RiskIssue(
                    package=dep.name,
                    version=dep.version,
                    category="vulnerability",
                    severity=_severity_from_cvss(vuln.cvss_score),
                    title=f"Vulnerability {vuln.id}",
                    description=vuln.summary or "No summary available",
                    recommendation=f"Upgrade to {vuln.fixed_version}"
                    if vuln.fixed_version
                    else "Review advisory",
                )
            )

    for finding in license_findings:
        issues.append(
            RiskIssue(
                package=finding.package or "unknown",
                version=finding.version or "unknown",
                category="license",
                severity="high" if finding.is_copyleft else "medium",
                title="License conflict",
                description=finding.conflict or "License issue detected",
                recommendation="Review license compatibility",
            )
        )

    for finding in maintenance_findings:
        issues.append(
            RiskIssue(
                package=finding.package,
                version=finding.version,
                category="maintenance",
                severity="high" if finding.score.value == "abandoned" else "medium",
                title=f"Maintenance risk: {finding.score.value}",
                description=f"Last release {finding.last_release_days} days ago; {finding.maintainers} maintainers",
                recommendation="Consider migrating to an actively maintained alternative",
            )
        )

    for finding in typosquat_findings:
        issues.append(
            RiskIssue(
                package=finding.package,
                version="unknown",
                category="typosquat",
                severity="critical",
                title="Possible typosquat",
                description=finding.reason,
                recommendation="Verify package name and replace if suspicious",
            )
        )

    for finding in secret_findings:
        issues.append(
            RiskIssue(
                package="repo",
                version="",
                category="secret",
                severity="critical",
                title="Potential secret leak",
                description=f"{finding.rule} in {finding.file}",
                recommendation="Rotate the secret and remove it from history",
            )
        )

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_issues = sorted(
        issues, key=lambda i: (severity_order.get(i.severity, 5), i.package)
    )
    score = max(
        0, 100 - len([i for i in sorted_issues if i.severity in ("critical", "high")]) * 10
    )

    return AnalysisResult(
        repo_url=repo_url,
        dependencies=deps,
        issues=sorted_issues,
        top_issues=sorted_issues[:10],
        overall_score=score,
    )
