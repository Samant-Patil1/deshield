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
