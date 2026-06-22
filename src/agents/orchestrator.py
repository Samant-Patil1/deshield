from pathlib import Path
import json

from google.adk.agents import Agent
from google.adk.tools import FunctionTool
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai.types import Content, Part

from src.agents.ingestion import ingest_repo
from src.agents.vulnerability import find_vulnerabilities
from src.agents.license import analyze_licenses
from src.agents.maintenance import analyze_maintenance
from src.agents.typosquat import analyze_typosquats
from src.agents.secrets import analyze_secrets
from src.agents.synthesizer import synthesize_risks
from src.agents.report import render_html, render_markdown
from src.models import (
    Dependency,
    Vulnerability,
    LicenseFinding,
    MaintenanceFinding,
    TyposquatFinding,
    SecretFinding,
)
from src.utils.logging import get_logger

logger = get_logger(__name__)

POPULAR_PACKAGES = [
    "requests",
    "flask",
    "django",
    "numpy",
    "pandas",
    "matplotlib",
    "scipy",
    "scikit-learn",
    "tensorflow",
    "pytorch",
    "pytest",
    "celery",
    "redis",
    "sqlalchemy",
    "boto3",
    "fastapi",
    "pydantic",
    "httpx",
    "jinja2",
]


def analyze_repo(repo_url: str) -> dict:
    ingest_result = ingest_repo(repo_url)
    repo_path = Path(ingest_result["repo_path"])
    deps = [Dependency(**d) for d in ingest_result["dependencies"]]

    vulns_by_dep: dict[str, list[Vulnerability]] = {}
    license_findings: list[LicenseFinding] = []
    maintenance_findings: list[MaintenanceFinding] = []
    typosquat_findings: list[TyposquatFinding] = []

    if deps:
        dep_dicts = [d.model_dump() for d in deps]
        for dep in deps:
            key = f"{dep.name}=={dep.version}"
            vulns_by_dep[key] = [
                Vulnerability(**v)
                for v in find_vulnerabilities([dep.model_dump()])
            ]
        license_findings = [LicenseFinding(**f) for f in analyze_licenses(dep_dicts)]
        maintenance_findings = [
            MaintenanceFinding(**f) for f in analyze_maintenance(dep_dicts)
        ]
        typosquat_findings = [
            TyposquatFinding(**f)
            for f in analyze_typosquats(dep_dicts, POPULAR_PACKAGES)
        ]

    secret_findings = [SecretFinding(**f) for f in analyze_secrets(str(repo_path))]

    result = synthesize_risks(
        repo_url=repo_url,
        deps=deps,
        vulnerabilities=vulns_by_dep,
        license_findings=license_findings,
        maintenance_findings=maintenance_findings,
        typosquat_findings=typosquat_findings,
        secret_findings=secret_findings,
    )
    return {
        "html": render_html(result),
        "markdown": render_markdown(result),
        "score": result.overall_score,
    }


orchestrator_agent = Agent(
    name="deshield_orchestrator",
    model="gemini-2.0-flash",
    instruction="You are DepShield. When given a GitHub repository URL, call analyze_repo and return the HTML report.",
    tools=[FunctionTool(analyze_repo)],
)


async def run_analysis(repo_url: str) -> dict:
    session_service = InMemorySessionService()
    session = await session_service.create_session(app_name="deshield", user_id="user")
    runner = Runner(
        agent=orchestrator_agent,
        app_name="deshield",
        session_service=session_service,
    )
    content = Content(
        role="user",
        parts=[Part(text=json.dumps({"repo_url": repo_url}))],
    )
    try:
        async for event in runner.run_async(
            user_id="user",
            session_id=session.id,
            new_message=content,
        ):
            if event.is_final_response() and event.content:
                text = event.content.parts[0].text
                return json.loads(text)
    except Exception as exc:
        logger.warning(
            "Orchestrator Runner failed (%s). Falling back to direct analyze_repo call.",
            exc,
        )
        return analyze_repo(repo_url)

    raise RuntimeError("No final response from orchestrator")
