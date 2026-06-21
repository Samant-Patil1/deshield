from pathlib import Path
import json

from google.adk.agents import Agent
from google.adk.tools import FunctionTool
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai.types import Content, Part

from src.tools.repo import clone_repo
from src.tools.manifest import detect_manifests, parse_requirements_txt, parse_pyproject_toml
from src.tools.osv import query_osv
from src.tools.secrets_scanner import scan_secrets
from src.models import Dependency, Ecosystem, AnalysisResult
from src.agents.synthesizer import synthesize_risks
from src.agents.report import render_html, render_markdown
from src.utils.logging import get_logger

logger = get_logger(__name__)


def analyze_repo(repo_url: str) -> dict:
    repo_path = clone_repo(repo_url)
    manifests = detect_manifests(repo_path)
    deps: list[Dependency] = []
    for manifest in manifests:
        if manifest.name == "requirements.txt":
            deps.extend(parse_requirements_txt(manifest.read_text()))
        elif manifest.name == "pyproject.toml":
            deps.extend(parse_pyproject_toml(manifest.read_text()))

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
