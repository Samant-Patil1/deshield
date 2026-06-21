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
