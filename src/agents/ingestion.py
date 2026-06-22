from google.adk.agents import Agent
from google.adk.tools import FunctionTool
from src.tools.repo import clone_repo, validate_repo_url
from src.tools.manifest import detect_manifests, parse_requirements_txt, parse_pyproject_toml, parse_package_json
from src.models import Dependency


def ingest_repo(repo_url: str) -> dict:
    validate_repo_url(repo_url)
    repo_path = clone_repo(repo_url)
    manifests = detect_manifests(repo_path)
    deps: list[Dependency] = []
    for manifest in manifests:
        if manifest.name == "requirements.txt":
            deps.extend(parse_requirements_txt(manifest.read_text()))
        elif manifest.name == "pyproject.toml":
            deps.extend(parse_pyproject_toml(manifest.read_text()))
        elif manifest.name == "package.json":
            deps.extend(parse_package_json(manifest.read_text()))
    return {
        "repo_path": str(repo_path),
        "dependencies": [d.model_dump() for d in deps],
    }


ingestion_agent = Agent(
    name="ingestion_agent",
    model="gemini-2.0-flash",
    instruction="You ingest a GitHub repository and return its Python and Node.js dependencies.",
    tools=[FunctionTool(ingest_repo)],
)
