from google.adk.agents import Agent
from google.adk.tools import FunctionTool
from src.tools.pypi import fetch_pypi_latest_metadata, score_maintenance
from src.models import MaintenanceFinding


def analyze_maintenance(deps: list[dict]) -> list[dict]:
    findings = []
    for dep in deps:
        metadata = fetch_pypi_latest_metadata(dep["name"])
        score, days = score_maintenance(metadata)
        if score is None:
            continue
        info = metadata.get("info", {})
        maintainers = info.get("maintainers")
        maintainer_count = (
            len(maintainers)
            if maintainers
            else len([x for x in [info.get("author"), info.get("maintainer")] if x])
        )
        findings.append(
            MaintenanceFinding(
                package=dep["name"],
                version=dep["version"],
                score=score,
                last_release_days=days,
                maintainers=maintainer_count,
            ).model_dump()
        )
    return findings


maintenance_agent = Agent(
    name="maintenance_agent",
    model="gemini-2.5-flash",
    instruction="Score dependency maintenance risk using PyPI metadata.",
    tools=[FunctionTool(analyze_maintenance)],
)
