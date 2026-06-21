from google.adk.agents import Agent
from google.adk.tools import FunctionTool
from src.tools.pypi import fetch_pypi_metadata, score_maintenance
from src.models import MaintenanceFinding


def analyze_maintenance(deps: list[dict]) -> list[dict]:
    findings = []
    for dep in deps:
        metadata = fetch_pypi_metadata(dep["name"], dep["version"])
        score = score_maintenance(metadata)
        findings.append(MaintenanceFinding(
            package=dep["name"],
            version=dep["version"],
            score=score,
        ).model_dump())
    return findings


maintenance_agent = Agent(
    name="maintenance_agent",
    model="gemini-2.5-flash",
    instruction="Score dependency maintenance risk using PyPI metadata.",
    tools=[FunctionTool(analyze_maintenance)],
)
