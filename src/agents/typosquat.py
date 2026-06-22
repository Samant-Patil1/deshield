from google.adk.agents import Agent
from google.adk.tools import FunctionTool
from src.tools.typosquat_logic import check_typosquat


def analyze_typosquats(deps: list[dict], popular_packages: list[str]) -> list[dict]:
    findings = []
    for dep in deps:
        result = check_typosquat(dep["name"], popular_packages)
        if result:
            findings.append(result.model_dump())
    return findings


typosquat_agent = Agent(
    name="typosquat_agent",
    model="gemini-2.0-flash",
    instruction="Detect typosquatting risks in dependency names.",
    tools=[FunctionTool(analyze_typosquats)],
)
