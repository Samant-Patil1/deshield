from google.adk.agents import Agent
from google.adk.tools import FunctionTool
from src.tools.license_data import check_compatibility


def analyze_licenses(deps: list[dict]) -> list[dict]:
    licenses = [d.get("license") for d in deps if d.get("license")]
    finding = check_compatibility(licenses, "proprietary")
    return [finding.model_dump()] if finding.conflict else []


license_agent = Agent(
    name="license_agent",
    model="gemini-2.5-flash",
    instruction="Detect license conflicts in dependencies.",
    tools=[FunctionTool(analyze_licenses)],
)
