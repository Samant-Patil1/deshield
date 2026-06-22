from google.adk.agents import Agent
from google.adk.tools import FunctionTool
from src.models import Ecosystem
from src.tools.pypi import fetch_pypi_metadata, get_package_license
from src.tools.license_data import check_package_license


def analyze_licenses(deps: list[dict]) -> list[dict]:
    findings = []
    for dep in deps:
        if dep.get("ecosystem") != Ecosystem.PYTHON:
            continue
        name = dep.get("name")
        version = dep.get("version")
        if not name or not version:
            continue
        metadata = fetch_pypi_metadata(name, version)
        license_expr = get_package_license(metadata)
        if not license_expr:
            continue
        finding = check_package_license(name, version, license_expr, "proprietary")
        if finding:
            findings.append(finding.model_dump())
    return findings


license_agent = Agent(
    name="license_agent",
    model="gemini-2.0-flash",
    instruction="Detect license conflicts in dependencies.",
    tools=[FunctionTool(analyze_licenses)],
)
