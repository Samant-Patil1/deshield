from pathlib import Path
from google.adk.agents import Agent
from google.adk.tools import FunctionTool
from src.tools.secrets_scanner import scan_secrets


def analyze_secrets(repo_path: str) -> list[dict]:
    findings = scan_secrets(Path(repo_path))
    return [f.model_dump() for f in findings]


secrets_agent = Agent(
    name="secrets_agent",
    model="gemini-2.5-flash",
    instruction="Scan a cloned repository for potential secret leaks.",
    tools=[FunctionTool(analyze_secrets)],
)
