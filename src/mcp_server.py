from mcp.server.fastmcp import FastMCP
from src.tools.osv import query_osv
from src.tools.typosquat_logic import check_typosquat
from src.models import Ecosystem

mcp = FastMCP("deshield")


@mcp.tool()
def get_vulnerabilities(package: str, version: str, ecosystem: str) -> list[dict]:
    """Query OSV for known vulnerabilities in a package."""
    return [v.model_dump() for v in query_osv(package, version, Ecosystem(ecosystem))]


@mcp.tool()
def check_name_typosquat(package: str, popular_packages: list[str]) -> dict | None:
    """Check if a package name is a typosquat of a popular package."""
    result = check_typosquat(package, popular_packages)
    return result.model_dump() if result else None


if __name__ == "__main__":
    mcp.run()
