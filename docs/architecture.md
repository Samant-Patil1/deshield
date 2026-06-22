# DepShield Architecture

## Overview

DepShield is a multi-agent system built with the Google Agent Development Kit (ADK). It receives a GitHub repository URL, clones the repository, extracts dependencies, runs several specialist analysis agents in parallel, synthesizes the results into prioritized risks, and renders a remediation plan plus an HTML dashboard.

## Components

### Web UI (`src/web/`)

- `app.py` — FastAPI application with rate-limiting middleware.
- `routes.py` — `/` form and `/analyze` endpoint.
- `templates/dashboard.html` — Bootstrap-based report template.

### Orchestrator (`src/agents/orchestrator.py`)

The ADK orchestrator agent receives the repo URL, delegates to `analyze_repo`, and returns the rendered HTML report. If the ADK Runner fails (for example, because no API key is configured), it falls back to calling `analyze_repo` directly so the UI remains functional.

### Specialist Agents (`src/agents/`)

| Agent | Responsibility | Data Sources |
|---|---|---|
| `ingestion` | Clone repo and parse manifests | GitHub, `requirements.txt`, `pyproject.toml` |
| `vulnerability` | Find known CVEs | OSV API |
| `license` | Detect copyleft/proprietary conflicts | PyPI metadata |
| `maintenance` | Score package health | PyPI metadata |
| `typosquat` | Flag suspiciously similar names | Popular package list |
| `secrets` | Detect leaked secrets | Local file scan |

### Synthesis & Reporting (`src/agents/`)

- `synthesizer.py` — Converts raw findings into `RiskIssue` objects, sorts them by severity, and computes an overall score.
- `remediation.py` — Generates ordered remediation steps from the top issues.
- `report.py` — Renders the results as HTML (Jinja2) and Markdown.

### Tools (`src/tools/`)

- `repo.py` — Safe GitHub URL validation and shallow cloning with timeout and size limits.
- `manifest.py` — Parses `requirements.txt` and PEP 621 `pyproject.toml` dependencies.
- `osv.py` — OSV API client with HTTP error handling.
- `pypi.py` — PyPI metadata fetcher and license/maintenance helpers.
- `license_data.py` — Copyleft detection and compatibility checks.
- `typosquat_logic.py` — Levenshtein-distance typosquat detection.
- `secrets_scanner.py` — Regex-based secret scanning.

### MCP Server (`src/mcp_server.py`)

Exposes `get_vulnerabilities` and `check_name_typosquat` as MCP tools so other agents can reuse DepShield's analysis capabilities.

## Security Measures

- Strict GitHub URL regex validation.
- Shallow clones with configurable timeout.
- Repository size cap (default 50 MB).
- In-memory per-IP rate limiting on the web UI.
- JSON structured logging for observability.
- `.env` and secrets excluded from Docker image and git history.

## Deployment Targets

- Local development with `python src/main.py --serve`.
- Docker container.
- Google Cloud Run (`gcloud run deploy --source .`).
