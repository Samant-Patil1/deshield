# DepShield: AI-Powered Software Supply Chain Risk Agent

## Problem

Modern software is built on top of hundreds of open-source dependencies. Every package pulled into a project is a potential source of:

- Security vulnerabilities
- License conflicts
- Maintenance debt
- Typosquatting attacks
- Leaked secrets

Most teams do not have time to audit every dependency. Existing tools usually focus on a single risk type, require complex configuration, or produce noisy reports that engineers struggle to act on.

DepShield solves this by combining multiple supply-chain risk checks into one cohesive, agentic analysis pipeline. It clones a GitHub repository, extracts its dependency tree, runs several specialist analyses in parallel, and returns a prioritized risk report with a concrete remediation plan.

## Solution

DepShield is a multi-agent system built with the Google Agent Development Kit (ADK). A single orchestrator agent receives a repository URL and coordinates parallel specialist agents for:

- Ingestion
- Vulnerability scanning
- License analysis
- Maintenance scoring
- Typosquat detection
- Secret scanning

A risk synthesizer combines the findings, a remediation agent generates actionable steps, and a report agent renders the results as an HTML dashboard and Markdown summary.

The system is packaged as an Agents CLI skill (`agent.json`), exposes core tools through an MCP server, and is containerized for deployment to Google Cloud Run.

## Architecture

The pipeline has five stages:

1. **Ingestion** — clones the repository with a shallow, time-bounded git fetch and parses `requirements.txt`, PEP 621 `pyproject.toml`, and `package.json` files.
2. **Specialist analysis** — parallel agents query OSV for vulnerabilities, PyPI for license and maintainer metadata, compare names against popular packages for typosquats, and scan the repo for secrets.
3. **Synthesis** — raw findings are normalized into `RiskIssue` objects, sorted by severity, and aggregated into an overall score from 0 to 100.
4. **Remediation** — the top issues are turned into ordered steps such as “Upgrade package X to version Y” or “Replace suspicious typosquat package Z.”
5. **Reporting** — results are rendered through a Jinja2 HTML dashboard and a Markdown summary.

Security is built in from the start: GitHub URLs are validated with a strict regex, clones are shallow and size-capped, temporary directories are cleaned up on failure, the web UI includes per-IP rate limiting, and all logs are emitted as structured JSON.

## Key Technologies

- **Google ADK** for the orchestrator and specialist agents
- **FastAPI + Jinja2** for the web dashboard
- **OSV API** for vulnerability data
- **PyPI API** for package metadata
- **MCP** for exposing reusable analysis tools
- **Docker + Google Cloud Run** for deployment

## Results

The implementation includes:

- 13 automated tests covering repo cloning, manifest parsing, OSV queries, license detection, typosquat logic, secret scanning, risk synthesis, and remediation
- A working FastAPI UI that returns an HTML report
- A Docker image that runs the service on port 8080
- An MCP server exposing vulnerability and typosquat tools

Running DepShield against a small public Python repository produces a score, a list of top issues, and a remediation plan within seconds.

## Future Work

- Add transitive dependency resolution using `pipdeptree` or `npm ls`
- Integrate `gitleaks` for more robust secret scanning
- Add CVSS score extraction from OSV severity data
- Support private repositories via `GITHUB_TOKEN`
- Add an evaluation harness with known vulnerable repositories

## Submission Links

- **Repository:** https://github.com/Samant-Patil1/deshield
- **Demo video:** [YouTube link to be added]
- **Live demo:** [Cloud Run URL to be added]
