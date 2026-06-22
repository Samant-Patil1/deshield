# DepShield Demo Video Script (≤ 5 minutes)

## 0:00 - 0:45 — Problem & Hook
- Open with the competition prompt: supply chain attacks are rising.
- Show a real-world example: a popular package with a CVE, a typosquat, or a leaked secret.
- State the goal: "DepShield analyzes any GitHub repo's dependencies and tells you exactly what to fix first."

## 0:45 - 1:30 — Architecture Overview
- Show the architecture diagram.
- Explain the orchestrator agent and the parallel specialist agents.
- Mention security, MCP server, and Cloud Run deployment in one sentence each.

## 1:30 - 3:00 — Live CLI Demo
- Run `python src/main.py --repo https://github.com/owner/repo`.
- Show the Markdown report: overall score, top issues, and remediation steps.
- Highlight a vulnerability, a license conflict, or a secret finding.

## 3:00 - 4:00 — Web Dashboard Demo
- Run `python src/main.py --serve`.
- Open the browser at `http://localhost:8080`.
- Paste a repo URL and submit.
- Show the HTML report with Bootstrap cards, severity badges, and the remediation plan.

## 4:00 - 4:30 — Code Walkthrough (very brief)
- Show `src/agents/orchestrator.py` and the ADK Runner usage.
- Show `src/mcp_server.py` exposing tools.
- Show the Dockerfile and Cloud Run command.

## 4:30 - 5:00 — Wrap-up
- Recap the value: fast, prioritized, actionable supply-chain risk analysis.
- Show the GitHub repo URL and the live Cloud Run link.
- End with the project tagline.

## Recording Tips
- Use a clean terminal with a dark theme.
- Use a screen recorder with a visible mouse cursor.
- Keep transitions quick; the live demo should drive the video.
