import argparse
import asyncio

import uvicorn

from src.agents.orchestrator import run_analysis


def main():
    parser = argparse.ArgumentParser(description="DepShield supply-chain risk agent")
    parser.add_argument("--repo", help="GitHub repository URL to analyze")
    parser.add_argument("--serve", action="store_true", help="Run the web UI")
    args = parser.parse_args()

    if args.serve:
        uvicorn.run("src.web.app:app", host="0.0.0.0", port=8080, reload=True)
    elif args.repo:
        result = asyncio.run(run_analysis(args.repo))
        print(result["markdown"])
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
