from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse

from src.agents.orchestrator import run_analysis

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    return """
    <!doctype html>
    <html><body class="p-5">
      <h1>DepShield</h1>
      <form action="/analyze" method="post">
        <input type="url" name="repo_url" placeholder="https://github.com/owner/repo" required class="form-control mb-2">
        <button type="submit" class="btn btn-primary">Analyze</button>
      </form>
    </body></html>
    """


@router.post("/analyze", response_class=HTMLResponse)
async def analyze(repo_url: str = Form(...)):
    result = await run_analysis(repo_url)
    return result["html"]
