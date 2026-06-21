import pytest
from src.tools.repo import clone_repo
from src.config import settings


def test_clone_repo_returns_path(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "clone_timeout_seconds", 30)
    path = clone_repo("https://github.com/octocat/Hello-World", tmp_path)
    assert path.exists()
    assert (path / "README").exists()
