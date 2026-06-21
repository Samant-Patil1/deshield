from src.tools.secrets_scanner import scan_secrets


def test_scan_detects_api_key(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "config.py").write_text("AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\n")
    findings = scan_secrets(repo)
    assert len(findings) > 0
    assert any("AWS" in f.rule for f in findings)
