from src.tools.manifest import parse_requirements_txt, detect_manifests


def test_parse_requirements_txt():
    text = "requests==2.31.0\nflask>=2.0\n# comment\n"
    deps = parse_requirements_txt(text)
    assert len(deps) == 2
    assert deps[0].name == "requests"
    assert deps[0].version == "2.31.0"
