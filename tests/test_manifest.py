from src.tools.manifest import parse_requirements_txt, parse_pyproject_toml


def test_parse_requirements_txt():
    text = "requests==2.31.0\nflask>=2.0\n# comment\n"
    deps = parse_requirements_txt(text)
    assert len(deps) == 2
    assert deps[0].name == "requests"
    assert deps[0].version == "2.31.0"


def test_parse_pyproject_toml_pep621():
    content = """
[project]
name = "example"
version = "1.0.0"
dependencies = [
    "requests==2.31.0",
    "flask>=2.0",
    "pytest",  # no version specifier, should be skipped
    "black>=23.0 ; python_version >= '3.11'",
]
"""
    deps = parse_pyproject_toml(content)
    assert len(deps) == 3
    names = {d.name for d in deps}
    assert names == {"requests", "flask", "black"}
    requests_dep = next(d for d in deps if d.name == "requests")
    assert requests_dep.version == "2.31.0"
