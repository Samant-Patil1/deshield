from src.tools.typosquat_logic import check_typosquat


def test_typosquat_detects_close_name():
    popular = ["requests", "flask", "django"]
    result = check_typosquat("reqeusts", popular)
    assert result is not None
    assert result.similar_to == "requests"
