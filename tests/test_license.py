from src.tools.license_data import is_copyleft, check_compatibility


def test_mit_is_not_copyleft():
    assert is_copyleft("MIT") is False


def test_gpl_is_copyleft():
    assert is_copyleft("GPL-3.0") is True


def test_incompatible_with_proprietary():
    result = check_compatibility(["MIT", "GPL-3.0"], "proprietary")
    assert result.conflict is not None
