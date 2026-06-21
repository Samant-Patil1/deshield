from src.tools.license_data import is_copyleft, check_compatibility, check_package_license


def test_mit_is_not_copyleft():
    assert is_copyleft("MIT") is False


def test_gpl_is_copyleft():
    assert is_copyleft("GPL-3.0") is True


def test_incompatible_with_proprietary():
    result = check_compatibility(["MIT", "GPL-3.0"], "proprietary")
    assert result.conflict is not None


def test_check_package_license_detects_copyleft_conflict():
    result = check_package_license("django", "4.2", "GPL-3.0", "proprietary")
    assert result is not None
    assert result.package == "django"
    assert result.is_copyleft is True
    assert "incompatible with proprietary" in result.conflict


def test_check_package_license_no_conflict_for_permissive():
    assert check_package_license("requests", "2.31.0", "MIT", "proprietary") is None
