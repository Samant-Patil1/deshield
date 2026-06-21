from src.models import LicenseFinding


COPYLEFT_LICENSES = {
    "GPL-2.0", "GPL-3.0", "LGPL-2.1", "LGPL-3.0",
    "AGPL-3.0", "MPL-2.0", "EPL-2.0", "CC-BY-SA-4.0",
}


def is_copyleft(license_expr: str | None) -> bool:
    if not license_expr:
        return False
    upper = license_expr.upper()
    return any(lic.upper() in upper for lic in COPYLEFT_LICENSES)


def check_compatibility(licenses: list[str], target_policy: str) -> LicenseFinding:
    for lic in licenses:
        if is_copyleft(lic) and target_policy == "proprietary":
            return LicenseFinding(
                package="",
                version="",
                license_expr=lic,
                is_copyleft=True,
                conflict=f"Copyleft license {lic} is incompatible with proprietary distribution",
            )
    return LicenseFinding(
        package="",
        version="",
        license_expr=licenses[0] if licenses else None,
        is_copyleft=False,
        conflict=None,
    )
