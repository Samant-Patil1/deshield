
from src.models import TyposquatFinding


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[-1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def check_typosquat(package: str, popular_packages: list[str], threshold: int = 2) -> TyposquatFinding | None:
    package_lower = package.lower()
    for popular in popular_packages:
        popular_lower = popular.lower()
        if package_lower == popular_lower:
            continue
        distance = _levenshtein(package_lower, popular_lower)
        if distance <= threshold:
            return TyposquatFinding(
                package=package,
                similar_to=popular,
                distance=distance,
                reason=f"Name is {distance} edits away from popular package '{popular}'",
            )
    return None
