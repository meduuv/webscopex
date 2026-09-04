from __future__ import annotations

from collections.abc import Mapping

SECURITY_HEADERS = ("content-security-policy", "strict-transport-security", "x-content-type-options", "referrer-policy")


def score_headers(headers: Mapping[str, str]) -> int:
    normalized = {k.lower() for k in headers}
    return sum(h in normalized for h in SECURITY_HEADERS)


def inspect_response(status: int, headers: Mapping[str, str], elapsed_ms: float) -> dict[str, object]:
    return {
        "status": int(status),
        "elapsed_ms": round(float(elapsed_ms), 2),
        "header_score": score_headers(headers),
        "missing_security_headers": [h for h in SECURITY_HEADERS if h not in {k.lower() for k in headers}],
    }
