from webscopex import inspect_response, score_headers


def test_score_headers():
    assert score_headers({"Content-Security-Policy": "x", "X-Content-Type-Options": "nosniff"}) == 2


def test_inspect_response():
    result = inspect_response(200, {"strict-transport-security": "max-age=1"}, 12.345)
    assert result["status"] == 200
    assert result["elapsed_ms"] == 12.35
