import httpx
import respx
from src.tools.osv import query_osv
from src.models import Ecosystem


@respx.mock
def test_query_osv_returns_vulns():
    route = respx.post("https://api.osv.dev/v1/query").mock(
        return_value=httpx.Response(200, json={"vulns": []})
    )
    result = query_osv("requests", "2.31.0", Ecosystem.PYTHON)
    assert result == []
    assert route.called
