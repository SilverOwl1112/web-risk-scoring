# connectors/ssl_connector.py
import asyncio
from httpx import AsyncClient, Timeout
from ssllabs import Ssllabs

async def check_ssl_grade_async(domain: str) -> dict:
    """
    Async SSL Labs analysis with safe fallback.
    Returns: {"ssl_grade": "A"|"B"|...|"N/A", "ssl_issues": 0|1}
    """
    data = {"ssl_grade": "N/A", "ssl_issues": 0}
    try:
        timeout = Timeout(30.0, read=60.0)
        async with AsyncClient(timeout=timeout) as client:
            ssllabs = Ssllabs(client)
            analysis = await ssllabs.analyze(host=domain)
            endpoints = getattr(analysis, "endpoints", None)
            if endpoints and len(endpoints) > 0:
                endpoint = endpoints[0]
                grade = getattr(endpoint, "grade", None)
                if grade:
                    data["ssl_grade"] = grade
                    if grade not in ("A", "A+", "B"):
                        data["ssl_issues"] = 1
    except Exception as e:
        print(f"[ssl_connector] error: {e}")
    return data
