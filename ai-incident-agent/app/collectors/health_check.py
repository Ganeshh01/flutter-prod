import time
import httpx


def check_application_health(url: str) -> dict:
    """
    Checks an application's health endpoint
    and returns structured incident evidence.
    """

    start_time = time.time()

    try:
        response = httpx.get(url, timeout=5.0)

        response_time = round(
            (time.time() - start_time) * 1000, 2
        )

        return {
            "collector": "application_health",
            "url": url,
            "status": "healthy" if response.is_success else "unhealthy",
            "http_status_code": response.status_code,
            "response_time_ms": response_time,
            "evidence": (
                "Application health endpoint responded successfully."
                if response.is_success
                else "Application health endpoint returned an error."
            )
        }

    except httpx.TimeoutException:
        return {
            "collector": "application_health",
            "url": url,
            "status": "unhealthy",
            "error": "timeout",
            "evidence": "Application health endpoint timed out."
        }

    except httpx.RequestError as error:
        return {
            "collector": "application_health",
            "url": url,
            "status": "unhealthy",
            "error": str(error),
            "evidence": "Unable to connect to the application."
        }