from app.collectors.health_check import check_application_health


result = check_application_health(
    "http://127.0.0.1:8000/health"
)

print(result)