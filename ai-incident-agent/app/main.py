from fastapi import FastAPI
from app.collectors.health_check import check_application_health
app = FastAPI(
    title="NPCI AI Incident Agent",
    description="AI-powered incident diagnosis and recommendation service",
    version="1.0.0"
)


@app.get("/")
def root():
    return {
        "message": "NPCI AI Incident Agent is running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "ai-incident-agent"
    }

@app.get("/api/v1/collectors/health")
def collect_application_health(
    url: str = "http://127.0.0.1:8000/health"
):
    return check_application_health(url)