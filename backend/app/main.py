from fastapi import FastAPI

app = FastAPI(
    title="AI SOC SOAR MVP",
    description="Wazuh-first, SIEM-agnostic AI SOC automation backend",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/")
def root() -> dict:
    return {
        "name": "AI SOC SOAR MVP",
        "status": "base-ready",
        "docs": "/docs",
    }
