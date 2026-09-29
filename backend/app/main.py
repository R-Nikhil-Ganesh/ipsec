"""
IPsec Sentinel — AI-Powered IPsec VPN Security Intelligence Platform
Main FastAPI Application Entrypoint
"""
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router as api_router
from app.database.db import init_db
from app.utils.synthetic_generator import generate_all_pcaps

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Check if sample pcaps exist, if not, generate them
    sample_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "sample_pcaps")
    if not os.path.exists(sample_dir) or not os.listdir(sample_dir):
        generate_all_pcaps()
    yield

app = FastAPI(
    title="IPsec Sentinel Intelligence Engine",
    description="AI-Assisted Defensive Security Platform for IPsec VPN PCAP Analysis, Digital Twin Reconstruction, Cryptographic Risk Assessment, and Hardening Simulation.",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")


@app.get("/")
def root():
    return {
        "platform": "IPsec Sentinel — AI-Powered IPsec VPN Security Intelligence Platform",
        "status": "Operational",
        "version": "1.0.0",
        "docs_url": "/docs"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
