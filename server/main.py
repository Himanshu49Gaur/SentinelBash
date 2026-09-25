"""
SentinelBash - Master FastAPI Application Server
Initializes FastAPI, mounts REST & SSE route modules, configures security headers, and binds static assets.
"""

import os
import sys
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
STATIC_DIR = os.path.join(PROJECT_ROOT, "static")

if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from db.init_db import init_database
from routes import auth, health, incidents, containment, rules, stream

# Initialize FastAPI Application
app = FastAPI(
    title="SentinelBash Mini-SOC API",
    description="Lightweight SIEM & SOAR Automation Engine Management REST Gateway",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configure CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    print(f"[!] Unhandled error on {request.method} {request.url.path}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error occurred.", "path": str(request.url.path)},
    )


# Mount REST and SSE Route Controllers
app.include_router(auth.router)
app.include_router(health.router)
app.include_router(incidents.router)
app.include_router(containment.router)
app.include_router(rules.router)
app.include_router(stream.router)


# Mount Static Files (Prepared for Phase 4 Web Console)
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
async def serve_index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {
        "name": "SentinelBash Mini-SOC Management API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/v1/health",
        "metrics": "/api/v1/metrics",
    }


# Lifespan / Startup Hook
@app.on_event("startup")
async def on_startup():
    try:
        init_database()
        print("[+] Database verified and initialized on FastAPI startup.")
    except Exception as e:
        print(f"[!] Startup database error: {e}")
