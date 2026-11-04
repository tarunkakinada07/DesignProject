"""Sentinel Extension Detector - Main FastAPI Application with Security Hardening."""

import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from backend.app.api.routes import router as api_router
from backend.app.core.config import settings

# Configure logging without secret/path leakage
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinel")

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Locally-run static malicious browser-extension detector using ML & heuristic rules.",
)


# Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self' http://localhost:8000 http://127.0.0.1:8000 http://localhost:5500 http://127.0.0.1:5500 ws://localhost:5500 ws://127.0.0.1:5500; "
        )
        return response


app.add_middleware(SecurityHeadersMiddleware)

# Restrict CORS to localhost only (including VS Code Live Server ports 5500-5505)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:5501",
        "http://127.0.0.1:5501",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


# Global Exception Handler preventing internal path leakage
@app.exception_handler(Exception)
async def global_sanitized_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled error processing request %s: %s", request.url.path, str(exc))
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred while processing the request safely."},
    )


# Register API routes under /api
app.include_router(api_router, prefix="/api")

# Serve frontend static assets if available
if settings.FRONTEND_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(settings.FRONTEND_DIR)), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_index():
        index_file = settings.FRONTEND_DIR / "index.html"
        if index_file.is_file():
            return FileResponse(str(index_file))
        return {"message": "Sentinel Extension Detector API active. Frontend index.html not yet present."}

    @app.get("/style.css", include_in_schema=False)
    async def serve_css():
        css_file = settings.FRONTEND_DIR / "style.css"
        if css_file.is_file():
            return FileResponse(str(css_file), media_type="text/css")
        return JSONResponse(status_code=404, content={"detail": "style.css not found"})

    @app.get("/app.js", include_in_schema=False)
    async def serve_js():
        js_file = settings.FRONTEND_DIR / "app.js"
        if js_file.is_file():
            return FileResponse(str(js_file), media_type="application/javascript")
        return JSONResponse(status_code=404, content={"detail": "app.js not found"})
