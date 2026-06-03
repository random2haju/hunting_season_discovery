"""
Threat Hunt Web Interface — FastAPI entry point

Usage:
    python web/app.py
"""

import os
import sys
import threading
import webbrowser

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

# Ensure both the repo root (for consolidate.py) and web/ (for api/ + state.py) are importable
_WEB_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.dirname(_WEB_DIR)
for _p in (_WEB_DIR, _ROOT_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from api.insights import router as insights_router
from api.pipeline import router as pipeline_router
from api.priority import router as priority_router
from api.seasons import router as seasons_router
from api.episodes import router as episodes_router
from api.history import router as history_router
from api.suppressions import router as suppressions_router
from api.recommendations import router as recommendations_router
from api.patterns import router as patterns_router
from state import find_latest_excel, load_from_excel

app = FastAPI(title="Threat Hunt Dashboard", version="1.0.0")

# Allow Vite dev server (port 5173) during frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(insights_router, prefix="/api")
app.include_router(pipeline_router, prefix="/api")
app.include_router(priority_router, prefix="/api")
app.include_router(seasons_router, prefix="/api")
app.include_router(episodes_router, prefix="/api")
app.include_router(history_router, prefix="/api")
app.include_router(suppressions_router, prefix="/api")
app.include_router(recommendations_router, prefix="/api")
app.include_router(patterns_router, prefix="/api")

# Serve the built React bundle.
# Routes are registered unconditionally — if dist/ hasn't been built yet
# the handlers return a 503 with instructions rather than a silent 404.
_frontend_dist = os.path.join(_WEB_DIR, "frontend", "dist")
_index = os.path.join(_frontend_dist, "index.html")
_assets_dir = os.path.join(_frontend_dist, "assets")

if os.path.isdir(_assets_dir):
    app.mount("/assets", StaticFiles(directory=_assets_dir), name="assets")


def _serve_index():
    if os.path.isfile(_index):
        return FileResponse(_index)
    return HTMLResponse(
        "<h2>Frontend not built.</h2>"
        "<p>Run: <code>cd web/frontend && npm install && npm run build</code></p>",
        status_code=503,
    )


@app.get("/", include_in_schema=False)
async def serve_root():
    return _serve_index()


@app.get("/{full_path:path}", include_in_schema=False)
async def serve_spa(full_path: str):
    return _serve_index()


@app.on_event("startup")
async def on_startup():
    path = find_latest_excel()
    if path:
        try:
            load_from_excel(path)
            print(f"[*] Auto-loaded: {os.path.basename(path)}")
        except Exception as e:
            print(f"[WARN] Could not auto-load latest Excel: {e}")
    else:
        print("[*] No output Excel found — use the dashboard to run the pipeline.")


def _open_browser():
    import time
    time.sleep(1.2)
    webbrowser.open("http://localhost:8000")


if __name__ == "__main__":
    threading.Thread(target=_open_browser, daemon=True).start()
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)
