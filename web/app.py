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
from fastapi.staticfiles import StaticFiles

# Ensure both the repo root (for consolidate.py) and web/ (for api/ + state.py) are importable
_WEB_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.dirname(_WEB_DIR)
for _p in (_WEB_DIR, _ROOT_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from api.pipeline import router as pipeline_router
from api.priority import router as priority_router
from api.seasons import router as seasons_router
from api.graph import router as graph_router
from api.episodes import router as episodes_router
from api.history import router as history_router
from api.stacking import router as stacking_router
from api.suppressions import router as suppressions_router
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

app.include_router(pipeline_router, prefix="/api")
app.include_router(priority_router, prefix="/api")
app.include_router(seasons_router, prefix="/api")
app.include_router(graph_router, prefix="/api")
app.include_router(episodes_router, prefix="/api")
app.include_router(history_router, prefix="/api")
app.include_router(stacking_router, prefix="/api")
app.include_router(suppressions_router, prefix="/api")

# Serve the built React bundle when it exists (production mode)
_frontend_dist = os.path.join(_WEB_DIR, "frontend", "dist")
if os.path.isdir(_frontend_dist):
    app.mount("/", StaticFiles(directory=_frontend_dist, html=True), name="frontend")


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
