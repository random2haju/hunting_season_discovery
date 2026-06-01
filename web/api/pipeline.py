"""
Pipeline control endpoints.

GET  /api/status            — is data loaded?
GET  /api/pipeline/run      — run consolidate.py, stream logs via SSE
POST /api/pipeline/reload   — reload state from latest Excel (no reprocessing)
"""

import asyncio
import json
import os
import sys

from fastapi import APIRouter
from fastapi.responses import JSONResponse, StreamingResponse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from state import state, find_latest_excel, load_from_excel, ROOT_DIR, OUTPUT_DIR, CONFIG_PATH, DATA_DIR

router = APIRouter()


@router.get("/status")
def get_status():
    return {
        "is_loaded": state.is_loaded,
        "is_running": state.is_running,
        "error": state.error,
        "loaded_file": state.loaded_file,
    }


@router.post("/pipeline/reload")
def reload_data():
    if state.is_running:
        return JSONResponse(status_code=409, content={"error": "Pipeline is already running"})
    path = find_latest_excel()
    if not path:
        return JSONResponse(
            status_code=404,
            content={"error": "No output Excel found. Run the pipeline first."},
        )
    state.is_running = True
    try:
        load_from_excel(path)
        return {"ok": True, "loaded_file": state.loaded_file}
    except Exception as e:
        state.error = str(e)
        return JSONResponse(status_code=500, content={"error": str(e)})
    finally:
        state.is_running = False


@router.get("/pipeline/run")
async def run_pipeline():
    """
    Runs consolidate.py as a subprocess and streams its stdout line-by-line
    as Server-Sent Events. On success, reloads state from the new Excel file.

    SSE event shape: {"type": "log"|"done"|"error", "message": "..."}
    """
    if state.is_running:
        return JSONResponse(status_code=409, content={"error": "Pipeline is already running"})

    state.is_running = True
    state.error = None

    async def event_stream():
        script = os.path.join(ROOT_DIR, "consolidate.py")
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, script,
                "--data-dir", DATA_DIR,
                "--config", CONFIG_PATH,
                "--out", OUTPUT_DIR,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=ROOT_DIR,
            )
            async for raw in proc.stdout:
                line = raw.decode("utf-8", errors="replace").rstrip()
                yield f"data: {json.dumps({'type': 'log', 'message': line})}\n\n"

            await proc.wait()

            if proc.returncode == 0:
                path = find_latest_excel()
                if path:
                    try:
                        load_from_excel(path)
                        yield f"data: {json.dumps({'type': 'done', 'message': f'Loaded {os.path.basename(path)}'})}\n\n"
                    except Exception as e:
                        state.error = str(e)
                        yield f"data: {json.dumps({'type': 'error', 'message': f'Pipeline succeeded but failed to load output: {e}'})}\n\n"
                else:
                    yield f"data: {json.dumps({'type': 'error', 'message': 'Pipeline succeeded but no output Excel found'})}\n\n"
            else:
                state.error = f"Exit code {proc.returncode}"
                yield f"data: {json.dumps({'type': 'error', 'message': f'Pipeline exited with code {proc.returncode}'})}\n\n"

        except Exception as e:
            state.error = str(e)
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
        finally:
            state.is_running = False

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
