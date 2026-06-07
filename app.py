"""
NexusPi — backend FastAPI.

Lancement (sur le Pi) :
    cd ~/nexuspi
    source .venv/bin/activate
    uvicorn app:app --host 0.0.0.0 --port 8000

Puis depuis Windows : http://<IP_DU_PI>:8000
"""
import os
from pathlib import Path
from typing import Dict, Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from core.registry import load_modules
from core import memory
from core.tasks import TASKS, run_in_background

app = FastAPI(title="NexusPi", version="0.3.0")

# Registre chargé une fois au démarrage
MODULES = {m.id: m for m in load_modules()}

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


class RunRequest(BaseModel):
    params: Dict[str, Any] = {}
    lab_mode: bool = False


@app.get("/api/modules")
def list_modules():
    # to_dict() rappelle detect() -> statut "connecté" toujours à jour
    return [m.to_dict() for m in MODULES.values()]


@app.post("/api/modules/{module_id}/run/{action_id}")
def run_action(module_id: str, action_id: str, req: RunRequest):
    """
    Lance l'action en BACKGROUND et retourne un task_id immédiatement.
    Le front poll /api/tasks/<id> pour suivre l'avancement + récupérer
    les logs en temps réel, et peut envoyer /api/tasks/<id>/stop pour
    interrompre proprement.
    """
    module = MODULES.get(module_id)
    if module is None:
        return JSONResponse({"ok": False, "error": "module inconnu"}, status_code=404)

    # Garde-fou serveur : action lab_gated requiert lab_mode=True
    action = next((a for a in module.actions() if a.id == action_id), None)
    if action is None:
        return JSONResponse({"ok": False, "error": "action inconnue"}, status_code=404)
    if action.lab_gated and not req.lab_mode:
        return JSONResponse(
            {"ok": False, "error": "action verrouillée : activez le Lab mode."},
            status_code=403,
        )

    task = run_in_background(
        f"{module_id}.{action_id}",
        module.run, action_id, req.params,
    )
    return {"task_id": task.id, "label": task.label, "status": task.status}


@app.get("/api/tasks/{tid}")
def task_status(tid: str, since: int = 0):
    """Snapshot de la tâche : logs depuis l'index `since`, status, résultat."""
    t = TASKS.get(tid)
    if not t:
        raise HTTPException(404, "task introuvable")
    return t.snapshot(since_idx=since)


@app.post("/api/tasks/{tid}/stop")
def task_stop(tid: str):
    """Arme le flag d'arrêt — la tâche sortira via son cleanup."""
    return {"ok": TASKS.stop(tid)}


@app.get("/api/files")
def download_file(path: str):
    """
    Téléchargement d'une capture (handshake .cap, PMKID .22000, etc.).
    Garde-fou anti path-traversal : le path doit être STRICTEMENT dans
    ~/nexuspi-data/. Tout symlink/«..» qui en sort → 403.
    """
    try:
        target = Path(path).resolve(strict=True)
    except (OSError, FileNotFoundError):
        raise HTTPException(404, "file not found")
    if not memory.is_within_data_dir(target):
        raise HTTPException(403, "path not allowed")
    if not target.is_file():
        raise HTTPException(404, "not a file")
    return FileResponse(target, filename=target.name,
                        media_type="application/octet-stream")


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
