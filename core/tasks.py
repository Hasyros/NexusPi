"""
NexusPi — registre de tâches background pour les actions longues.

Modèle :
  - Une action POST `/api/modules/.../run/...` crée une Task et lance le
    `module.run()` dans un thread daemon.
  - Le front poll `GET /api/tasks/<id>?since=N` toutes les ~1s pour
    récupérer les nouveaux logs et le statut.
  - `POST /api/tasks/<id>/stop` arme l'event d'arrêt — les boucles longues
    le checkent et sortent via leur cleanup.

API exposée aux modules (via thread-local) :

    from core.tasks import current_task
    t = current_task()                  # peut être None si appel hors tâche
    if t: t.log("hostapd lancé")
    if t and t.is_stopped(): return ...  # respect demande d'arrêt
    t.wait(15)                           # sleep interruptible
"""
import threading
import time
import traceback
import uuid
from typing import Any, Callable, Dict, List, Optional


# Thread-local pour exposer la task courante au code module sans changer
# la signature de BaseModule.run().
_local = threading.local()


def current_task() -> Optional["TaskState"]:
    return getattr(_local, "task", None)


class TaskState:
    """État + buffer de logs + flag d'arrêt d'une exécution d'action."""

    def __init__(self, task_id: str, label: str):
        self.id = task_id
        self.label = label  # ex: "wifi.eviltwin"
        self.created = time.time()
        self.status = "running"  # running | done | error | stopped
        self.result: Optional[Dict[str, Any]] = None
        self.logs: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def log(self, msg: str, level: str = "info") -> None:
        """Ajoute une ligne au buffer (visible par le front via polling)."""
        with self._lock:
            self.logs.append({
                "ts": time.time(),
                "level": level,  # info | warn | error
                "msg": msg,
            })
            # cap : éviter explosion mémoire si action bug en boucle
            if len(self.logs) > 500:
                self.logs = self.logs[-500:]

    def is_stopped(self) -> bool:
        return self._stop.is_set()

    def request_stop(self) -> None:
        self._stop.set()
        self.log("Arrêt demandé par l'utilisateur", level="warn")

    def wait(self, seconds: float, check_interval: float = 1.0) -> bool:
        """
        Sleep interruptible. Retourne True si l'attente est allée au bout,
        False si l'arrêt a été demandé en cours de route.
        """
        elapsed = 0.0
        while elapsed < seconds:
            if self._stop.is_set():
                return False
            sl = min(check_interval, seconds - elapsed)
            time.sleep(sl)
            elapsed += sl
        return True

    def snapshot(self, since_idx: int = 0) -> Dict[str, Any]:
        """Vue read-only pour le front. since_idx = on ne renvoie que les
        logs au-delà de cet index (polling incrémental)."""
        with self._lock:
            return {
                "id": self.id,
                "label": self.label,
                "status": self.status,
                "result": self.result,
                "logs": self.logs[since_idx:],
                "log_total": len(self.logs),
            }


class TaskRegistry:
    """Mappe task_id → TaskState. Purge les vieilles tâches finies."""

    def __init__(self):
        self._tasks: Dict[str, TaskState] = {}
        self._lock = threading.Lock()

    def create(self, label: str) -> TaskState:
        tid = uuid.uuid4().hex[:10]
        task = TaskState(tid, label)
        with self._lock:
            self._tasks[tid] = task
            self._purge_locked()
        return task

    def get(self, tid: str) -> Optional[TaskState]:
        return self._tasks.get(tid)

    def stop(self, tid: str) -> bool:
        t = self.get(tid)
        if t and t.status == "running":
            t.request_stop()
            return True
        return False

    def _purge_locked(self) -> None:
        """Garde uniquement les tâches running ou finies récemment (< 1h)."""
        cutoff = time.time() - 3600
        self._tasks = {
            k: v for k, v in self._tasks.items()
            if v.status == "running" or v.created > cutoff
        }


TASKS = TaskRegistry()


def run_in_background(label: str, target: Callable, *args, **kwargs) -> TaskState:
    """
    Crée une Task et lance `target(*args, **kwargs)` dans un thread.
    Le module peut accéder à la task via core.tasks.current_task().
    """
    task = TASKS.create(label)

    def runner():
        _local.task = task
        try:
            res = target(*args, **kwargs)
            task.result = res
            task.status = "stopped" if task.is_stopped() else "done"
            if task.status == "done":
                task.log("Terminé.", level="info")
            else:
                task.log("Arrêté avant la fin.", level="warn")
        except Exception as e:
            tb = traceback.format_exc()
            task.log(f"Exception : {type(e).__name__}: {e}", level="error")
            for line in tb.splitlines()[-6:]:
                task.log(line, level="error")
            task.result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
            task.status = "error"
        finally:
            _local.task = None

    threading.Thread(target=runner, daemon=True).start()
    return task
