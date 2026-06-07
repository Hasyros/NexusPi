"""
Auto-découverte des modules.

Parcourt le package modules/, instancie toute classe héritant de BaseModule,
et renvoie la liste. Ajouter un fichier dans modules/ suffit : aucune
inscription manuelle nécessaire.
"""
import importlib
import inspect
import pkgutil
import traceback
from typing import List

from core.base_module import BaseModule
import modules as modules_pkg


def load_modules() -> List[BaseModule]:
    found: List[BaseModule] = []
    for _, modname, _ in pkgutil.iter_modules(modules_pkg.__path__):
        try:
            mod = importlib.import_module(f"modules.{modname}")
        except Exception:
            print(f"[registry] échec import modules.{modname}:")
            traceback.print_exc()
            continue
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if issubclass(obj, BaseModule) and obj is not BaseModule:
                try:
                    found.append(obj())
                    print(f"[registry] module chargé: {obj.__name__}")
                except Exception:
                    print(f"[registry] échec instanciation {obj.__name__}:")
                    traceback.print_exc()
    return found
