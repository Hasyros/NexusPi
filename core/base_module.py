"""
Contrat commun à tous les modules NexusPi.

Pour ajouter un module : créer un fichier dans modules/ avec une classe
qui hérite de BaseModule. Le registre le découvre automatiquement, et
sa carte apparaît dans le dashboard sans toucher au reste du code.

Schéma des paramètres d'action (params)
----------------------------------------
Chaque Action peut déclarer une liste d'inputs requis. Le front lit ce
schéma et génère le formulaire automatiquement. Types supportés :

  {"name":"bssid",    "label":"Cible",   "type":"target_ap"}
      -> select avec les APs du dernier scan (lit module.state.last_aps).
         Valeur transmise = BSSID. Le canal de l'AP suit (resolved côté backend).

  {"name":"duration", "label":"Durée (s)", "type":"int",
   "default":60, "min":10, "max":300}
      -> input number.

Quand l'utilisateur clique EXÉCUTER, le front envoie params = {"bssid":"…",
"duration":60} au backend. Le backend résout le canal en relisant ses
last_aps si besoin.
"""
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List


# Phases de déploiement (cf. wifi-attacks.md / threat-model.md)
#   passive : écoute, aucune émission        -> risque légal faible
#   capture : capture de matériel            -> à exploiter hors-ligne
#   active  : émission / injection           -> "lab mode" requis
#   rogue   : AP malveillant / MITM          -> "lab mode" requis
PHASES = ("passive", "capture", "active", "rogue")


@dataclass
class Action:
    id: str
    label: str
    phase: str = "passive"
    lab_gated: bool = False      # nécessite l'activation du "lab mode"
    description: str = ""
    hint: str = ""               # exemple d'utilisation affiché sous la description
    params: List[Dict[str, Any]] = field(default_factory=list)  # schéma inputs

    def __post_init__(self):
        if self.phase not in PHASES:
            raise ValueError(f"phase invalide: {self.phase!r} (attendu: {PHASES})")
        # Sécurité : toute action active/rogue est verrouillée par défaut
        if self.phase in ("active", "rogue"):
            self.lab_gated = True


class BaseModule:
    """Classe mère. Un module concret surcharge detect(), actions() et run()."""

    id: str = "base"
    name: str = "Base"
    icon: str = "box"            # nom d'icône (mappé côté front)
    description: str = ""

    def detect(self) -> bool:
        """Retourne True si le matériel du module est présent/branché."""
        return False

    def actions(self) -> List[Action]:
        """Liste des actions proposées par le module."""
        return []

    def run(self, action_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Exécute une action. À implémenter par chaque module."""
        return {"ok": False, "error": f"action '{action_id}' non implémentée"}

    def state(self) -> Dict[str, Any]:
        """
        État interne exposé au front (cache des derniers résultats, etc.).
        Sert à alimenter dynamiquement les <select> des actions ciblées.
        """
        return {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "icon": self.icon,
            "description": self.description,
            "connected": self.detect(),
            "actions": [asdict(a) for a in self.actions()],
            "state": self.state(),
        }
