"""
Module IR — émetteur KY-005 (GPIO 18) + récepteur KY-022 (GPIO 17).

Actions :
  Passive (réception) :
    - record          : enregistre un signal IR brut via ir-ctl --receive.
    - decode          : décode protocole + scancode d'un signal reçu.
    - scan_codes      : écoute prolongée, log tous les codes reçus.

  Capture :
    - save_signal     : enregistre un signal et le sauvegarde en mémoire.

  Active (émission, lab-gated) :
    - replay          : rejoue un signal IR enregistré.
    - send_code       : envoie un scancode (protocole + code).
    - brute_power     : brute-force des codes power on/off courants.
    - replay_fuzz     : rejoue un signal avec variations (timing fuzzing).

Matériel :
  - KY-022 (récepteur TSOP) → GPIO 17 → /dev/lirc1 (RX)
  - KY-005 (LED IR)         → GPIO 18 → /dev/lirc0 (TX, PWM hardware)
  - Overlays : gpio-ir (pin=17) + gpio-ir-tx (pin=18)

Notes :
  - ir-ctl (paquet ir-keytable) gère tout via /dev/lircN.
  - Pas besoin de pigpiod ni LIRC daemon.
  - Signaux stockés dans ~/nexuspi-data/ir/<nom>.ir (format ir-ctl pulse/space).
"""
import json
import os
import re
import select as _sel
import subprocess
import sys
import time
import traceback
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.base_module import BaseModule, Action
from core.tasks import current_task


# ── Config ────────────────────────────────────────────────────────────────

LIRC_TX = "/dev/lirc0"   # KY-005, GPIO 18
LIRC_RX = "/dev/lirc1"   # KY-022, GPIO 17

IR_TMP = Path("/tmp/nexuspi/ir")
IR_DATA = Path.home() / "nexuspi-data" / "ir"

# Protocoles courants supportés par ir-ctl --send (kernel rc protocols)
KNOWN_PROTOCOLS = [
    "nec", "nec32", "necx", "rc5", "rc5x_20", "rc5_sz",
    "rc6_0", "rc6_mce",
    "sony12", "sony15", "sony20", "sanyo", "sharp",
]

# Codes power courants pour le brute-force (protocole:scancode)
COMMON_POWER_CODES = [
    # NEC — les plus répandus (TV, décodeurs, barres de son)
    ("nec", "0x00ff00ff"),   # Samsung générique
    ("nec", "0x04fb08f7"),   # LG TV
    ("nec", "0x20df10ef"),   # LG (autre)
    ("nec", "0x40bf12ed"),   # Sony via NEC
    ("nec", "0x807f02fd"),   # Philips via NEC
    ("nec", "0x00ff40bf"),   # Decodeur générique
    ("nec", "0x00ff906f"),   # Barre de son
    ("nec", "0x00ff50af"),   # Climatiseur générique
    ("nec", "0x00ff629d"),   # LED strip / RGB
    ("nec", "0x01fe48b7"),   # TCL TV
    ("nec", "0x08f7e01f"),   # Hisense TV
    # RC5 — Philips et dérivés
    ("rc5", "0x100c"),       # Philips TV power
    ("rc5", "0x110c"),       # Philips (autre)
    ("rc5", "0x1026"),       # Philips SAT
    # RC6 — MCE et Microsoft
    ("rc6_mce", "0x800f040c"),  # MCE power
    # Samsung (via necx — samsung32 non supporté par ce kernel)
    ("necx", "0xe0e040"),   # Samsung TV power
    ("necx", "0xe0e099"),   # Samsung (autre)
    # Sony SIRC
    ("sony12", "0x0015"),    # Sony TV power (12-bit)
    ("sony15", "0x0015"),    # Sony TV power (15-bit)
    ("sony20", "0x0015"),    # Sony TV power (20-bit)
    # Sharp
    ("sharp", "0x4101"),     # Sharp TV
    # Sanyo
    ("sanyo", "0x1c1c6060"),  # Sanyo projector
]


# ── Helpers ───────────────────────────────────────────────────────────────

def _which(cmd: str) -> bool:
    return subprocess.run(["which", cmd], capture_output=True).returncode == 0


def _run(cmd: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True,
                          errors="replace", timeout=timeout)


def _parse_ir_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse une ligne ir-ctl : 'pulse 560' ou 'space 1680' ou scancode."""
    line = line.strip()
    # Scancode décodé : "nec 0x00ff00ff" ou "lirc protocol(nec): scancode = 0x00ff00ff"
    m = re.match(r".*protocol\((\w+)\):\s*scancode\s*=\s*(0x[0-9a-fA-F]+)", line)
    if m:
        return {"type": "scancode", "protocol": m.group(1),
                "scancode": m.group(2)}
    # Format simplifié : "nec 0x00ff00ff"
    m = re.match(r"^(\w+)\s+(0x[0-9a-fA-F]+)", line)
    if m and m.group(1).lower() in KNOWN_PROTOCOLS:
        return {"type": "scancode", "protocol": m.group(1).lower(),
                "scancode": m.group(2)}
    # Pulse/space raw
    m = re.match(r"^(pulse|space)\s+(\d+)", line)
    if m:
        return {"type": m.group(1), "duration": int(m.group(2))}
    return None


# ── Module ────────────────────────────────────────────────────────────────

class IrModule(BaseModule):
    id = "ir"
    name = "IR · Infrarouge"
    icon = "ir"
    description = ("Émetteur/récepteur infrarouge. Enregistre, décode et "
                   "rejoue des signaux de télécommandes (TV, clim, volets…).")

    def __init__(self):
        self._last_signals: List[Dict[str, Any]] = []
        self._saved_signals: List[Dict[str, str]] = []
        self._refresh_saved()

    def _refresh_saved(self):
        """Recharge la liste des signaux sauvegardés sur disque."""
        self._saved_signals = []
        if IR_DATA.is_dir():
            for f in sorted(IR_DATA.glob("*.ir")):
                self._saved_signals.append({
                    "name": f.stem,
                    "file": str(f),
                    "size": f.stat().st_size,
                })

    def detect(self) -> bool:
        return Path(LIRC_RX).exists() or Path(LIRC_TX).exists()

    def state(self) -> Dict[str, Any]:
        self._refresh_saved()
        return {
            "tx_available": Path(LIRC_TX).exists(),
            "rx_available": Path(LIRC_RX).exists(),
            "last_signals": self._last_signals[-20:],
            "saved_signals": self._saved_signals,
        }

    def actions(self) -> List[Action]:
        dur_record = {"name": "duration", "label": "Durée (s)",
                      "type": "int", "default": 10, "min": 3, "max": 60}
        return [
            # ── Passive ──
            Action("record", "Enregistrer signal IR", "passive",
                   description="Pointe une télécommande vers le récepteur et "
                               "appuie sur un bouton. Le signal brut est "
                               "capturé (pulse/space).",
                   hint="appuie sur le bouton pendant l'enregistrement",
                   params=[dur_record,
                           {"name": "signal_name", "label": "Nom du signal",
                            "type": "text", "default": "",
                            "placeholder": "ex: tv-power, clim-on"}]),
            Action("decode", "Décoder signal IR", "passive",
                   description="Attend un signal IR et affiche le protocole "
                               "détecté + le scancode (NEC, RC5, Sony…).",
                   hint="pointe la télécommande vers le récepteur",
                   params=[dur_record]),
            Action("scan_codes", "Scanner (écoute prolongée)", "passive",
                   description="Écoute prolongée : log tous les codes IR "
                               "reçus avec protocole et timestamp.",
                   params=[{"name": "duration", "label": "Durée (s)",
                            "type": "int", "default": 30,
                            "min": 5, "max": 300}]),
            # ── Capture ──
            Action("save_signal", "Capturer & sauvegarder", "capture",
                   description="Enregistre un signal IR et le sauvegarde en "
                               "mémoire pour le rejouer plus tard.",
                   params=[dur_record,
                           {"name": "signal_name", "label": "Nom du signal",
                            "type": "text", "default": "",
                            "placeholder": "ex: tv-power, clim-25deg"}]),
            # ── Active ──
            Action("replay", "Rejouer un signal", "active",
                   description="Émet un signal IR précédemment enregistré. "
                               "Pointe l'émetteur vers l'appareil cible.",
                   params=[{"name": "signal", "label": "Signal",
                            "type": "ir_signal"},
                           {"name": "repeat", "label": "Répétitions",
                            "type": "int", "default": 1,
                            "min": 1, "max": 50}]),
            Action("send_code", "Envoyer un scancode", "active",
                   description="Envoie un code IR spécifique (protocole + "
                               "scancode hex). Ex: nec 0x00ff00ff.",
                   params=[{"name": "protocol", "label": "Protocole",
                            "type": "select",
                            "options": [{"value": p, "label": p}
                                        for p in KNOWN_PROTOCOLS],
                            "default": "nec"},
                           {"name": "scancode", "label": "Scancode (hex)",
                            "type": "text", "default": "",
                            "placeholder": "0x00ff00ff"},
                           {"name": "repeat", "label": "Répétitions",
                            "type": "int", "default": 3,
                            "min": 1, "max": 50}]),
            Action("brute_power", "Brute-force Power ON/OFF", "active",
                   description="Essaie ~30 codes power courants (NEC, RC5, "
                               "Sony, Samsung…). Pointe vers l'appareil.",
                   params=[{"name": "delay", "label": "Délai entre codes (ms)",
                            "type": "int", "default": 300,
                            "min": 100, "max": 2000}]),
            Action("replay_fuzz", "Replay + fuzzing", "active",
                   description="Rejoue un signal enregistré avec des "
                               "variations de timing (±10-50%). Utile pour "
                               "tester la tolérance d'un récepteur.",
                   params=[{"name": "signal", "label": "Signal",
                            "type": "ir_signal"},
                           {"name": "fuzz_pct", "label": "Variation (%)",
                            "type": "int", "default": 20,
                            "min": 5, "max": 50},
                           {"name": "iterations", "label": "Itérations",
                            "type": "int", "default": 10,
                            "min": 1, "max": 100}]),
        ]

    # ── Implémentations ───────────────────────────────────────────────────

    def _check_rx(self) -> Optional[Dict[str, Any]]:
        if not Path(LIRC_RX).exists():
            return {"ok": False,
                    "error": "Récepteur IR introuvable (/dev/lirc1). "
                             "Vérifie le câblage KY-022 et l'overlay gpio-ir."}
        return None

    def _check_tx(self) -> Optional[Dict[str, Any]]:
        if not Path(LIRC_TX).exists():
            return {"ok": False,
                    "error": "Émetteur IR introuvable (/dev/lirc0). "
                             "Vérifie le câblage KY-005 et l'overlay gpio-ir-tx."}
        return None

    def _record_raw(self, duration: int) -> Optional[Path]:
        """Enregistre du raw IR pendant `duration` secondes, retourne le fichier."""
        IR_TMP.mkdir(parents=True, exist_ok=True)
        out = IR_TMP / f"rec_{int(time.time())}.ir"

        task = current_task()
        if task:
            task.log(f"⏺ Enregistrement IR ({duration}s) — envoie un signal…")

        # ir-ctl --device=/dev/lirc1 --receive --one-shot (1 signal)
        # Ou sans --one-shot pour capturer pendant toute la durée
        proc = subprocess.Popen(
            ["sudo", "ir-ctl", "-d", LIRC_RX, "--receive",
             "-t", str(duration * 1000)],  # timeout en ms
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, errors="replace")

        lines = []
        try:
            deadline = time.time() + duration + 2
            while time.time() < deadline:
                rlist, _, _ = _sel.select([proc.stdout], [], [], 1.0)
                if rlist:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    line = line.rstrip()
                    if line:
                        lines.append(line)
                        if task and len(lines) <= 5:
                            task.log(f"  {line}")
                if proc.poll() is not None:
                    break
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        if not lines:
            if task:
                task.log("⚠ Aucun signal reçu.", "warn")
            return None

        # Écrire le fichier raw
        out.write_text("\n".join(lines) + "\n")
        if task:
            task.log(f"✅ {len(lines)} lignes capturées → {out.name}")
        return out

    def _record(self, duration: int, signal_name: str = "") -> Dict[str, Any]:
        """Enregistre un signal IR brut."""
        err = self._check_rx()
        if err:
            return err

        raw = self._record_raw(duration)
        if raw is None:
            return {"ok": True,
                    "message": f"Aucun signal IR reçu en {duration}s.\n"
                               "Vérifie que la télécommande pointe bien vers "
                               "le récepteur KY-022."}

        content = raw.read_text()
        # Compter les pulses
        pulses = content.count("pulse ")
        spaces = content.count("space ")

        # Parser pour trouver un éventuel scancode
        decoded = []
        for line in content.splitlines():
            p = _parse_ir_line(line)
            if p and p["type"] == "scancode":
                decoded.append(p)

        msg = f"Signal IR enregistré ({pulses} pulses, {spaces} spaces).\n"
        if decoded:
            for d in decoded:
                msg += f"Décodé : <b>{d['protocol']}</b> scancode <code>{d['scancode']}</code>\n"
        msg += f"Fichier : <code>{raw.name}</code>"

        # Stocker dans last_signals
        sig = {"name": signal_name or raw.stem, "file": str(raw),
               "pulses": pulses, "decoded": decoded,
               "ts": time.strftime("%H:%M:%S")}
        self._last_signals.append(sig)
        if len(self._last_signals) > 50:
            self._last_signals = self._last_signals[-50:]

        return {"ok": True, "signal": sig, "message": msg}

    def _decode(self, duration: int) -> Dict[str, Any]:
        """Attend un signal et décode le protocole."""
        err = self._check_rx()
        if err:
            return err

        task = current_task()
        if task:
            task.log(f"👂 Décodage IR ({duration}s) — envoie un signal…")

        # ir-ctl en mode scancode decode
        proc = subprocess.Popen(
            ["sudo", "ir-ctl", "-d", LIRC_RX, "--receive",
             "-t", str(duration * 1000)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, errors="replace")

        decoded = []
        raw_lines = []
        try:
            deadline = time.time() + duration + 2
            while time.time() < deadline:
                rlist, _, _ = _sel.select([proc.stdout], [], [], 1.0)
                if rlist:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    line = line.rstrip()
                    if not line:
                        continue
                    raw_lines.append(line)
                    p = _parse_ir_line(line)
                    if p and p["type"] == "scancode":
                        decoded.append(p)
                        if task:
                            task.log(f"  🔑 {p['protocol']} : "
                                     f"{p['scancode']}", "warn")
                if proc.poll() is not None:
                    break
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        if not decoded and not raw_lines:
            return {"ok": True,
                    "message": f"Aucun signal IR reçu en {duration}s."}

        msg = ""
        if decoded:
            msg += f"<b>{len(decoded)} code(s) décodé(s)</b> :\n\n"
            for d in decoded:
                msg += (f"  • Protocole <b>{d['protocol']}</b> — "
                        f"scancode <code>{d['scancode']}</code>\n")
            msg += ("\nPour rejouer : utilise <b>Envoyer un scancode</b> "
                    "avec ces valeurs.")
        else:
            msg += (f"Signal reçu ({len(raw_lines)} lignes raw) mais "
                    "protocole non reconnu.\n"
                    "Essaie <b>Enregistrer signal</b> puis <b>Rejouer</b> "
                    "en mode raw.")

        return {"ok": True, "decoded": decoded, "message": msg}

    def _scan_codes(self, duration: int) -> Dict[str, Any]:
        """Écoute prolongée, log tous les codes."""
        err = self._check_rx()
        if err:
            return err

        task = current_task()
        if task:
            task.log(f"📡 Scan IR ({duration}s) — pointe des télécommandes…")

        proc = subprocess.Popen(
            ["sudo", "ir-ctl", "-d", LIRC_RX, "--receive",
             "-t", str(duration * 1000)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, errors="replace")

        codes = []
        try:
            deadline = time.time() + duration + 2
            while time.time() < deadline:
                if task and task.is_stopped():
                    break
                rlist, _, _ = _sel.select([proc.stdout], [], [], 1.0)
                if rlist:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    line = line.rstrip()
                    if not line:
                        continue
                    p = _parse_ir_line(line)
                    if p and p["type"] == "scancode":
                        ts = time.strftime("%H:%M:%S")
                        entry = {**p, "ts": ts}
                        codes.append(entry)
                        if task:
                            task.log(f"  [{ts}] {p['protocol']} "
                                     f"{p['scancode']}")
                if proc.poll() is not None:
                    break
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        if not codes:
            return {"ok": True,
                    "message": f"Aucun code IR reçu en {duration}s."}

        # Dédupliquer pour le résumé
        unique = {}
        for c in codes:
            key = f"{c['protocol']}:{c['scancode']}"
            if key not in unique:
                unique[key] = {"protocol": c["protocol"],
                               "scancode": c["scancode"], "count": 0}
            unique[key]["count"] += 1

        msg = f"<b>{len(codes)} code(s)</b> reçus en {duration}s "
        msg += f"({len(unique)} unique(s)) :\n\n"
        for k, v in unique.items():
            msg += (f"  • <b>{v['protocol']}</b> "
                    f"<code>{v['scancode']}</code> × {v['count']}\n")

        return {"ok": True, "codes": codes, "unique": list(unique.values()),
                "message": msg}

    def _save_signal(self, duration: int, signal_name: str) -> Dict[str, Any]:
        """Enregistre un signal et le sauvegarde en mémoire persistante."""
        err = self._check_rx()
        if err:
            return err
        if not signal_name or not signal_name.strip():
            return {"ok": False,
                    "error": "Donne un nom au signal (ex: tv-power, clim-on)."}

        name = re.sub(r'[^\w\-]', '_', signal_name.strip())
        raw = self._record_raw(duration)
        if raw is None:
            return {"ok": True,
                    "message": f"Aucun signal IR reçu en {duration}s."}

        # Sauvegarder dans ~/nexuspi-data/ir/
        IR_DATA.mkdir(parents=True, exist_ok=True)
        dest = IR_DATA / f"{name}.ir"
        # Si le fichier existe, suffixer
        if dest.exists():
            dest = IR_DATA / f"{name}_{int(time.time())}.ir"

        import shutil
        shutil.copy2(str(raw), str(dest))

        self._refresh_saved()

        task = current_task()
        if task:
            task.log(f"💾 Signal sauvegardé : {dest}")

        content = raw.read_text()
        pulses = content.count("pulse ")

        return {"ok": True,
                "message": f"Signal <b>{name}</b> sauvegardé ({pulses} pulses).\n"
                           f"Fichier : <code>{dest}</code>\n"
                           "Utilise <b>Rejouer un signal</b> pour le retransmettre."}

    def _replay(self, signal_path: str, repeat: int) -> Dict[str, Any]:
        """Rejoue un signal IR enregistré."""
        err = self._check_tx()
        if err:
            return err
        if not signal_path:
            return {"ok": False,
                    "error": "Sélectionne un signal à rejouer."}

        sig_file = Path(signal_path)
        if not sig_file.is_file():
            return {"ok": False,
                    "error": f"Fichier introuvable : {signal_path}"}

        task = current_task()
        if task:
            task.log(f"📤 Replay {sig_file.name} (×{repeat})…")

        for i in range(repeat):
            if task and task.is_stopped():
                if task:
                    task.log("⏹ Stop demandé.", "warn")
                break
            ret = _run(["sudo", "ir-ctl", "-d", LIRC_TX,
                        "--send=" + str(sig_file)], timeout=10)
            if ret.returncode != 0:
                err_msg = ret.stderr.strip() or ret.stdout.strip()
                return {"ok": False,
                        "error": f"ir-ctl send échoué : {err_msg}"}
            if task and repeat > 1:
                task.log(f"  Envoi {i + 1}/{repeat}")
            if i < repeat - 1:
                time.sleep(0.1)

        return {"ok": True,
                "message": f"Signal <b>{sig_file.stem}</b> envoyé ×{repeat}."}

    def _send_code(self, protocol: str, scancode: str,
                   repeat: int) -> Dict[str, Any]:
        """Envoie un scancode IR spécifique."""
        err = self._check_tx()
        if err:
            return err
        if not scancode or not scancode.strip():
            return {"ok": False,
                    "error": "Scancode requis (ex: 0x00ff00ff)."}
        if protocol not in KNOWN_PROTOCOLS:
            return {"ok": False,
                    "error": f"Protocole inconnu : {protocol}. "
                             f"Supportés : {', '.join(KNOWN_PROTOCOLS[:8])}…"}

        sc = scancode.strip()
        if not sc.startswith("0x"):
            sc = "0x" + sc

        task = current_task()
        if task:
            task.log(f"📤 Envoi {protocol} {sc} (×{repeat})…")

        for i in range(repeat):
            if task and task.is_stopped():
                break
            ret = _run(["sudo", "ir-ctl", "-d", LIRC_TX,
                        "--scancode", f"{protocol}:{sc}"], timeout=10)
            if ret.returncode != 0:
                err_msg = ret.stderr.strip() or ret.stdout.strip()
                # Fallback info
                if "unknown protocol" in err_msg.lower():
                    return {"ok": False,
                            "error": f"Protocole {protocol} non supporté par "
                                     "ce kernel. Essaie un replay raw."}
                return {"ok": False,
                        "error": f"ir-ctl scancode échoué : {err_msg}"}
            if task and repeat > 1:
                task.log(f"  Envoi {i + 1}/{repeat}")
            if i < repeat - 1:
                time.sleep(0.05)

        return {"ok": True,
                "message": f"Code <b>{protocol}</b> "
                           f"<code>{sc}</code> envoyé ×{repeat}."}

    def _brute_power(self, delay_ms: int) -> Dict[str, Any]:
        """Brute-force des codes power courants."""
        err = self._check_tx()
        if err:
            return err

        task = current_task()
        total = len(COMMON_POWER_CODES)
        if task:
            task.log(f"⚡ Brute-force power — {total} codes à tester "
                     f"(délai {delay_ms}ms)")

        sent = 0
        errors = 0
        for i, (proto, code) in enumerate(COMMON_POWER_CODES, 1):
            if task and task.is_stopped():
                if task:
                    task.log("⏹ Stop demandé.", "warn")
                break

            ret = _run(["sudo", "ir-ctl", "-d", LIRC_TX,
                        "--scancode", f"{proto}:{code}"], timeout=10)
            if ret.returncode == 0:
                sent += 1
                if task:
                    task.log(f"  [{i}/{total}] {proto} {code}")
            else:
                errors += 1
                if task:
                    task.log(f"  [{i}/{total}] {proto} {code} — ERREUR",
                             "warn")

            time.sleep(delay_ms / 1000.0)

        msg = (f"Brute-force terminé : <b>{sent}/{total}</b> codes envoyés.\n"
               f"Si l'appareil a réagi, note le code dans la console.\n"
               "Sinon, essaie <b>Enregistrer</b> la vraie télécommande "
               "puis <b>Rejouer</b>.")
        if errors:
            msg += f"\n⚠ {errors} erreur(s) d'envoi."

        return {"ok": True, "sent": sent, "total": total, "message": msg}

    def _replay_fuzz(self, signal_path: str, fuzz_pct: int,
                     iterations: int) -> Dict[str, Any]:
        """Rejoue un signal avec variations de timing."""
        err = self._check_tx()
        if err:
            return err
        if not signal_path:
            return {"ok": False,
                    "error": "Sélectionne un signal à fuzzer."}

        sig_file = Path(signal_path)
        if not sig_file.is_file():
            return {"ok": False,
                    "error": f"Fichier introuvable : {signal_path}"}

        content = sig_file.read_text()
        lines = content.strip().splitlines()

        task = current_task()
        if task:
            task.log(f"🔀 Replay fuzz {sig_file.name} — {iterations}× "
                     f"avec ±{fuzz_pct}% variation")

        import random
        IR_TMP.mkdir(parents=True, exist_ok=True)

        sent = 0
        for it in range(iterations):
            if task and task.is_stopped():
                break

            # Générer une version fuzzée
            fuzzed = []
            for line in lines:
                m = re.match(r"^(pulse|space)\s+(\d+)", line)
                if m:
                    kind = m.group(1)
                    dur = int(m.group(2))
                    # Variation aléatoire
                    factor = 1.0 + random.uniform(-fuzz_pct, fuzz_pct) / 100.0
                    new_dur = max(1, int(dur * factor))
                    fuzzed.append(f"{kind} {new_dur}")
                else:
                    fuzzed.append(line)

            # Écrire le fichier fuzzé temporaire
            tmp_file = IR_TMP / f"fuzz_{it}.ir"
            tmp_file.write_text("\n".join(fuzzed) + "\n")

            ret = _run(["sudo", "ir-ctl", "-d", LIRC_TX,
                        "--send=" + str(tmp_file)], timeout=10)
            if ret.returncode == 0:
                sent += 1
            if task:
                task.log(f"  [{it + 1}/{iterations}] "
                         f"{'✅' if ret.returncode == 0 else '❌'}")
            time.sleep(0.15)

        return {"ok": True,
                "message": f"Fuzz replay terminé : <b>{sent}/{iterations}</b> "
                           f"envoyés avec ±{fuzz_pct}% variation.\n"
                           "Si l'appareil a réagi à une itération, "
                           "le signal original est compatible."}

    # ── Dispatch ──────────────────────────────────────────────────────────

    def run(self, action_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        known = {a.id for a in self.actions()}
        if action_id not in known:
            return {"ok": False, "error": f"action inconnue : {action_id}"}

        try:
            duration = int(params.get("duration", 10))
        except (TypeError, ValueError):
            duration = 10

        try:
            if action_id == "record":
                name = str(params.get("signal_name", ""))
                return self._record(max(3, min(60, duration)), name)
            if action_id == "decode":
                return self._decode(max(3, min(60, duration)))
            if action_id == "scan_codes":
                return self._scan_codes(max(5, min(300, duration)))
            if action_id == "save_signal":
                name = str(params.get("signal_name", ""))
                return self._save_signal(max(3, min(60, duration)), name)
            if action_id == "replay":
                sig = str(params.get("signal", ""))
                rep = int(params.get("repeat", 1))
                return self._replay(sig, max(1, min(50, rep)))
            if action_id == "send_code":
                proto = str(params.get("protocol", "nec"))
                sc = str(params.get("scancode", ""))
                rep = int(params.get("repeat", 3))
                return self._send_code(proto, sc, max(1, min(50, rep)))
            if action_id == "brute_power":
                delay = int(params.get("delay", 300))
                return self._brute_power(max(100, min(2000, delay)))
            if action_id == "replay_fuzz":
                sig = str(params.get("signal", ""))
                fuzz = int(params.get("fuzz_pct", 20))
                iters = int(params.get("iterations", 10))
                return self._replay_fuzz(sig, max(5, min(50, fuzz)),
                                         max(1, min(100, iters)))
            return {"ok": False, "error": f"action non implémentée : {action_id}"}
        except Exception as e:
            tb = traceback.format_exc()
            print(f"[ir] EXCEPTION run({action_id}): "
                  f"{type(e).__name__}: {e}\n{tb}", file=sys.stderr)
            return {"ok": False,
                    "error": f"{type(e).__name__}: {e}",
                    "trace": tb.splitlines()[-6:]}
