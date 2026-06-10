"""
Module NFC — lecteur PN532 V3 (I2C).

Actions :
  Passive :
    - poll_tag       : détecte un tag NFC, lit UID + type (ATQA/SAK).
    - read_info      : lit les infos complètes d'un tag (UID, ATQA, SAK, ATS).
    - scan_tags      : écoute prolongée, log tous les tags présentés.

  Capture :
    - dump_classic   : dump complet d'un MIFARE Classic 1K/4K (nfc-mfclassic).
    - dump_ultralight: dump d'un MIFARE Ultralight / NTAG (nfc-mfultralight).
    - crack_keys     : crack des clés MIFARE Classic via MFOC (nested attack).

  Active (lab-gated) :
    - write_classic  : écrit un dump MFD sur un MIFARE Classic.
    - clone_classic  : lit une carte source puis écrit sur une carte cible
                       (clone complet, nécessite un "magic" Chinese clone).
    - write_ultralight: écrit un dump MFD sur un MIFARE Ultralight.

Matériel :
  - PN532 V3 → I2C1, adresse 0x24
  - Config : /etc/nfc/libnfc.conf (connstring pn532_i2c:/dev/i2c-1)
  - I2C baudrate 100 kHz (dtparam=i2c_arm_baudrate=100000)

Outils :
  - libnfc : nfc-list, nfc-mfclassic, nfc-mfultralight, nfc-scan-device
  - mfoc   : crack clés MIFARE Classic (nested authentication attack)
  - Dumps stockés dans ~/nexuspi-data/nfc/<nom>.mfd (binaire 1024/4096 octets)
"""
import json
import os
import re
import subprocess
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.base_module import BaseModule, Action
from core.tasks import current_task


# ── Config ────────────────────────────────────────────────────────────────

NFC_DATA = Path.home() / "nexuspi-data" / "nfc"
NFC_TMP = Path("/tmp/nexuspi/nfc")

# Taille standard des dumps MFD
MFC_1K_SIZE = 1024    # MIFARE Classic 1K : 16 secteurs × 4 blocs × 16 octets
MFC_4K_SIZE = 4096    # MIFARE Classic 4K : 32×4×16 + 8×16×16


# ── Helpers ───────────────────────────────────────────────────────────────

def _which(cmd: str) -> bool:
    return subprocess.run(["which", cmd], capture_output=True).returncode == 0


def _run(cmd: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True,
                          errors="replace", timeout=timeout)


def _nfc_available() -> bool:
    """Vérifie que le PN532 répond via nfc-list."""
    try:
        ret = _run(["sudo", "nfc-list"], timeout=10)
        return "opened" in ret.stdout.lower()
    except Exception:
        return False


def _parse_nfc_list(output: str) -> List[Dict[str, Any]]:
    """Parse la sortie de nfc-list / nfc-poll pour extraire les tags."""
    tags = []
    current_tag: Optional[Dict[str, Any]] = {}
    # Patterns principaux
    uid_re = re.compile(r"UID.*?:\s*((?:[0-9a-fA-F]{2}\s*)+)", re.IGNORECASE)
    atqa_re = re.compile(r"ATQA.*?:\s*((?:[0-9a-fA-F]{2}\s*)+)", re.IGNORECASE)
    sak_re = re.compile(r"SAK.*?:\s*((?:[0-9a-fA-F]{2}\s*)+)", re.IGNORECASE)
    ats_re = re.compile(r"ATS.*?:\s*((?:[0-9a-fA-F]{2}\s*)+)", re.IGNORECASE)
    iso_type_re = re.compile(
        r"ISO/IEC\s+14443[AB]?\s*(?:\(\d+[kK]bps\))?\s+(?:tag|target)",
        re.IGNORECASE)
    felica_re = re.compile(r"FeliCa", re.IGNORECASE)

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Nouveau tag détecté
        if iso_type_re.search(line):
            if current_tag and current_tag.get("uid"):
                tags.append(current_tag)
            current_tag = {"type": line.strip()}
            continue
        if felica_re.search(line) and "target" in line.lower():
            if current_tag and current_tag.get("uid"):
                tags.append(current_tag)
            current_tag = {"type": line.strip()}
            continue

        m = uid_re.search(line)
        if m and current_tag is not None:
            current_tag["uid"] = m.group(1).strip().replace("  ", " ")
            continue
        m = atqa_re.search(line)
        if m and current_tag is not None:
            current_tag["atqa"] = m.group(1).strip()
            continue
        m = sak_re.search(line)
        if m and current_tag is not None:
            current_tag["sak"] = m.group(1).strip()
            continue
        m = ats_re.search(line)
        if m and current_tag is not None:
            current_tag["ats"] = m.group(1).strip()

    if current_tag and current_tag.get("uid"):
        tags.append(current_tag)

    return tags


def _identify_tag(tag: Dict[str, Any]) -> str:
    """Identifie le type de tag à partir de ATQA/SAK."""
    sak = tag.get("sak", "").strip().lower()
    atqa = tag.get("atqa", "").strip().lower().replace(" ", "")

    if sak == "08":
        return "MIFARE Classic 1K"
    if sak == "18":
        return "MIFARE Classic 4K"
    if sak == "09":
        return "MIFARE Mini"
    if sak == "00":
        # Ultralight / NTAG — discriminer via ATQA
        if atqa == "0044":
            return "MIFARE Ultralight / NTAG"
        return "MIFARE Ultralight / NTAG (ou ISO 14443-4)"
    if sak == "20":
        if "0344" in atqa:
            return "MIFARE DESFire"
        return "ISO 14443-4 (possible DESFire / JCOP)"
    if sak == "28":
        return "MIFARE Classic 1K (émulée, SmartMX)"
    if sak == "38":
        return "MIFARE Classic 4K (émulée, SmartMX)"
    if sak in ("01",):
        return "MIFARE Pro / ProX"
    if sak == "10":
        return "MIFARE Plus 2K (SL2)"
    if sak == "11":
        return "MIFARE Plus 4K (SL2)"
    return f"Inconnu (SAK={sak}, ATQA={atqa})"


def _uid_short(tag: Dict[str, Any]) -> str:
    """UID raccourci pour affichage."""
    uid = tag.get("uid", "?")
    return uid.replace(" ", ":").upper()


# ── Module ────────────────────────────────────────────────────────────────

class NfcModule(BaseModule):
    id = "nfc"
    name = "NFC · PN532"
    icon = "nfc"
    description = ("Lecteur NFC PN532 V3 (I2C). Lit, clone et cracke des "
                   "tags MIFARE Classic, Ultralight et NTAG.")

    def __init__(self):
        self._last_tags: List[Dict[str, Any]] = []
        self._saved_dumps: List[Dict[str, Any]] = []
        self._refresh_saved()

    def _refresh_saved(self):
        """Recharge la liste des dumps sauvegardés sur disque."""
        self._saved_dumps = []
        if NFC_DATA.is_dir():
            for f in sorted(NFC_DATA.glob("*.mfd")):
                self._saved_dumps.append({
                    "name": f.stem,
                    "file": str(f),
                    "size": f.stat().st_size,
                })
            # Inclure aussi les .json (résultats mfoc avec clés)
            for f in sorted(NFC_DATA.glob("*.json")):
                self._saved_dumps.append({
                    "name": f.stem + " (clés)",
                    "file": str(f),
                    "size": f.stat().st_size,
                })

    def detect(self) -> bool:
        """Détecte le PN532 via I2C ou nfc-list."""
        # Vérif rapide I2C (sans sudo)
        try:
            ret = subprocess.run(
                ["sudo", "i2cdetect", "-y", "1"],
                capture_output=True, text=True, timeout=5)
            if "24" in ret.stdout:
                return True
        except Exception:
            pass
        # Fallback : nfc-list (plus lent)
        return _which("nfc-list")

    def state(self) -> Dict[str, Any]:
        self._refresh_saved()
        return {
            "last_tags": self._last_tags[-20:],
            "saved_dumps": self._saved_dumps,
        }

    def actions(self) -> List[Action]:
        return [
            # ── Passive ──
            Action("poll_tag", "Détecter un tag", "passive",
                   description="Pose un tag NFC sur le lecteur. Affiche "
                               "l'UID, le type (MIFARE Classic, Ultralight, "
                               "DESFire…) et les infos ATQA/SAK.",
                   hint="pose le tag sur le PN532",
                   params=[{"name": "timeout", "label": "Timeout (s)",
                            "type": "int", "default": 15,
                            "min": 5, "max": 60}]),
            Action("read_info", "Infos détaillées du tag", "passive",
                   description="Lecture approfondie : UID, ATQA, SAK, ATS, "
                               "type de tag identifié, nombre de secteurs.",
                   params=[{"name": "timeout", "label": "Timeout (s)",
                            "type": "int", "default": 15,
                            "min": 5, "max": 60}]),
            Action("scan_tags", "Scanner (écoute prolongée)", "passive",
                   description="Écoute prolongée : log tous les tags "
                               "présentés avec UID et type.",
                   params=[{"name": "duration", "label": "Durée (s)",
                            "type": "int", "default": 30,
                            "min": 10, "max": 300}]),

            # ── Capture ──
            Action("dump_classic", "Dump MIFARE Classic", "capture",
                   description="Lecture complète d'un MIFARE Classic 1K/4K. "
                               "Nécessite les clés par défaut (FFFFFFFFFFFF) "
                               "ou un fichier de clés (via crack_keys d'abord).",
                   hint="pose le tag et ne le bouge pas pendant le dump",
                   params=[{"name": "dump_name", "label": "Nom du dump",
                            "type": "text", "default": "",
                            "placeholder": "ex: badge-bureau, carte-parking"},
                           {"name": "key_file", "label": "Fichier de clés",
                            "type": "nfc_dump",
                            "description": "Optionnel : dump .mfd contenant "
                                           "les clés (issu de crack_keys)."}]),
            Action("dump_ultralight", "Dump Ultralight / NTAG", "capture",
                   description="Lecture complète d'un MIFARE Ultralight ou "
                               "NTAG. Sauvegarde en fichier .mfd.",
                   hint="pose le tag et ne le bouge pas",
                   params=[{"name": "dump_name", "label": "Nom du dump",
                            "type": "text", "default": "",
                            "placeholder": "ex: ntag-215, bracelet"}]),
            Action("crack_keys", "Crack clés MIFARE (MFOC)", "capture",
                   description="Attaque nested authentication sur MIFARE "
                               "Classic. Nécessite au moins 1 clé connue "
                               "(par défaut : FFFFFFFFFFFF). Peut prendre "
                               "plusieurs minutes.",
                   hint="ne retire pas le tag pendant le crack",
                   params=[{"name": "dump_name", "label": "Nom du résultat",
                            "type": "text", "default": "",
                            "placeholder": "ex: badge-cracke"}]),

            # ── Active (lab-gated) ──
            Action("write_classic", "Écrire MIFARE Classic", "active",
                   description="Écrit un dump .mfd sur un MIFARE Classic. "
                               "Le tag cible doit être un 'Magic' Chinese "
                               "clone (Gen1/Gen2) pour écrire le bloc 0.",
                   params=[{"name": "dump_file", "label": "Dump source",
                            "type": "nfc_dump"},
                           {"name": "unlock", "label": "Écriture déverrouillée",
                            "type": "select",
                            "options": [
                                {"value": "normal", "label": "Normal (w)"},
                                {"value": "unlock",
                                 "label": "Unlock — Chinese clone (W)"},
                            ],
                            "default": "normal"}]),
            Action("clone_classic", "Cloner MIFARE Classic", "active",
                   description="Étape 1 : lit la carte source (dump). "
                               "Étape 2 : pose la carte cible (Chinese clone) "
                               "et écrit le dump dessus. Clone complet "
                               "incluant l'UID (bloc 0).",
                   params=[{"name": "clone_name", "label": "Nom du clone",
                            "type": "text", "default": "",
                            "placeholder": "ex: clone-badge"}]),
            Action("write_ultralight", "Écrire Ultralight / NTAG", "active",
                   description="Écrit un dump .mfd sur un MIFARE Ultralight "
                               "ou NTAG.",
                   params=[{"name": "dump_file", "label": "Dump source",
                            "type": "nfc_dump"}]),
        ]

    # ── Vérifications ─────────────────────────────────────────────────────

    def _check_nfc(self) -> Optional[Dict[str, Any]]:
        """Vérifie que le PN532 est accessible."""
        if not _which("nfc-list"):
            return {"ok": False,
                    "error": "libnfc non installé. Installe libnfc-bin."}
        try:
            ret = _run(["sudo", "nfc-list"], timeout=10)
            if "opened" not in ret.stdout.lower():
                err = ret.stderr.strip() or ret.stdout.strip()
                return {"ok": False,
                        "error": f"PN532 non détecté. Vérifie le câblage I2C "
                                 f"(SDA/SCL/VCC/GND).\n{err}"}
        except subprocess.TimeoutExpired:
            return {"ok": False,
                    "error": "Timeout nfc-list — le PN532 ne répond pas. "
                             "Vérifie le câblage et redémarre si besoin."}
        return None

    # ── Implémentations ───────────────────────────────────────────────────

    def _poll_tag(self, timeout: int) -> Dict[str, Any]:
        """Détecte un tag NFC et lit son UID + type."""
        err = self._check_nfc()
        if err:
            return err

        task = current_task()
        if task:
            task.log(f"📡 Détection NFC ({timeout}s) — pose un tag…")

        # nfc-list fait un poll unique ; on boucle pour le timeout
        deadline = time.time() + timeout
        tags = []
        while time.time() < deadline:
            if task and task.is_stopped():
                break
            ret = _run(["sudo", "nfc-list"], timeout=8)
            tags = _parse_nfc_list(ret.stdout)
            if tags:
                break
            if task:
                task.log("  …aucun tag, réessai…")
            time.sleep(1.5)

        if not tags:
            return {"ok": True,
                    "message": f"Aucun tag NFC détecté en {timeout}s.\n"
                               "Vérifie que le tag est bien posé sur le PN532."}

        tag = tags[0]
        tag_type = _identify_tag(tag)
        uid = _uid_short(tag)

        # Stocker dans last_tags
        entry = {**tag, "identified": tag_type,
                 "ts": time.strftime("%H:%M:%S")}
        self._last_tags.append(entry)
        if len(self._last_tags) > 50:
            self._last_tags = self._last_tags[-50:]

        msg = f"<b>Tag NFC détecté</b>\n\n"
        msg += f"  UID : <code>{uid}</code>\n"
        msg += f"  Type : <b>{tag_type}</b>\n"
        if tag.get("atqa"):
            msg += f"  ATQA : <code>{tag['atqa']}</code>\n"
        if tag.get("sak"):
            msg += f"  SAK  : <code>{tag['sak']}</code>\n"
        if tag.get("ats"):
            msg += f"  ATS  : <code>{tag['ats']}</code>\n"

        # Conseils selon le type
        if "Classic" in tag_type:
            msg += ("\n→ Utilise <b>Dump MIFARE Classic</b> pour lire le "
                    "contenu, ou <b>Crack clés</b> si les clés par défaut "
                    "ne marchent pas.")
        elif "Ultralight" in tag_type or "NTAG" in tag_type:
            msg += "\n→ Utilise <b>Dump Ultralight / NTAG</b> pour lire."
        elif "DESFire" in tag_type:
            msg += "\n⚠ DESFire utilise un chiffrement AES — lecture limitée."

        if task:
            task.log(f"✅ Tag détecté : {uid} ({tag_type})")

        return {"ok": True, "tag": entry, "message": msg}

    def _read_info(self, timeout: int) -> Dict[str, Any]:
        """Lecture approfondie d'un tag."""
        # Réutilise poll_tag avec plus de détails
        result = self._poll_tag(timeout)
        if not result.get("ok") or "tag" not in result:
            return result

        tag = result["tag"]
        tag_type = tag.get("identified", "Inconnu")

        # Infos supplémentaires selon le type
        msg = result["message"]
        if "Classic 1K" in tag_type:
            msg += "\n\n<b>Structure MIFARE Classic 1K :</b>\n"
            msg += "  • 16 secteurs × 4 blocs × 16 octets = 1024 octets\n"
            msg += "  • Bloc 0 : UID + données constructeur (lecture seule)\n"
            msg += "  • Bloc 3,7,11…63 : sector trailers (clés A/B + ACL)\n"
            msg += "  • 752 octets de données utilisables"
        elif "Classic 4K" in tag_type:
            msg += "\n\n<b>Structure MIFARE Classic 4K :</b>\n"
            msg += "  • 32 petits secteurs (4 blocs) + 8 grands (16 blocs)\n"
            msg += "  • Total : 4096 octets, ~3440 utilisables"
        elif "Ultralight" in tag_type:
            msg += "\n\n<b>Structure Ultralight / NTAG :</b>\n"
            msg += "  • Pages de 4 octets\n"
            msg += "  • Ultralight : 16 pages (64 octets)\n"
            msg += "  • NTAG213 : 45 pages (180 octets)\n"
            msg += "  • NTAG215 : 135 pages (540 octets, Amiibo)\n"
            msg += "  • NTAG216 : 231 pages (924 octets)"

        return {"ok": True, "tag": tag, "message": msg}

    def _scan_tags(self, duration: int) -> Dict[str, Any]:
        """Écoute prolongée, log tous les tags."""
        err = self._check_nfc()
        if err:
            return err

        task = current_task()
        if task:
            task.log(f"📡 Scan NFC ({duration}s) — présente des tags…")

        seen = []  # (uid, type, ts)
        seen_uids = set()
        deadline = time.time() + duration

        while time.time() < deadline:
            if task and task.is_stopped():
                if task:
                    task.log("⏹ Stop demandé.", "warn")
                break
            ret = _run(["sudo", "nfc-list"], timeout=8)
            tags = _parse_nfc_list(ret.stdout)
            for tag in tags:
                uid = _uid_short(tag)
                tag_type = _identify_tag(tag)
                ts = time.strftime("%H:%M:%S")

                # Ne logger qu'une fois par UID (sauf si retiré et remis)
                key = uid
                if key not in seen_uids:
                    seen_uids.add(key)
                    entry = {**tag, "identified": tag_type, "ts": ts}
                    seen.append(entry)
                    self._last_tags.append(entry)

                    if task:
                        task.log(f"  [{ts}] {uid} — {tag_type}")

            if not tags:
                # Le tag a été retiré → reset pour pouvoir re-détecter
                seen_uids.clear()

            time.sleep(1.0)

        if len(self._last_tags) > 50:
            self._last_tags = self._last_tags[-50:]

        if not seen:
            return {"ok": True,
                    "message": f"Aucun tag NFC détecté en {duration}s."}

        msg = f"<b>{len(seen)} tag(s)</b> détecté(s) en {duration}s :\n\n"
        for s in seen:
            msg += (f"  [{s['ts']}] <code>{_uid_short(s)}</code> — "
                    f"<b>{s.get('identified', '?')}</b>\n")

        return {"ok": True, "tags": seen, "message": msg}

    def _dump_classic(self, dump_name: str,
                      key_file: str = "") -> Dict[str, Any]:
        """Dump complet MIFARE Classic via nfc-mfclassic."""
        err = self._check_nfc()
        if err:
            return err
        if not dump_name or not dump_name.strip():
            return {"ok": False,
                    "error": "Donne un nom au dump (ex: badge-bureau)."}

        name = re.sub(r'[^\w\-]', '_', dump_name.strip())
        NFC_TMP.mkdir(parents=True, exist_ok=True)
        tmp_out = NFC_TMP / f"{name}.mfd"

        task = current_task()
        if task:
            task.log(f"📖 Dump MIFARE Classic → {name}.mfd")
            task.log("  Pose le tag et ne le retire pas…")

        # Construire la commande : nfc-mfclassic r a u <dump.mfd> [keys.mfd]
        cmd = ["sudo", "nfc-mfclassic", "r", "A", "u", str(tmp_out)]
        if key_file and Path(key_file).is_file():
            cmd.append(key_file)
            if task:
                task.log(f"  Clés depuis : {Path(key_file).name}")

        try:
            ret = _run(cmd, timeout=120)
        except subprocess.TimeoutExpired:
            return {"ok": False,
                    "error": "Timeout pendant le dump (120s). Le tag a été "
                             "retiré ou les clés sont incorrectes."}

        if task:
            for line in ret.stdout.splitlines()[-10:]:
                if line.strip():
                    task.log(f"  {line.strip()}")
            if ret.stderr.strip():
                for line in ret.stderr.strip().splitlines()[-5:]:
                    task.log(f"  ⚠ {line.strip()}", "warn")

        # Vérifier si le dump a réussi
        if not tmp_out.exists() or tmp_out.stat().st_size == 0:
            errmsg = ret.stderr.strip() or ret.stdout.strip()
            if "authentication failed" in errmsg.lower():
                return {"ok": False,
                        "error": "Authentification échouée. Les clés par "
                                 "défaut ne marchent pas. Lance <b>Crack "
                                 "clés MIFARE</b> (MFOC) d'abord."}
            return {"ok": False,
                    "error": f"Dump échoué.\n{errmsg}"}

        size = tmp_out.stat().st_size

        # Sauvegarder en mémoire persistante
        NFC_DATA.mkdir(parents=True, exist_ok=True)
        dest = NFC_DATA / f"{name}.mfd"
        if dest.exists():
            dest = NFC_DATA / f"{name}_{int(time.time())}.mfd"

        import shutil
        shutil.copy2(str(tmp_out), str(dest))
        self._refresh_saved()

        if task:
            task.log(f"💾 Dump sauvegardé : {dest} ({size} octets)")

        tag_type = "4K" if size >= MFC_4K_SIZE else "1K"
        sectors = 40 if size >= MFC_4K_SIZE else 16
        msg = (f"Dump MIFARE Classic <b>{tag_type}</b> réussi.\n\n"
               f"  Taille : <code>{size}</code> octets ({sectors} secteurs)\n"
               f"  Fichier : <code>{dest.name}</code>\n\n"
               "→ Utilise <b>Écrire MIFARE Classic</b> ou <b>Cloner</b> "
               "pour copier sur un autre tag.")

        return {"ok": True, "dump": str(dest), "size": size, "message": msg}

    def _dump_ultralight(self, dump_name: str) -> Dict[str, Any]:
        """Dump MIFARE Ultralight / NTAG via nfc-mfultralight."""
        err = self._check_nfc()
        if err:
            return err
        if not dump_name or not dump_name.strip():
            return {"ok": False,
                    "error": "Donne un nom au dump (ex: ntag-215)."}

        name = re.sub(r'[^\w\-]', '_', dump_name.strip())
        NFC_TMP.mkdir(parents=True, exist_ok=True)
        tmp_out = NFC_TMP / f"{name}.mfd"

        task = current_task()
        if task:
            task.log(f"📖 Dump Ultralight/NTAG → {name}.mfd")
            task.log("  Pose le tag et ne le retire pas…")

        cmd = ["sudo", "nfc-mfultralight", "r", str(tmp_out)]
        try:
            ret = _run(cmd, timeout=60)
        except subprocess.TimeoutExpired:
            return {"ok": False,
                    "error": "Timeout pendant le dump (60s)."}

        if task:
            for line in ret.stdout.splitlines()[-10:]:
                if line.strip():
                    task.log(f"  {line.strip()}")

        if not tmp_out.exists() or tmp_out.stat().st_size == 0:
            errmsg = ret.stderr.strip() or ret.stdout.strip()
            return {"ok": False,
                    "error": f"Dump Ultralight échoué.\n{errmsg}"}

        size = tmp_out.stat().st_size

        NFC_DATA.mkdir(parents=True, exist_ok=True)
        dest = NFC_DATA / f"{name}.mfd"
        if dest.exists():
            dest = NFC_DATA / f"{name}_{int(time.time())}.mfd"

        import shutil
        shutil.copy2(str(tmp_out), str(dest))
        self._refresh_saved()

        if task:
            task.log(f"💾 Dump sauvegardé : {dest} ({size} octets)")

        pages = size // 4
        msg = (f"Dump Ultralight/NTAG réussi.\n\n"
               f"  Taille : <code>{size}</code> octets ({pages} pages)\n"
               f"  Fichier : <code>{dest.name}</code>\n\n"
               "→ Utilise <b>Écrire Ultralight</b> pour copier sur un "
               "autre tag.")

        return {"ok": True, "dump": str(dest), "size": size, "message": msg}

    def _crack_keys(self, dump_name: str) -> Dict[str, Any]:
        """Crack clés MIFARE Classic via MFOC (nested attack)."""
        err = self._check_nfc()
        if err:
            return err
        if not _which("mfoc"):
            return {"ok": False,
                    "error": "mfoc non installé. `sudo apt install mfoc`."}
        if not dump_name or not dump_name.strip():
            return {"ok": False,
                    "error": "Donne un nom au résultat (ex: badge-cracke)."}

        name = re.sub(r'[^\w\-]', '_', dump_name.strip())
        NFC_TMP.mkdir(parents=True, exist_ok=True)
        tmp_out = NFC_TMP / f"{name}.mfd"

        task = current_task()
        if task:
            task.log(f"🔓 MFOC crack → {name}.mfd")
            task.log("  Attaque nested authentication en cours…")
            task.log("  ⚠ Peut prendre plusieurs minutes. Ne retire pas le tag.")

        # mfoc -O <output.mfd>
        # Lit le tag, tente les clés par défaut, puis nested attack
        proc = subprocess.Popen(
            ["sudo", "mfoc", "-O", str(tmp_out)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, errors="replace")

        lines_out = []
        try:
            while True:
                if task and task.is_stopped():
                    proc.terminate()
                    if task:
                        task.log("⏹ Stop demandé.", "warn")
                    break
                line = proc.stdout.readline()
                if not line:
                    break
                line = line.rstrip()
                if line:
                    lines_out.append(line)
                    if task:
                        # Filtrer les lignes intéressantes
                        ll = line.lower()
                        if any(k in ll for k in (
                            "found key", "sector", "auth", "exploit",
                            "dumping", "success", "error", "fail",
                            "done", "writing")):
                            task.log(f"  {line}")
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        except Exception:
            proc.kill()

        rc = proc.returncode

        if not tmp_out.exists() or tmp_out.stat().st_size == 0:
            # Échec : afficher les dernières lignes
            tail = "\n".join(lines_out[-15:]) if lines_out else "(aucune sortie)"
            if any("no sector encrypted" in l.lower() for l in lines_out):
                return {"ok": False,
                        "error": "Aucun secteur chiffré trouvé. Le tag "
                                 "utilise peut-être les clés par défaut "
                                 "partout → essaie un dump direct."}
            return {"ok": False,
                    "error": f"MFOC échoué (code {rc}).\n\n"
                             f"Dernières lignes :\n{tail}"}

        size = tmp_out.stat().st_size

        NFC_DATA.mkdir(parents=True, exist_ok=True)
        dest = NFC_DATA / f"{name}.mfd"
        if dest.exists():
            dest = NFC_DATA / f"{name}_{int(time.time())}.mfd"

        import shutil
        shutil.copy2(str(tmp_out), str(dest))
        self._refresh_saved()

        if task:
            task.log(f"✅ Crack réussi ! Dump : {dest} ({size} octets)")

        # Extraire les clés trouvées depuis la sortie
        keys_found = []
        for line in lines_out:
            m = re.search(
                r"[Ff]ound [Kk]ey:?\s*\[?([0-9a-fA-F]{12})\]?", line)
            if m:
                keys_found.append(m.group(1).upper())

        msg = (f"<b>Crack MFOC réussi</b>\n\n"
               f"  Dump : <code>{dest.name}</code> ({size} octets)\n")
        if keys_found:
            unique_keys = list(dict.fromkeys(keys_found))
            msg += f"  Clés trouvées ({len(unique_keys)}) :\n"
            for k in unique_keys[:20]:
                msg += f"    <code>{k}</code>\n"
        msg += ("\n→ Ce dump contient les clés. Utilise-le comme "
                "<b>fichier de clés</b> pour un dump complet, "
                "ou directement pour <b>Écrire / Cloner</b>.")

        return {"ok": True, "dump": str(dest), "size": size,
                "keys": keys_found, "message": msg}

    def _write_classic(self, dump_file: str,
                       unlock: str = "normal") -> Dict[str, Any]:
        """Écrit un dump MFD sur un MIFARE Classic."""
        err = self._check_nfc()
        if err:
            return err
        if not dump_file or not Path(dump_file).is_file():
            return {"ok": False,
                    "error": "Sélectionne un dump .mfd à écrire."}

        src = Path(dump_file)
        task = current_task()

        # w = normal write, W = unlocked write (Chinese clone, block 0)
        mode = "W" if unlock == "unlock" else "w"
        mode_label = "déverrouillé (Chinese clone)" if mode == "W" else "normal"

        if task:
            task.log(f"✍ Écriture MIFARE Classic ({mode_label})")
            task.log(f"  Source : {src.name}")
            task.log("  Pose le tag cible et ne le retire pas…")

        cmd = ["sudo", "nfc-mfclassic", mode, "A", "u",
               str(src), str(src)]  # dump source = aussi fichier de clés

        try:
            ret = _run(cmd, timeout=120)
        except subprocess.TimeoutExpired:
            return {"ok": False,
                    "error": "Timeout écriture (120s). Tag retiré ?"}

        if task:
            for line in ret.stdout.splitlines()[-10:]:
                if line.strip():
                    task.log(f"  {line.strip()}")

        out = ret.stdout + ret.stderr
        if "done" in out.lower() or "written" in out.lower():
            if task:
                task.log("✅ Écriture terminée !")
            return {"ok": True,
                    "message": f"Écriture MIFARE Classic terminée ({mode_label}).\n"
                               f"Source : <code>{src.name}</code>"}

        errmsg = ret.stderr.strip() or ret.stdout.strip()
        if "authentication failed" in errmsg.lower():
            return {"ok": False,
                    "error": "Authentification échouée. Le tag cible n'a pas "
                             "les mêmes clés. Utilise un Chinese clone (Gen1) "
                             "avec le mode <b>Unlock</b>."}
        return {"ok": False,
                "error": f"Écriture échouée.\n{errmsg}"}

    def _clone_classic(self, clone_name: str) -> Dict[str, Any]:
        """Clone complet : lit source → écrit sur cible (Chinese clone)."""
        err = self._check_nfc()
        if err:
            return err
        if not clone_name or not clone_name.strip():
            return {"ok": False,
                    "error": "Donne un nom au clone (ex: clone-badge)."}

        name = re.sub(r'[^\w\-]', '_', clone_name.strip())
        task = current_task()

        # Étape 1 : Lire la carte source
        if task:
            task.log("📖 Étape 1/2 : Lecture de la carte source…")
            task.log("  Pose la carte ORIGINALE sur le lecteur.")

        # Essayer d'abord un dump avec clés par défaut
        dump_result = self._dump_classic(f"{name}_source")
        if not dump_result.get("ok"):
            # Si les clés par défaut échouent, tenter MFOC
            if "authentification" in dump_result.get("error", "").lower():
                if task:
                    task.log("  Clés par défaut refusées → lancement MFOC…",
                             "warn")
                dump_result = self._crack_keys(f"{name}_source")
                if not dump_result.get("ok"):
                    return dump_result
            else:
                return dump_result

        src_dump = dump_result.get("dump", "")
        if not src_dump or not Path(src_dump).is_file():
            return {"ok": False,
                    "error": "Dump source introuvable après lecture."}

        # Étape 2 : Écrire sur la carte cible
        if task:
            task.log("")
            task.log("✍ Étape 2/2 : Écriture sur la carte cible…")
            task.log("  ⚠ RETIRE la carte originale.")
            task.log("  Pose la carte CIBLE (Chinese clone) sur le lecteur.")
            task.log("  Attente 8s pour le changement de carte…")

        # Attendre que l'utilisateur change de carte
        if task:
            if not task.wait(8, check_interval=1.0):
                return {"ok": True,
                        "message": "Clone interrompu. Le dump source a été "
                                   f"sauvegardé : <code>{Path(src_dump).name}</code>"}

        # Écriture déverrouillée (bloc 0 inclus = UID cloné)
        write_result = self._write_classic(src_dump, unlock="unlock")

        if write_result.get("ok"):
            msg = (f"<b>Clone MIFARE Classic réussi !</b>\n\n"
                   f"  Dump source : <code>{Path(src_dump).name}</code>\n"
                   "  La carte cible est maintenant une copie exacte "
                   "(UID + données + clés).")
            return {"ok": True, "message": msg}

        # Si l'écriture unlock échoue, essayer en normal
        if task:
            task.log("  Écriture unlock échouée — essai en mode normal…",
                     "warn")
        write_result = self._write_classic(src_dump, unlock="normal")
        if write_result.get("ok"):
            msg = (f"<b>Clone partiel réussi</b>\n\n"
                   f"  Dump source : <code>{Path(src_dump).name}</code>\n"
                   "  ⚠ Les données sont copiées mais l'UID (bloc 0) "
                   "n'a pas pu être écrit.\n"
                   "  Pour un clone UID, utilise un tag Chinese clone Gen1.")
            return {"ok": True, "message": msg}

        return write_result

    def _write_ultralight(self, dump_file: str) -> Dict[str, Any]:
        """Écrit un dump MFD sur un MIFARE Ultralight / NTAG."""
        err = self._check_nfc()
        if err:
            return err
        if not dump_file or not Path(dump_file).is_file():
            return {"ok": False,
                    "error": "Sélectionne un dump .mfd à écrire."}

        src = Path(dump_file)
        task = current_task()
        if task:
            task.log(f"✍ Écriture Ultralight/NTAG")
            task.log(f"  Source : {src.name}")
            task.log("  Pose le tag cible…")

        cmd = ["sudo", "nfc-mfultralight", "w", str(src), "--full"]

        try:
            ret = _run(cmd, timeout=60)
        except subprocess.TimeoutExpired:
            return {"ok": False,
                    "error": "Timeout écriture (60s)."}

        if task:
            for line in ret.stdout.splitlines()[-10:]:
                if line.strip():
                    task.log(f"  {line.strip()}")

        out = ret.stdout + ret.stderr
        if "done" in out.lower() or "written" in out.lower():
            if task:
                task.log("✅ Écriture terminée !")
            return {"ok": True,
                    "message": f"Écriture Ultralight/NTAG terminée.\n"
                               f"Source : <code>{src.name}</code>"}

        errmsg = ret.stderr.strip() or ret.stdout.strip()
        return {"ok": False,
                "error": f"Écriture échouée.\n{errmsg}"}

    # ── Dispatch ──────────────────────────────────────────────────────────

    def run(self, action_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        known = {a.id for a in self.actions()}
        if action_id not in known:
            return {"ok": False, "error": f"action inconnue : {action_id}"}

        try:
            timeout = int(params.get("timeout", 15))
        except (TypeError, ValueError):
            timeout = 15

        try:
            if action_id == "poll_tag":
                return self._poll_tag(max(5, min(60, timeout)))
            if action_id == "read_info":
                return self._read_info(max(5, min(60, timeout)))
            if action_id == "scan_tags":
                dur = int(params.get("duration", 30))
                return self._scan_tags(max(10, min(300, dur)))
            if action_id == "dump_classic":
                name = str(params.get("dump_name", ""))
                key_file = str(params.get("key_file", ""))
                return self._dump_classic(name, key_file)
            if action_id == "dump_ultralight":
                name = str(params.get("dump_name", ""))
                return self._dump_ultralight(name)
            if action_id == "crack_keys":
                name = str(params.get("dump_name", ""))
                return self._crack_keys(name)
            if action_id == "write_classic":
                dump = str(params.get("dump_file", ""))
                unlock = str(params.get("unlock", "normal"))
                return self._write_classic(dump, unlock)
            if action_id == "clone_classic":
                name = str(params.get("clone_name", ""))
                return self._clone_classic(name)
            if action_id == "write_ultralight":
                dump = str(params.get("dump_file", ""))
                return self._write_ultralight(dump)
            return {"ok": False,
                    "error": f"action non implémentée : {action_id}"}
        except Exception as e:
            tb = traceback.format_exc()
            print(f"[nfc] EXCEPTION run({action_id}): "
                  f"{type(e).__name__}: {e}\n{tb}", file=sys.stderr)
            return {"ok": False,
                    "error": f"{type(e).__name__}: {e}",
                    "trace": tb.splitlines()[-6:]}
