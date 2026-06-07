"""
Stockage persistant des captures (handshakes, PMKID, snapshots).

Arborescence sur le Pi :

    ~/nexuspi-data/
    └── captures/
        └── <BSSID-safe>/                 (ex: 4A-82-DE-4D-BC-5D)
            ├── meta.json                 essid, channels, encryption, first/last seen
            ├── handshakes/
            │   └── hs_<YYYYMMDD_HHMMSS>.cap
            └── pmkid/
                ├── pmkid_<...>.pcapng    capture brute
                └── pmkid_<...>.22000     hash hashcat prêt à casser

Pourquoi pas dans /tmp/nexuspi ?
    Parce que `_clean_scan_dir()` wipe /tmp/nexuspi au début de chaque action.
    Tu perdrais tes captures à chaque nouveau scan. La mémoire vit ailleurs.

API :
    store_handshake(...)   -> Path du fichier copié, ou None
    store_pmkid(...)       -> dict avec {pcapng, "22000"}
    list_networks()        -> liste de dicts pour le front
    delete_network(bssid)  -> bool
    clear_all()            -> int (nombre de réseaux supprimés)
"""
import json
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


DATA_DIR = Path.home() / "nexuspi-data"
CAPTURES_DIR = DATA_DIR / "captures"


# ── Helpers ─────────────────────────────────────────────────────────────────

def _safe_bssid(bssid: str) -> str:
    return bssid.replace(":", "-").upper()


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _now_tag() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def _net_dir(bssid: str) -> Path:
    d = CAPTURES_DIR / _safe_bssid(bssid)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _read_meta(d: Path) -> Dict[str, Any]:
    f = d / "meta.json"
    if not f.exists():
        return {}
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _write_meta(d: Path, meta: Dict[str, Any]) -> None:
    (d / "meta.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def is_within_data_dir(path: Path) -> bool:
    """Garde-fou : un path est-il bien sous ~/nexuspi-data/ ? (anti path traversal)"""
    try:
        Path(path).resolve().relative_to(DATA_DIR.resolve())
        return True
    except (ValueError, OSError):
        return False


# ── Mise à jour des métadonnées ─────────────────────────────────────────────

def update_network_info(bssid: str, essid: str, channel: int,
                        encryption: str = "") -> None:
    """Crée/met à jour le meta.json d'un réseau."""
    if not bssid:
        return
    d = _net_dir(bssid)
    meta = _read_meta(d)
    meta["bssid"] = bssid
    meta["essid"] = essid or meta.get("essid", "")
    meta.setdefault("first_seen", _now_iso())
    meta["last_seen"] = _now_iso()
    channels = set(meta.get("channels", []))
    if channel:
        channels.add(int(channel))
    meta["channels"] = sorted(channels)
    if encryption:
        meta["encryption"] = encryption
    _write_meta(d, meta)


# ── Stockage des fichiers ───────────────────────────────────────────────────

def store_handshake(bssid: str, essid: str, channel: int,
                    encryption: str, cap_path: Path) -> Optional[Path]:
    """Copie un .cap dans le stockage persistant. Retourne le chemin destination."""
    cap_path = Path(cap_path)
    if not cap_path.exists():
        return None
    update_network_info(bssid, essid, channel, encryption)
    d = _net_dir(bssid) / "handshakes"
    d.mkdir(parents=True, exist_ok=True)
    dest = d / f"hs_{_now_tag()}.cap"
    shutil.copy2(cap_path, dest)
    return dest


def store_pmkid(bssid: str, essid: str, channel: int, encryption: str,
                pcap_path: Optional[Path] = None,
                hash_path: Optional[Path] = None) -> Dict[str, Optional[Path]]:
    """Copie pcapng + hash 22000 dans le stockage."""
    update_network_info(bssid, essid, channel, encryption)
    d = _net_dir(bssid) / "pmkid"
    d.mkdir(parents=True, exist_ok=True)
    tag = _now_tag()
    out: Dict[str, Optional[Path]] = {"pcapng": None, "22000": None}
    if pcap_path and Path(pcap_path).exists():
        dest = d / f"pmkid_{tag}.pcapng"
        shutil.copy2(pcap_path, dest)
        out["pcapng"] = dest
    if hash_path and Path(hash_path).exists():
        dest = d / f"pmkid_{tag}.22000"
        shutil.copy2(hash_path, dest)
        out["22000"] = dest
    return out


def store_eviltwin_creds(bssid: str, essid: str, channel: int, encryption: str,
                         creds_log: Optional[Path]) -> Optional[Path]:
    """Copie le log creds (form portail captif) en mémoire."""
    if not creds_log:
        return None
    creds_log = Path(creds_log)
    if not creds_log.exists() or creds_log.stat().st_size == 0:
        return None
    update_network_info(bssid, essid, channel, encryption)
    d = _net_dir(bssid) / "eviltwin"
    d.mkdir(parents=True, exist_ok=True)
    dest = d / f"creds_{_now_tag()}.log"
    shutil.copy2(creds_log, dest)
    return dest


def store_eviltwin_pcap(bssid: str, essid: str, channel: int, encryption: str,
                        pcap_path: Optional[Path]) -> Optional[Path]:
    """Copie un pcap de sniffing MITM dans la mémoire."""
    if not pcap_path:
        return None
    pcap_path = Path(pcap_path)
    if not pcap_path.exists() or pcap_path.stat().st_size < 100:
        return None
    update_network_info(bssid, essid, channel, encryption)
    d = _net_dir(bssid) / "eviltwin"
    d.mkdir(parents=True, exist_ok=True)
    dest = d / f"sniff_{_now_tag()}.pcap"
    shutil.copy2(pcap_path, dest)
    return dest


# ── Lecture / nettoyage ─────────────────────────────────────────────────────

def _file_info(p: Path) -> Dict[str, Any]:
    try:
        s = p.stat()
        return {"path": str(p), "name": p.name, "size": s.st_size,
                "mtime": time.strftime("%Y-%m-%d %H:%M:%S",
                                       time.localtime(s.st_mtime))}
    except OSError:
        return {"path": str(p), "name": p.name, "size": 0, "mtime": ""}


def list_networks() -> List[Dict[str, Any]]:
    """Liste tous les réseaux stockés avec leurs fichiers."""
    if not CAPTURES_DIR.exists():
        return []
    networks = []
    for net_dir in sorted(CAPTURES_DIR.iterdir()):
        if not net_dir.is_dir():
            continue
        meta = _read_meta(net_dir)
        if not meta:
            continue
        hs_dir = net_dir / "handshakes"
        pmk_dir = net_dir / "pmkid"
        et_dir = net_dir / "eviltwin"
        handshakes = sorted(hs_dir.glob("*.cap")) if hs_dir.exists() else []
        pmkid_hashes = sorted(pmk_dir.glob("*.22000")) if pmk_dir.exists() else []
        pmkid_pcaps = sorted(pmk_dir.glob("*.pcapng")) if pmk_dir.exists() else []
        eviltwin_logs = sorted(et_dir.glob("*.log")) if et_dir.exists() else []
        eviltwin_pcaps = sorted(et_dir.glob("sniff_*.pcap")) if et_dir.exists() else []
        networks.append({
            "bssid": meta.get("bssid", ""),
            "essid": meta.get("essid", ""),
            "channels": meta.get("channels", []),
            "encryption": meta.get("encryption", ""),
            "first_seen": meta.get("first_seen", ""),
            "last_seen": meta.get("last_seen", ""),
            "handshakes": [_file_info(f) for f in handshakes],
            "pmkid_hashes": [_file_info(f) for f in pmkid_hashes],
            "pmkid_pcapng": [_file_info(f) for f in pmkid_pcaps],
            "eviltwin_creds": [_file_info(f) for f in eviltwin_logs],
            "eviltwin_pcaps": [_file_info(f) for f in eviltwin_pcaps],
        })
    # plus récent en premier
    networks.sort(key=lambda n: n.get("last_seen", ""), reverse=True)
    return networks


def delete_network(bssid: str) -> bool:
    d = CAPTURES_DIR / _safe_bssid(bssid)
    if d.exists():
        shutil.rmtree(d)
        return True
    return False


def clear_all() -> int:
    if not CAPTURES_DIR.exists():
        return 0
    count = sum(1 for x in CAPTURES_DIR.iterdir() if x.is_dir())
    shutil.rmtree(CAPTURES_DIR)
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    return count
