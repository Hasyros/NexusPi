"""
Module Mémoire — captures persistantes (handshakes, PMKID).

C'est un "module virtuel" : pas de hardware. Il est toujours `connected`,
expose des actions de gestion (lister / supprimer un réseau / tout vider),
et rend les fichiers téléchargeables depuis le front via /api/files.
"""
import shutil
import subprocess
from collections import Counter
from html import escape
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import quote

from core.base_module import BaseModule, Action
from core import memory


# ── Format console (HTML pour la <div class="console" white-space:pre-wrap>) ──

def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}"
        n /= 1024
    return f"{n:.0f}TB"


def _dl_link(f: Dict[str, Any], label: str) -> str:
    href = f"/api/files?path={quote(f['path'])}"
    return (f"<a href='{href}' target='_blank' "
            f"style='color:#5bd5e0;text-decoration:underline'>{label}</a>")


def _format_networks_console(networks: List[Dict[str, Any]]) -> str:
    if not networks:
        return ("Mémoire vide.\n"
                "Lance un handshake_deauth, pmkid ou eviltwin réussi pour archiver une cible.")
    hs_total = sum(len(n["handshakes"]) for n in networks)
    pk_total = sum(len(n["pmkid_hashes"]) for n in networks)
    et_total = sum(len(n.get("eviltwin_creds", [])) for n in networks)
    lines = [f"{len(networks)} réseau(x) en mémoire — "
             f"{hs_total} handshake(s), {pk_total} PMKID, {et_total} eviltwin log(s).\n"]

    for n in networks:
        essid = escape(n.get("essid") or "<hidden>")
        bssid = escape(n.get("bssid") or "")
        chans = ",".join(str(c) for c in n.get("channels", []))
        enc = escape(n.get("encryption") or "")
        last = escape(n.get("last_seen") or "")
        lines.append(f"\n━━━ <b>{essid}</b> · {bssid} · ch{chans} · {enc}")
        lines.append(f"     vu pour la dernière fois : {last}")

        if n["handshakes"]:
            lines.append("   handshakes :")
            for f in n["handshakes"]:
                lines.append(f"     · {_dl_link(f, escape(f['name']))} "
                             f"<span style='color:#3a4a46'>"
                             f"({_human_size(f['size'])}, {escape(f['mtime'])})</span>")
        if n["pmkid_hashes"]:
            lines.append("   PMKID (hashcat-22000) :")
            for f in n["pmkid_hashes"]:
                lines.append(f"     · {_dl_link(f, escape(f['name']))} "
                             f"<span style='color:#3a4a46'>"
                             f"({_human_size(f['size'])})</span>")
        if n["pmkid_pcapng"]:
            lines.append("   PMKID (pcapng brut) :")
            for f in n["pmkid_pcapng"]:
                lines.append(f"     · {_dl_link(f, escape(f['name']))} "
                             f"<span style='color:#3a4a46'>"
                             f"({_human_size(f['size'])})</span>")
        if n.get("eviltwin_creds"):
            lines.append("   Evil Twin — creds portail captif (TSV) :")
            for f in n["eviltwin_creds"]:
                lines.append(f"     · {_dl_link(f, escape(f['name']))} "
                             f"<span style='color:#3a4a46'>"
                             f"({_human_size(f['size'])}, {escape(f['mtime'])})</span>")
        if n.get("eviltwin_pcaps"):
            lines.append("   Evil Twin — sniffing MITM (pcap) :")
            for f in n["eviltwin_pcaps"]:
                lines.append(f"     · {_dl_link(f, escape(f['name']))} "
                             f"<span style='color:#3a4a46'>"
                             f"({_human_size(f['size'])}, {escape(f['mtime'])})</span>")
    return "\n".join(lines)


# ── Module ──────────────────────────────────────────────────────────────────

class MemoryModule(BaseModule):
    id = "memory"
    name = "Mémoire — Captures"
    icon = "memory"
    description = "Handshakes, PMKID & métadonnées des réseaux capturés."

    def detect(self) -> bool:
        return True  # carte virtuelle, toujours dispo

    def actions(self) -> List[Action]:
        target_net = {"name": "bssid", "label": "Réseau", "type": "memory_network"}
        return [
            Action("list", "Lister les captures", "passive",
                   description="Affiche tous les réseaux stockés avec leurs fichiers cliquables."),
            Action("analyze_pcap", "Analyser pcap (DNS/HTTP/SNI)", "passive",
                   description="Parse le dernier pcap MITM d'un réseau via tshark : "
                               "DNS queries, HTTP requests, TLS SNI (HTTPS).",
                   params=[target_net]),
            Action("delete", "Supprimer un réseau", "active",
                   description="Efface toutes les captures d'un réseau précis. Lab mode requis.",
                   params=[target_net]),
            Action("clear", "Tout vider", "rogue",
                   description="Supprime TOUS les fichiers stockés. Irréversible. Lab mode requis."),
        ]

    def state(self) -> Dict[str, Any]:
        nets = memory.list_networks()
        return {
            "network_count": len(nets),
            "handshake_count": sum(len(n["handshakes"]) for n in nets),
            "pmkid_count": sum(len(n["pmkid_hashes"]) for n in nets),
            # Pour le <select type=memory_network> côté front
            "memory_networks": [{
                "bssid": n["bssid"], "essid": n["essid"],
                "handshakes": len(n["handshakes"]),
                "pmkid": len(n["pmkid_hashes"]),
            } for n in nets],
        }

    def run(self, action_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if action_id == "list":
            nets = memory.list_networks()
            return {"ok": True, "count": len(nets),
                    "networks": nets,
                    "message": _format_networks_console(nets)}
        if action_id == "analyze_pcap":
            bssid = str(params.get("bssid", "")).strip()
            return self._analyze_pcap(bssid)
        if action_id == "delete":
            bssid = str(params.get("bssid", "")).strip()
            if not bssid:
                return {"ok": False, "error": "BSSID requis"}
            ok = memory.delete_network(bssid)
            return ({"ok": True, "message": f"Réseau {bssid} supprimé."}
                    if ok else
                    {"ok": False, "error": f"Réseau {bssid} introuvable."})
        if action_id == "clear":
            n = memory.clear_all()
            return {"ok": True, "message": f"{n} réseau(x) effacé(s) de la mémoire."}
        return {"ok": False, "error": f"action inconnue: {action_id}"}

    # ── Analyse pcap via tshark ─────────────────────────────────────────────

    def _analyze_pcap(self, bssid: str) -> Dict[str, Any]:
        if not bssid:
            return {"ok": False, "error": "Réseau cible requis."}
        if not shutil.which("tshark"):
            return {"ok": False,
                    "error": "tshark requis (sudo apt install -y tshark)."}
        nets = memory.list_networks()
        target = next((n for n in nets
                       if n["bssid"].upper().replace("-", ":") == bssid.upper()
                       or n["bssid"] == bssid), None)
        if target is None:
            return {"ok": False, "error": f"Réseau {bssid!r} introuvable."}
        pcaps = target.get("eviltwin_pcaps", [])
        if not pcaps:
            return {"ok": False,
                    "error": "Aucun pcap MITM stocké pour ce réseau. "
                             "Lance un eviltwin en mode mitm d'abord."}
        pcap_path = Path(pcaps[-1]["path"])  # le plus récent
        return self._format_pcap_analysis(pcap_path, target)

    def _format_pcap_analysis(self, pcap_path: Path,
                              target: Dict[str, Any]) -> Dict[str, Any]:
        def tshark(args):
            try:
                res = subprocess.run(
                    ["tshark", "-r", str(pcap_path), *args],
                    capture_output=True, text=True, errors="replace",
                    timeout=60,
                )
                return res.stdout
            except Exception:
                return ""

        # DNS queries
        dns_out = tshark(["-Y", "dns.flags.response == 0",
                          "-T", "fields", "-e", "ip.src", "-e", "dns.qry.name"])
        dns_by_src: Dict[str, Counter] = {}
        for line in dns_out.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2 and parts[1]:
                dns_by_src.setdefault(parts[0], Counter())[parts[1]] += 1

        # HTTP requests
        http_out = tshark(["-Y", "http.request",
                           "-T", "fields", "-e", "ip.src", "-e", "http.host",
                           "-e", "http.request.method",
                           "-e", "http.request.uri"])
        http_reqs = []
        for line in http_out.splitlines():
            parts = line.split("\t")
            if len(parts) >= 4:
                http_reqs.append({"src": parts[0], "host": parts[1],
                                  "method": parts[2], "uri": parts[3]})

        # TLS SNI (sites HTTPS visités)
        sni_out = tshark(["-Y", "tls.handshake.extensions_server_name",
                          "-T", "fields", "-e", "ip.src",
                          "-e", "tls.handshake.extensions_server_name"])
        sni_by_src: Dict[str, Counter] = {}
        for line in sni_out.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2 and parts[1]:
                sni_by_src.setdefault(parts[0], Counter())[parts[1]] += 1

        # Format
        sz = pcap_path.stat().st_size
        lines = [f"<b>Analyse pcap</b> · {escape(target['essid'])} "
                 f"({target['bssid']})"]
        lines.append(f"Fichier : <code>{escape(pcap_path.name)}</code> "
                     f"({_human_size(sz)})\n")

        if not (dns_by_src or http_reqs or sni_by_src):
            lines.append("Aucun trafic HTTP/DNS/TLS exploitable dans ce pcap.")
            lines.append("Pistes : la victime n'a peut-être pas eu le temps de "
                         "naviguer, ou le trafic n'est pas passé par le rogue.")
            return {"ok": True, "message": "\n".join(lines)}

        if dns_by_src:
            total = sum(sum(c.values()) for c in dns_by_src.values())
            lines.append(f"━━━ DNS queries — {total} requêtes")
            for src, cnt in dns_by_src.items():
                lines.append(f"  <b>{escape(src)}</b> ({sum(cnt.values())}):")
                for dom, n in cnt.most_common(15):
                    lines.append(f"    {n:>3}× {escape(dom)}")

        if http_reqs:
            lines.append(f"\n━━━ HTTP requests — {len(http_reqs)}")
            for r in http_reqs[:30]:
                lines.append(f"  {escape(r['src'])} → "
                             f"<b>{escape(r['method'])}</b> "
                             f"http://{escape(r['host'])}{escape(r['uri'])}")
            if len(http_reqs) > 30:
                lines.append(f"  … et {len(http_reqs) - 30} de plus")

        if sni_by_src:
            total = sum(sum(c.values()) for c in sni_by_src.values())
            lines.append(f"\n━━━ TLS SNI (sites HTTPS visités) — {total}")
            for src, cnt in sni_by_src.items():
                lines.append(f"  <b>{escape(src)}</b>:")
                for sni, n in cnt.most_common(15):
                    lines.append(f"    {n:>3}× {escape(sni)}")

        return {"ok": True, "pcap": str(pcap_path),
                "dns_count": sum(sum(c.values()) for c in dns_by_src.values()),
                "http_count": len(http_reqs),
                "sni_count": sum(sum(c.values()) for c in sni_by_src.values()),
                "message": "\n".join(lines)}
