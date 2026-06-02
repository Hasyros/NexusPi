# Wi-Fi Attack Surface — NexusPi

> Reference document for the Wi-Fi auditing capabilities of NexusPi (Alfa AWUS036ACH / RTL8812AU).
> Each technique is paired with its real-world purpose, required tooling, and **defensive counterpart**.
> This file is a planning/reference artifact — it maps what the `wifi.py` module *could* expose in the app.

---

## ⚠️ Legal & Ethical Scope

Everything documented here is intended for **authorized security testing and education only**.

Lawful use is limited to:
- Networks and devices **you own**
- A controlled lab environment you fully control
- An engagement with **explicit written authorization** (scope agreement)

In France specifically:
- **Art. 323-1 et seq. of the Code pénal** — fraudulent access or maintenance in an automated data processing system is a criminal offense.
- **Interception of private communications** without consent is prohibited.
- **ARCEP** regulates RF transmission; unauthorized emission on regulated bands is illegal.

Using these techniques against third-party networks without permission is a crime. You are solely responsible for your use of this toolkit.

---

## Hardware Capability Baseline

| Capability | Requirement | AWUS036ACH (RTL8812AU) |
|---|---|---|
| Monitor mode | Driver + chipset support | ✅ |
| Packet injection | Driver + chipset support | ✅ |
| 2.4 GHz | Single-band minimum | ✅ |
| 5 GHz | Dual-band | ✅ |
| AP mode (rogue AP) | hostapd-compatible driver | ✅ |
| 6 GHz (WiFi 6E) | Newer chipset (not 8812AU) | ❌ |

> Note: the native in-kernel `rtw88_8812au` driver (kernel ≥ 6.14) handles monitor/injection well.
> Some advanced fork-only features may vary — validate injection with `aireplay-ng --test`.

---

## 1. Passive Reconnaissance

No frames transmitted — purely listening. Lowest legal risk, foundation of everything else.

### 1.1 Network scanning / wardriving
- **Principle:** enumerate nearby APs — SSID, BSSID, channel, encryption, signal strength.
- **Tools:** `airodump-ng`, `kismet`
- **Injection:** No
- **NexusPi angle:** pair with the GPS module to geolocate networks (wardriving map in the app UI).

### 1.2 Client / device detection
- **Principle:** identify connected stations, their MACs, and the APs they associate with.
- **Tools:** `airodump-ng`, `kismet`
- **Injection:** No

### 1.3 Probe request sniffing
- **Principle:** capture the network names client devices actively search for — reveals previously-joined SSIDs, enabling device profiling and Karma-style attacks.
- **Tools:** `airodump-ng`, `probequest`
- **Injection:** No

### 1.4 Hidden SSID discovery
- **Principle:** a cloaked SSID is revealed the moment a client (re)associates.
- **Tools:** `airodump-ng` (+ optional deauth to force reassociation)
- **Injection:** Only if forcing reassociation

---

## 2. Handshake Capture (path to the passphrase)

### 2.1 WPA/WPA2 4-way handshake capture
- **Principle:** the initial key exchange when a client joins contains material to test the passphrase **offline**.
- **Flow:** capture with `airodump-ng` → (optionally deauth to force a handshake) → crack with `aircrack-ng` / `hashcat`.
- **Tools:** `airodump-ng`, `aircrack-ng`, `hashcat`
- **Injection:** For the deauth step

### 2.2 PMKID capture (clientless)
- **Principle:** retrieve crackable material **directly from a vulnerable AP** without waiting for a client. Stealthier — no deauth needed.
- **Tools:** `hcxdumptool`, `hcxpcapngtool`, `hashcat`
- **Injection:** No

> Cracking itself (offline) is where the GPU/CPU of the host (phone/laptop) matters — fits the NexusPi "offload heavy work to the client" architecture.

---

## 3. Active / Denial-of-Service

Require injection. Disruptive and **highly visible** — easy to detect, high legal exposure.

### 3.1 Deauthentication
- **Principle:** spoof deauth frames to kick clients off an AP. Used to force handshake capture or as a DoS.
- **Tools:** `aireplay-ng --deauth`, `mdk4 d`
- **Injection:** Yes
- **Note:** Protected Management Frames (PMF / 802.11w) defeat this — increasingly common on modern APs.

### 3.2 Disassociation
- **Principle:** variant of deauth using disassoc frames.
- **Tools:** `mdk4`, `aireplay-ng`
- **Injection:** Yes

### 3.3 Beacon flooding
- **Principle:** flood the area with fake SSIDs (noise, confusion, fill client network lists).
- **Tools:** `mdk4 b`
- **Injection:** Yes

### 3.4 Authentication flood
- **Principle:** overwhelm an AP with fake auth/association requests (resource-exhaustion DoS).
- **Tools:** `mdk4 a`
- **Injection:** Yes

---

## 4. Rogue AP / Man-in-the-Middle

The core of high-value pentest scenarios. Requires AP mode + injection.

### 4.1 Evil Twin
- **Principle:** stand up an AP cloning a legitimate SSID (often stronger signal) so victims connect to you. Their traffic then flows through you.
- **Tools:** `hostapd`, `airgeddon`, `wifipumpkin3`, `eaphammer`
- **Injection:** Yes (often combined with deauth of the real AP)

### 4.2 Captive portal / Wi-Fi phishing
- **Principle:** the evil twin serves a fake login page ("re-enter your Wi-Fi password") to harvest credentials. Social-engineering driven.
- **Tools:** `wifipumpkin3`, `airgeddon`, `Fluxion`
- **Injection:** Yes

### 4.3 Karma attack
- **Principle:** answer "yes, that's me" to every client probe request, exploiting devices that auto-search for known networks.
- **Tools:** `hostapd-mana`, `eaphammer`
- **Injection:** Yes

### 4.4 Post-connection MITM
- **Principle:** once victims are on your rogue AP — DNS spoofing, SSL stripping, content injection, credential interception.
- **Tools:** `bettercap`, `mitmproxy`, `ettercap`
- **Injection:** Yes (and routing/forwarding on the host)

---

## 5. WPS Attacks

### 5.1 WPS PIN brute force
- **Principle:** the 8-digit WPS PIN has a design flaw that shrinks the search space dramatically (checked in two halves).
- **Tools:** `reaver`, `bully`
- **Injection:** Yes

### 5.2 Pixie Dust
- **Principle:** exploits weak nonce generation on some routers to recover the WPS PIN offline in seconds.
- **Tools:** `reaver -K`, `bully --pixie-dust`
- **Injection:** Yes

---

## 6. WPA3 & Modern Protocols

### 6.1 Dragonblood
- **Principle:** family of flaws in WPA3's SAE handshake (timing/cache side-channels, downgrade). Complex and hardware-dependent.
- **Tools:** `dragonslayer`, `dragondrain` (research tooling)
- **Injection:** Yes

### 6.2 WPA3 transition downgrade
- **Principle:** force an AP running WPA3/WPA2 "transition mode" to fall back to WPA2, then attack the weaker path.
- **Tools:** `hostapd`-based rogue + deauth
- **Injection:** Yes

---

## Summary Matrix

| Category | Attack | Primary tool | Injection | PMF/WPA3 resistant? |
|---|---|---|---|---|
| Recon | Scanning / wardriving | airodump-ng, kismet | No | n/a |
| Recon | Probe request sniffing | airodump-ng | No | n/a |
| Recon | Hidden SSID discovery | airodump-ng | Maybe | n/a |
| Crack | WPA2 handshake capture | airodump-ng + aircrack-ng | For deauth | Harder w/ PMF |
| Crack | PMKID capture | hcxdumptool | No | AP-dependent |
| DoS | Deauth / disassoc | aireplay-ng, mdk4 | Yes | Defeated by PMF |
| DoS | Beacon / auth flood | mdk4 | Yes | n/a |
| MITM | Evil Twin | hostapd, airgeddon | Yes | Partially |
| MITM | Captive portal phishing | wifipumpkin3 | Yes | Social-eng |
| MITM | Karma | hostapd-mana, eaphammer | Yes | Modern OSes resist |
| MITM | Post-connection MITM | bettercap | Yes | HSTS/TLS resist |
| WPS | PIN brute force | reaver, bully | Yes | WPS-only |
| WPS | Pixie Dust | reaver -K | Yes | WPS-only |
| WPA3 | Dragonblood | dragonslayer | Yes | Target-specific |
| WPA3 | Transition downgrade | hostapd + deauth | Yes | Transition-mode only |

---

## Defensive Counterparts (Blue Team view)

A security tool is more valuable when it understands defense. For each attack class:

| Attack class | Detection | Mitigation |
|---|---|---|
| Passive recon | Hard to detect (no emission) | Reduce SSID broadcast info, MAC randomization awareness |
| Handshake/PMKID | WIDS anomaly on deauth bursts | Strong passphrase (length > dictionary), WPA3-SAE |
| Deauth / DoS | Spike in deauth/disassoc frames | **802.11w (PMF)** mandatory, WIDS/WIPS |
| Evil Twin / Karma | Rogue AP detection, BSSID mismatch | 802.1X/EAP-TLS, certificate validation, PMF |
| Captive phishing | User training, URL/cert inspection | DNS over HTTPS, no credential reuse |
| WPS attacks | WPS attempt logging | **Disable WPS entirely** |
| WPA3 Dragonblood | Vendor patch status | Firmware updates, disable transition mode |

---

## NexusPi Implementation Notes

Suggested phased rollout for the `wifi.py` module + app UI:

- **Phase 1 — Passive:** scanning, client list, probe sniffing, GPS-tagged wardriving map. Lowest risk, great demo value.
- **Phase 2 — Capture:** handshake + PMKID capture, with offload of cracking to the client device.
- **Phase 3 — Active (lab-gated):** deauth, floods — behind an explicit "lab mode" confirmation in the UI.
- **Phase 4 — Rogue AP:** evil twin + captive portal framework — most complex, highest impact.

> Design suggestion: gate Phases 3–4 behind an in-app acknowledgment screen restating the legal scope, and log every active operation (timestamp, target, operator) to support the "authorized engagement" audit trail described in `threat-model.md`.

---

*Reference document — part of the NexusPi project. For educational and authorized testing use only.*
