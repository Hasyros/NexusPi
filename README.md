# NexusPi — DIY Multi-Protocol Red Team Toolkit

> A handheld, Raspberry Pi–based alternative to the Flipper Zero, built for RF, sub-GHz, NFC/RFID, IR, and Wi-Fi security assessment. Capture happens on the device; heavy processing and the UI are offloaded to a phone or laptop over a local Wi-Fi link.

![Status](https://img.shields.io/badge/status-WIP-orange)
![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi%203B%2B-c51a4a)
![License](https://img.shields.io/badge/license-MIT-blue)

---

## ⚠️ Legal Notice

This project is built and documented **for educational purposes and authorized security testing only**. Transmitting on regulated RF bands, cloning access credentials, or interacting with networks/devices you do not own or have **explicit written permission** to test is illegal in most jurisdictions (in France: ARCEP regulations and Articles 323-1 et seq. of the Code pénal).

You are solely responsible for how you use this toolkit. Use it on your own hardware, in a controlled lab, or within the scope of an authorized engagement.

---

## Overview

NexusPi turns a Raspberry Pi and a handful of cheap modules into a portable multi-protocol assessment tool. The design philosophy splits the workload:

- **The Pi handles raw capture** — it drives the radios and sensors over USB/SPI/GPIO.
- **A phone or laptop handles the heavy lifting** — FFT, signal decoding, analysis, storage, and the user interface — connecting to the Pi over a Wi-Fi link.

This keeps the device cheap and low-power while delivering analysis performance the Pi alone could not.

```
┌────────────────────────────┐         ┌──────────────────────────┐
│      Raspberry Pi 3B+      │         │      Phone / Laptop      │
│                            │         │                          │
│  RTL-SDR  ── RF capture    │         │  • FFT / DSP             │
│  CC1101   ── sub-GHz TX/RX │ ◄─────► │  • Signal decoding       │
│  PN532    ── NFC / RFID    │  Wi-Fi  │  • Web UI (browser)      │
│  KY-005/22── IR TX/RX      │  WS/API │  • Storage (SSHFS/Samba) │
│  AWUS036  ── Wi-Fi audit   │         │  • Logs & captures       │
└────────────────────────────┘         └──────────────────────────┘
```

---

## Capabilities

| Domain | Hardware | What it does |
|---|---|---|
| **Wide-spectrum RX** | RTL-SDR v5 (RTL2832U) | ADS-B, 433/868 MHz sensors, TPMS, NOAA, spectrum sweep |
| **Sub-GHz TX/RX** | CC1101 | Capture & replay sub-GHz remotes (315/433/868/915 MHz) |
| **NFC / RFID 13.56 MHz** | PN532 | Read/write MIFARE Classic/Ultralight, NFC tags, clone to magic cards |
| **Infrared** | KY-005 + KY-022 (38 kHz) | Capture & replay IR remotes (TV, A/C, etc.) |
| **Wi-Fi audit** | Alfa AWUS036ACH (RTL8812AU) | Monitor mode, handshake/PMKID capture, deauth, evil-twin (lab) |

---

## Hardware

### Bill of Materials

| Component | Model | Interface | Approx. cost |
|---|---|---|---|
| SBC | Raspberry Pi 3B+ | — | ~35 € |
| SDR receiver | Nooelec RTL-SDR v5 | USB | ~58 € |
| Sub-GHz transceiver | CC1101 + SMA antenna | SPI | ~8 € |
| NFC/RFID | PN532 V3 (+ magic cards) | I²C / SPI | ~12 € |
| IR TX/RX | KY-005 + KY-022 kit | GPIO | ~2.30 € |
| Wi-Fi adapter | Alfa AWUS036ACH | USB | (owned) |
| TX amplifier | 2N2222 + resistors | — | <1 € |
| Decoupling | 100 µF + 100 nF caps | — | ~4 € |
| Wiring | Dupont F-F jumpers | — | ~1.50 € |
| Power | Buck converter 5V/3A + battery | — | varies |
| Hub | Powered USB hub | — | ~10 € |

> **USB bus note:** the Pi 3B+ shares one USB 2.0 controller with Ethernet. Run the RTL-SDR and AWUS through a **powered hub** to avoid dropped samples when both are active.

### Wiring

See [`docs/wiring.md`](docs/wiring.md) for the full GPIO pinout of each module.

---

## Software Stack

| Layer | Tooling |
|---|---|
| OS | Kali Linux ARM (or Raspberry Pi OS) |
| Backend | Python + FastAPI (WebSocket for real-time streams) |
| Frontend | Web UI (runs in any browser on phone/PC) |
| SDR | `rtl_sdr`, `rtl_power`, GNU Radio |
| Sub-GHz | SPI driver for CC1101 |
| NFC | `libnfc`, `nfcpy` |
| IR | LIRC (`irrecord`, `irsend`) |
| Wi-Fi | `aircrack-ng`, `bettercap`, `hcxdumptool` |
| Storage | SSHFS / Samba mount to client device |

---

## Repository Structure

```
piflux/
├── README.md
├── LICENSE
├── docs/
│   ├── wiring.md            # GPIO pinouts per module
│   ├── architecture.md      # Pi ↔ client split, data flow
│   ├── setup.md             # OS + dependency install
│   └── threat-model.md      # scope, assumptions, legal boundaries
├── backend/
│   ├── main.py              # FastAPI entrypoint
│   ├── modules/
│   │   ├── sdr.py
│   │   ├── subghz.py        # CC1101
│   │   ├── nfc.py           # PN532
│   │   ├── ir.py            # LIRC wrapper
│   │   └── wifi.py          # AWUS controls
│   └── requirements.txt
├── frontend/                # Web UI served to phone/PC
├── hardware/
│   ├── pinout.md
│   └── enclosure/           # 3D-print files
└── scripts/
    └── install.sh
```

---

## Roadmap

- [x] Define hardware build & BOM
- [ ] Base OS + driver setup
- [ ] Per-module bring-up & individual tests
- [ ] FastAPI backend with WebSocket streaming
- [ ] Web UI (spectrum view, capture browser, module controls)
- [ ] Client-side DSP offload
- [ ] 3D-printed enclosure
- [ ] Documented threat model & lab test scenarios

---

## Author

Built as a hands-on cybersecurity engineering project — RF, hardware integration, and full-stack tooling.

*Documentation and code released under the MIT License.*
