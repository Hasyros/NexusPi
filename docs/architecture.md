# Architecture

NexusPi is a **distributed system**, not a single device. The Raspberry Pi is a capture node; the phone and PC are display-and-compute clients. This document explains how the pieces fit together and why the work is split the way it is.

---

## Design principle: capture vs. compute

The Pi is good at one thing here — talking to hardware (USB, SPI, I²C, GPIO). It is *not* good at heavy signal processing or password cracking. So NexusPi draws a hard line:

- **Capture stays on the Pi.** Driving the radios/sensors and pulling raw data.
- **Compute moves to the clients.** FFT, demodulation, decoding, cracking, and the UI run on the phone (CPU) and the PC (GPU), which are far more capable.

This keeps the handheld cheap and low-power while giving the system analysis performance the Pi alone could never reach.

```
┌──────────────────────────────┐
│        RASPBERRY PI           │   role: CAPTURE NODE
│                              │
│  RTL-SDR  ── raw I/Q          │
│  CC1101   ── sub-GHz frames   │
│  PN532    ── card data        │
│  IR       ── pulse timings    │
│  AWUS     ── 802.11 frames    │
│                              │
│  FastAPI server + WebSocket   │
└───────────────┬──────────────┘
                │  Wi-Fi (Pi hotspot or LAN)
                │  WebSocket (real-time) + REST (control)
       ┌────────┴─────────┐
       │                  │
┌──────▼───────┐   ┌───────▼────────┐
│   PHONE APK   │   │   PC APP        │
│              │   │                │
│ • display     │   │ • display       │
│ • spectra     │   │ • spectra       │
│ • CPU compute │   │ • GPU compute   │
└──────────────┘   └────────────────┘
```

---

## Communication: WebSocket + REST

Two channels, each for what it does best:

| Channel | Use | Why |
|---|---|---|
| **WebSocket** | Live data streams (spectrum, capture feed, status) | Low-latency, bidirectional, push-based |
| **REST** | Control actions (start scan, set frequency, save dump) | Simple request/response, easy to debug |

The Pi runs a FastAPI server exposing both. Clients connect over the Pi's Wi-Fi hotspot (field use) or the local network (lab use).

### Message format

All real-time messages are JSON envelopes with a type tag, so any client can route them:

```json
{
  "module": "sdr",
  "type": "spectrum",
  "ts": 1730462400.123,
  "payload": { "freqs": [...], "power": [...] }
}
```

Control commands follow the same shape in the other direction:

```json
{
  "module": "subghz",
  "type": "command",
  "action": "replay",
  "params": { "capture_id": "garage_01" }
}
```

---

## Distributed compute

The most ambitious part: clients don't just display, they **contribute processing power** back to the system.

### How a heavy job flows

```
1. Pi captures raw data (e.g. a WPA handshake on the user's own AP)
2. Pi packages the job and offers it over WebSocket
3. A client claims the job:
     • PC  → runs it on the GPU (hashcat) — the workhorse
     • Phone → runs a CPU share — supplementary
4. Client streams progress/result back to the Pi
5. Pi aggregates and stores the outcome
```

### Realistic expectations

Being honest about orders of magnitude (a recruiter values this more than hype):

| Client | Strength | Realistic role |
|---|---|---|
| **PC GPU** | Thousands of H/s on modern hashes | Primary cracking engine |
| **Phone CPU** | Orders of magnitude slower | Light/supplementary work, demonstrates the distributed model |

The phone's contribution is more about proving the distributed architecture works than about raw throughput. The PC GPU does the real lifting.

---

## Storage

Captures (card dumps, I/Q recordings, handshakes) can be large. Rather than filling the Pi's SD card, the Pi mounts client storage over the network:

```
Pi  ──(SSHFS / Samba)──►  Client disk
```

The Pi writes captures straight to the PC's disk as if it were a local folder. Sensitive artifacts never leave the user's own devices and are excluded from the repo via `.gitignore`.

---

## Module independence

Every module is usable on its own — each has a standalone guide in [`modules/`](modules/) and a self-contained backend handler in `backend/modules/`. You can run the SDR alone, the NFC reader alone, etc., without bringing up the whole stack. The FastAPI server simply exposes whichever modules are present.

This mirrors the project philosophy: a toolkit of independent capabilities, unified by a common client interface — not a monolith.

---

## Data flow summary

```
HARDWARE → Pi backend module → FastAPI → WebSocket/REST → client
                                                        ↓
                                          display  +  compute  +  storage
                                                        ↓
                                         result ───────► back to Pi
```

---

## Why this design holds up

- **Cheap & portable:** the Pi stays minimal; clients supply the muscle.
- **Scalable:** add a client, add compute. The job-offer model doesn't care how many clients connect.
- **Debuggable:** REST for control means every action is a plain HTTP call you can test with `curl`.
- **Modular:** independent modules, independently documented and runnable.
