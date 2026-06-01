# Infrared — KY-022 (RX) + KY-005 (TX)

## Role

Capture and replay infrared remote-control signals — TVs, air conditioners, hi-fi, projectors. The receiver records a remote's signal; the transmitter re-emits it. The NexusPi equivalent of the Flipper's IR feature.

- **Receiver:** KY-022 (VS1838, 38 kHz demodulator)
- **Transmitter:** KY-005 (940 nm IR LED)
- **Interface:** GPIO (via LIRC)

## Wiring

GPIO — see [`../wiring.md`](../wiring.md). Summary: RX OUT→GPIO18 (Pin 12); TX DAT→GPIO17 (Pin 11). Optional 2N2222 amplifier on the TX LED for longer range.

## Kali setup

LIRC is the standard Linux IR stack. Install it and enable the GPIO IR overlays:

```bash
sudo apt install lirc
```

Add to `/boot/config.txt` (Raspberry Pi OS) — adjust pins to match the wiring:

```
dtoverlay=gpio-ir,gpio_pin=18
dtoverlay=gpio-ir-tx,gpio_pin=17
```

Reboot, then check the IR devices exist:

```bash
ls /dev/lirc*           # expect /dev/lirc0 (rx) and /dev/lirc1 (tx)
```

## Core commands

| Goal | Command |
|---|---|
| Record a remote into a config | `irrecord -d /dev/lirc0 myremote.lircd.conf` |
| Test raw reception | `mode2 -d /dev/lirc0` |
| List known remotes | `irsend LIST "" ""` |
| List a remote's buttons | `irsend LIST myremote ""` |
| Send a command | `irsend SEND_ONCE myremote KEY_POWER` |

## Example — capture and replay a TV power button

```bash
# 1. Record — follow the prompts, press buttons when asked
irrecord -d /dev/lirc0 tv.lircd.conf

# 2. Install the config
sudo cp tv.lircd.conf /etc/lirc/lircd.conf.d/

# 3. Replay
irsend SEND_ONCE tv KEY_POWER
```

The NexusPi backend (`backend/modules/ir.py`) wraps `irrecord`/`irsend` so captures and replays can be driven from the client app.

## Limits & legal

- IR is short-range and line-of-sight; the KY-005 straight from GPIO reaches ~1–2 m (add the transistor amp for more).
- The VS1838 receiver is tuned for 38 kHz, covering the large majority of consumer remotes; a few devices use 36/40 kHz and may be hit-or-miss.
- Use only on appliances you own. IR is low-risk, but the ownership rule from [`threat-model.md`](threat-model.md) still applies.
