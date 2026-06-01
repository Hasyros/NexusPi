# Wi-Fi — Alfa AWUS036ACH

## Role

A USB Wi-Fi adapter that supports **monitor mode and packet injection** — the prerequisites for Wi-Fi security assessment. In NexusPi it handles network surveying, handshake/PMKID capture, and lab-only resilience testing of networks you own.

- **Chipset:** Realtek RTL8812AU (dual-band 2.4/5 GHz)
- **Interface:** USB
- **Key feature:** monitor + injection

> **Scope reminder up front:** every command below is intended for **your own networks** or an explicitly authorized engagement, in an isolated lab. See [`threat-model.md`](threat-model.md). Wi-Fi attacks against networks you don't own are illegal (in France, Art. 323-1 et seq. Code pénal).

## Wiring

USB — plug into a **powered hub** alongside the RTL-SDR (the Pi 3B+ shares one USB controller; see [`../wiring.md`](../wiring.md)).

## Kali setup

The RTL8812AU driver isn't always in-kernel. Install the DKMS package:

```bash
sudo apt update
sudo apt install realtek-rtl88xxau-dkms
```

Confirm the adapter and driver:

```bash
lsusb                   # look for "Realtek ... RTL8812AU"
iw dev                  # your interface, e.g. wlan1
lsmod | grep 8812
```

## Core commands

| Goal | Tool / command |
|---|---|
| Kill interfering processes | `sudo airmon-ng check kill` |
| Enable monitor mode | `sudo airmon-ng start wlan1` |
| Survey nearby networks | `sudo airodump-ng wlan1mon` |
| Focus-capture one AP | `sudo airodump-ng -c <ch> --bssid <bssid> -w cap wlan1mon` |
| Clientless PMKID capture | `sudo hcxdumptool -i wlan1mon -o cap.pcapng` |
| Interactive recon/MITM (lab) | `sudo bettercap -iface wlan1mon` |
| Back to managed mode | `sudo airmon-ng stop wlan1mon` |

## Example — audit the strength of your own Wi-Fi password

This is the legitimate use case: prove to yourself that your home AP's passphrase is (or isn't) strong.

```bash
# 1. Monitor mode
sudo airmon-ng check kill
sudo airmon-ng start wlan1

# 2. Capture the handshake from YOUR access point
sudo airodump-ng -c 6 --bssid <YOUR_AP_BSSID> -w home wlan1mon

# 3. Convert and crack offline (GPU recommended — this is where the
#    NexusPi "distributed compute" / client PC GPU comes in)
hcxpcapngtool -o home.hash home-01.cap
hashcat -m 22000 home.hash wordlist.txt
```

If your own passphrase falls quickly to a wordlist, that's your signal to change it. The cracking step is intentionally offloaded to the client PC's GPU in the NexusPi architecture — the Pi captures, the GPU does the heavy lifting.

## Limits & legal

- Monitor mode and injection depend entirely on the RTL8812AU driver being correctly loaded — most setup issues trace back to the driver.
- **Only** test networks you own or are authorized in writing to assess. Capturing third-party traffic or cracking others' passphrases is a criminal offence.
- Treat captured handshakes as sensitive: keep them off the public repo (`.gitignore`) and on encrypted storage.
