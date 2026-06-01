# RTL-SDR — Wide-Spectrum Receiver

## Role

A software-defined radio **receiver only**. It digitises a slice of the RF spectrum and hands the raw I/Q samples to software for decoding. In NexusPi it is the "ears" of the device: ADS-B aircraft, 433/868 MHz sensors, weather satellites, spectrum surveys.

- **Chipset:** RTL2832U + R820T2 tuner
- **Range:** ~500 kHz – 1.766 GHz
- **Direction:** RX only (no transmit)

## Wiring

USB — just plug it into the Pi (ideally a **powered USB hub**, see [`../wiring.md`](../wiring.md)).

## Kali setup

```bash
sudo apt update
sudo apt install rtl-sdr gqrx-sdr
```

Verify the device is detected:

```bash
rtl_test
```

If you see a "Found Rafael Micro R820T tuner" line, you're good. If `rtl_test` complains the device is in use, blacklist the kernel DVB driver:

```bash
echo 'blacklist dvb_usb_rtl28xxu' | sudo tee /etc/modprobe.d/blacklist-rtl.conf
sudo reboot
```

## Core commands

| Goal | Command |
|---|---|
| Test / sample-rate check | `rtl_test -s 2048000` |
| Raw I/Q capture | `rtl_sdr -f 433920000 -s 2048000 capture.bin` |
| Power scan across a band | `rtl_power -f 400M:450M:1k -i 10 -e 1h scan.csv` |
| FM demod (quick listen) | `rtl_fm -f 100M -M wbfm -s 200k - \| aplay -r 32k -f S16_LE` |
| Live GUI spectrum | `gqrx` |

## Example — survey the 433 MHz band

```bash
# Sweep 433–434 MHz, 1 kHz bins, sample every 5 s
rtl_power -f 433M:434M:1k -i 5 -e 60s -g 40 survey.csv
```

The resulting CSV is a heatmap of activity — exactly the kind of data the client app will plot as a waterfall. In NexusPi the Pi streams the I/Q or power data over WebSocket and the phone/PC renders the spectrum.

## Limits & legal

- **Receive only** — pair with the CC1101 for transmit.
- Passive reception of freely-receivable signals is fine; decoding or relaying protected/private communications is **not**. Keep within the scope defined in [`threat-model.md`](threat-model.md).
