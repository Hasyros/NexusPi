# Threat Model & Scope of Use

This document defines the intended use, operating scope, and ethical/legal boundaries of **NexusPi**. It exists to make the project's purpose unambiguous: NexusPi is a learning and self-assessment platform, not an attack tool aimed at third parties.

Defining scope explicitly is itself a security practice — it forces clarity about what the tool is *allowed* to touch, what it is *not*, and what assumptions the design rests on.

---

## 1. Purpose

NexusPi is built for three legitimate purposes:

1. **Hands-on learning** — understanding how RF, sub-GHz, NFC/RFID, IR, and Wi-Fi protocols work at a practical level.
2. **Self-assessment** — testing the security posture of equipment the author owns (home network, personal access cards, personal remotes).
3. **Portfolio demonstration** — showcasing hardware integration, full-stack tooling, and security engineering skills.

NexusPi is **not** intended to be used against any system, network, device, or credential that the operator does not own or lack explicit written authorization to test.

---

## 2. Authorized Scope

The tool is designed to be exercised **only** within the following boundaries:

| Domain | In scope | Out of scope |
|---|---|---|
| Wi-Fi | The author's own access points and client devices, in an isolated lab | Any third-party or public network |
| Sub-GHz | The author's own remotes, sensors, and test transmitters | Vehicle key fobs, neighbours' devices, public infrastructure |
| NFC/RFID | The author's own cards, tags, and blank "magic" cards | Bank cards, transit passes, third-party badges |
| IR | The author's own appliances | Any device the author does not own |
| SDR | Passive reception of freely receivable signals | Decoding/relaying protected or private communications |

A practical rule of thumb governs every module: **if the author does not physically own the target, it is out of scope.**

---

## 3. Legal Context

This project is developed in France and is bound by, among others:

- **ARCEP regulations** governing radio-frequency emission. Transmitting on regulated bands without authorization is prohibited; emission testing is restricted to license-free ISM bands within power limits, or to a shielded/controlled environment.
- **Articles 323-1 et seq. of the French Code pénal** (unauthorized access to and interference with automated data systems).
- **GDPR** where any captured data could contain personal information.

The operator is solely responsible for compliance with all applicable laws in their jurisdiction. International readers should note that equivalent legislation exists in most countries (e.g. the Computer Fraud and Abuse Act in the US, the Computer Misuse Act in the UK).

---

## 4. Operating Assumptions

The design assumes:

- The operator has full ownership of, or written authorization for, every target.
- Wi-Fi and sub-GHz emission testing is performed in an isolated environment (lab, Faraday-shielded space, or against dedicated test hardware).
- Captured data (handshakes, card dumps, signal recordings) is stored locally on the operator's own devices and never redistributed.
- The device is single-operator and physically controlled by its owner.

If any of these assumptions does not hold, the tool is being used outside its intended threat model.

---

## 5. Risks Acknowledged

This section documents risks the author is aware of — both risks the tool could create if misused, and risks to the operator.

**Misuse potential.** The same capabilities that make NexusPi useful for self-assessment (capture/replay, cloning, monitor mode) could cause harm if pointed at third parties. This is mitigated by scope discipline, not by technical restriction — the operator's ethics are the primary control.

**Data sensitivity.** Card dumps and captured handshakes are sensitive artifacts. They are kept off any public repository (see `.gitignore`) and stored only on the operator's encrypted storage.

**Legal exposure.** Even "just testing" can cross legal lines if performed against the wrong target or band. When in doubt, the operator defaults to *not* transmitting.

---

## 6. Explicit Non-Goals

NexusPi will **not** be developed to:

- Bypass or defeat security controls on devices the operator does not own.
- Capture, store, or process other people's personal data.
- Operate covertly against third parties.
- Ship with or distribute captured credentials, dumps, or recordings.

---

## 7. Responsible Disclosure

If, during legitimate self-assessment, this project surfaces a vulnerability in a commercial product, the author commits to responsible disclosure to the affected vendor rather than public release of exploit details.

---

*This threat model is a living document and will evolve alongside the project's capabilities.*
