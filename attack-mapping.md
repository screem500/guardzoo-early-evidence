# GuardZoo — MITRE ATT&CK (Mobile) Mapping

Mapping of GuardZoo behaviors to MITRE ATT&CK for Mobile techniques. IDs verified against ATT&CK Mobile (v9+); always confirm against https://attack.mitre.org/matrices/mobile/ for the current version.

**Evidence key:**
- **[Field]** — directly evidenced in this repository (2022 field observation, indicators, verified sample behavior)
- **[Public]** — from public reporting on GuardZoo and its Dendroid lineage (Lookout Threat Lab, Jul 2024)

| Tactic | Technique | Name | GuardZoo behavior | Evidence |
|--------|-----------|------|-------------------|----------|
| Initial Access | T1444 | Masquerade as Legitimate Application | Trojanized "Alpin Quest Pro2022" APK posing as a paid update of the AlpineQuest mapping app | [Field] |
| Initial Access | T1476 | Deliver Malicious App via Other Means | APK delivered via WhatsApp Business / Telegram link (MediaFire), outside any official app store | [Field] |
| Defense Evasion | T1407 | Download New Code at Runtime | DEX update mechanism: `/updateApp?dexfile=classes.dex` | [Field] |
| Discovery | T1420 | File and Directory Discovery | Searches device storage for map/GPS files (KMZ, WPT, RTE, TRK) — the campaign's primary collection objective | [Public] |
| Discovery | T1426 | System Information Discovery | Registration request carries `Device`, `Sdk`, `Provider`, `Phone_Number` parameters | [Field] |
| Collection | T1430 | Location Tracking | `Coordinates` parameter in `/get` C2 request; GPS data is a core objective | [Field] |
| Collection | T1533 | Data from Local System | Exfiltration of map/GPS files and other files from device storage | [Public] |
| Collection | T1412 | Capture SMS Messages | SMS collection (Dendroid-derived capability) | [Public] |
| Collection | T1429 | Capture Audio | Microphone recording (Dendroid-derived capability) | [Public] |
| Collection | T1512 | Capture Camera | Photo capture (Dendroid-derived capability) | [Public] |
| Collection | T1432 | Access Contact List | Contact list collection (Dendroid-derived capability) | [Public] |
| Collection | T1433 | Access Call Log | Call log collection (Dendroid-derived capability) | [Public] |
| Command and Control | T1437.001 | Application Layer Protocol: Web Protocols | HTTP(S) C2 with `UID`/`Password` parameters (`/getfunctions`, `/get`, `/message`); ASP.NET backend on IIS; self-signed TLS certificate | [Field] |
| Exfiltration | T1646 | Exfiltration Over C2 Channel | Collected data exfiltrated to C2 over HTTP(S) | [Public] |

## Usage

- Feed this mapping into your detection content: the Sigma rules in `detection/` already tag `attack.command_and_control` / `attack.t1071.001`.
- Rows marked [Public] describe family-level capabilities; validate against a specific sample before asserting them in an incident report.
