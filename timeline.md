# GuardZoo Campaign — Timeline

Chronology of the GuardZoo Android surveillanceware campaign, combining public reporting with the field evidence preserved in this repository.

| Date | Event | Source |
|------|-------|--------|
| ~Oct 2019 | GuardZoo campaign assessed to have become active. Android surveillanceware built on the leaked Dendroid RAT, using a custom ASP.NET C2 backend on IIS. | Lookout Threat Lab, Jul 2024 |
| 2022 | **Field observation (this repo):** a trojanized "Alpin Quest Pro2022" APK — a fake paid update of the AlpineQuest topographic mapping app — delivered over WhatsApp Business and Telegram from a Yemeni number (+967), hosted on MediaFire. Military/mapping lure matching the actor's objective of collecting KMZ/WPT/RTE/TRK map files. | This repository (field evidence, predates public naming) |
| 2022 | A targeted individual requests help; delivery confirmed hostile; technical and reporting measures result in the attacker's WhatsApp and Telegram accounts being taken down and the legitimate accounts restored to their owner. | This repository (field evidence) |
| 9 Jul 2024 | Lookout publicly discloses the campaign as **GuardZoo**, attributes it to a Yemeni, Houthi-aligned threat actor, and publishes C2 infrastructure (`wwwgoogl.zapto.org` primary, `somrasdc.ddns.net` backup) and sample hashes. | Lookout Threat Lab |
| Jul 2024 | Indicators independently confirmed live: published sample contacts `somrasdc.ddns.net` with UID/Password request structure and YemenNet IPs `134.35.5.242` / `134.35.9.243`. | This repository (VirusTotal verification) |
| 2025 | Doctor Web reports a **separate** campaign also using a trojanized AlpineQuest app, targeting Russian military personnel via Telegram — **not** attributed to the Houthis and not GuardZoo. | Doctor Web |
| 26 Jun 2026 | `guardzoo-early-evidence` repository published: machine-readable indicators, sample hashes, YARA and Sigma detection rules. | This repository |
| 22 Jul 2026 | Phase 2 enrichment: STIX 2.1 / MISP exports, MITRE ATT&CK (Mobile) mapping, campaign timeline, license. | This repository |

## Notes

- The 2022 field evidence predates the public naming of the campaign by roughly two years.
- Attribution to a Houthi-aligned actor is as reported by Lookout; the material here is corroborating evidence, not independent attribution to a named individual.
- For defensive and research purposes only.
