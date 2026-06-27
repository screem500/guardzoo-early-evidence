# GuardZoo Early Evidence

Field evidence and indicators for the GuardZoo Android surveillanceware campaign (Houthi-aligned, Yemen), documented in 2022 and cross-referenced with the indicators later published by Lookout in July 2024.

For defensive and research purposes only.

## Background

GuardZoo is Android surveillanceware that targets military personnel in the Middle East. It was publicly disclosed by Lookout on 9 July 2024 and attributed to a Yemeni, Houthi-aligned threat actor. The campaign has been active since around October 2019. The malware is based on the leaked Dendroid RAT and uses a custom ASP.NET command-and-control backend served on IIS. It is delivered through WhatsApp, WhatsApp Business, Telegram, and direct browser download, mainly using military and mapping-app lures, and its primary collection objective is GPS and map files (KMZ, WPT, RTE, TRK).

## Field observation (2022)

In 2022, while tracking threats aimed at individuals in the region, I encountered an Android malware operation spreading over messaging apps. What stood out was the lure: a fake topographic mapping and navigation app, framed with military reconnaissance language, delivered as an APK from outside any official app store. That delivery pattern does not match a legitimate app update, so I tracked the sending account and the file and preserved the messages and distribution details. This predated any public naming of the campaign, which Lookout later disclosed in 2024 as GuardZoo.

### Delivery sample (2022)

A trojanized lure was delivered from a Yemeni number over both WhatsApp Business and Telegram, disguised as a paid 2022 update of the AlpineQuest topographic mapping app ("Alpin Quest Pro2022"), hosted as an APK on MediaFire. This matches the GuardZoo pattern precisely: a fake GPS/mapping app is the ideal lure to reach victims who already hold the KMZ/WPT/RTE/TRK files the actor seeks.

![Trojanized AlpineQuest lure delivered over WhatsApp Business and Telegram](alpinequest-delivery.png)

Note: the original APK is no longer retained. The published samples and the live confirmation below cover the family and the infrastructure.

### Direct response

A targeted individual, kept anonymous here for their protection, reached out to me for help. I reviewed the messages and the malicious APK, confirmed the delivery was hostile, and took technical and reporting measures against the operator.

As a result, the attacker's accounts were removed from both WhatsApp and Telegram, and the legitimate accounts were successfully restored to their owner. The priority throughout was protecting the targeted person and documenting the activity without exposing them.

## Analysis and confirmation

The published indicators were checked independently on VirusTotal, and the sample's own behavior confirms them.

Detection: the sample is flagged as Android spyware by a broad majority of engines, with a popular threat label of trojan.dingwe, another name for the Dendroid lineage that GuardZoo is built on.

![VirusTotal detection: trojan.dingwe / Android spyware](virustotal-detection.png)

Behavior: the sample contacts somrasdc.ddns.net (the published backup C2) using requests that carry UID (victim identifier) and Password (authentication) parameters, exactly as described by Lookout. It also contacts YemenNet IP addresses 134.35.5.242 and 134.35.9.243, and bundles assets/sample.pdf alongside a flagged classes.dex, indicating a PDF-document lure for this particular sample.

![VirusTotal relations: live C2 contact and YemenNet IPs](virustotal-relations.png)

Together this shows that the published indicators and the C2 protocol are real and live, and places the 2022 field observation inside a verified campaign. This is corroborating evidence; it is not, on its own, a forensic link to a specific named individual.

## Indicators

Machine-readable indicators are in this repository:

- indicators.txt: C2 domains, resolved YemenNet IPs, TLS certificate fingerprint, C2 request structure, and the delivery artifact
- sha256.txt: published sample hashes

The attacker phone number is partially redacted; the country code is retained for attribution.

## Not to be confused with a separate 2025 campaign

A different 2025 campaign reported by Doctor Web also used a trojanized AlpineQuest app, but it targeted Russian military personnel, was distributed via Telegram, and is not attributed to the Houthis. The evidence here concerns GuardZoo, not that campaign.

## Sources

- Lookout Threat Lab, GuardZoo report, 9 July 2024: https://www.lookout.com/threat-intelligence/article/guardzoo-houthi-android-surveillanceware
- Sample behavior independently confirmed on VirusTotal.

## Credit

Field evidence and analysis: Screem500

## ملخص بالعربية

توثيق لأدلة ميدانية على حملة GuardZoo ، وهي برمجية تجسس أندرويد محسوبة على الحوثيين تستهدف عسكريين في المنطقة. رُصدت الأدلة في 2022، أي قبل الكشف العلني الذي نشرته   Lookout في يوليو 2024 بسنتين. تشمل الأدلة توصيل نسخة مفخخة من تطبيق الخرائط AlpineQuest عبر واتساب بزنس وتيليجرام من رقم يمني. تواصل معي الشخص المستهدف (يبقى مجهول لحمايته) طلباً للمساعدة، واتُّخذت إجراءات تقنية أدّت إلى إزالة حسابات المهاجم من واتساب وتيليجرام، وإعادة الحسابات لأصحابها الشرعيين بنجاح. وتأكدت المؤشرات حيّاً عبر VirusTotal، حيث تتصل العيّنة بنطاق الـ C2 المنشور somrasdc.ddns.net بمعاملات UID وPassword، وبعناوين YemenNet.
هذا التوثيق دفاعي وبحثي، وأدلة تتقاطع مع مؤشرات منشورة ومؤكّدة، وليست إسناداً قاطعاً لشخص بعينه.
