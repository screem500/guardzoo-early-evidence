#!/usr/bin/env python3
"""
generate_exports.py - GuardZoo early-evidence machine-readable export generator.

Regenerates the STIX 2.1 bundle (stix/guardzoo_iocs.json) and the MISP event
(misp/guardzoo_event.json) from the indicators documented in this repository.

IDs are deterministic (UUIDv5), so re-running produces identical files.

Usage:
    python3 generate_exports.py        # writes stix/ and misp/ next to this script

For defensive and research purposes only. License: CC BY 4.0
"""
import json
import os
import uuid

NS = uuid.UUID("7c9e6679-7425-40de-944b-e07fc1f90ae7")  # project namespace
NOW = "2026-07-22T00:00:00.000Z"
TLP_CLEAR = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"

SHA256_HASHES = """d34cd64dea64f1e29534f10c7fe3d504d5d7d825c441fd2fb3b81c2cb56c5971\nbb09cf4023bca6fe8e854626641df398a3ce484236c650d790af83b5990b5408\n3113eed5c125b4c753f6797e50db3320c907eb80c03a9028286ad1bc1c86fe32\n54b126aee7055a5160d118b7b9432cac2c75d91df3b7a9d47edb0068191ed8ed\n1a049acb067200157a338398a71ffe1982dd4bfac22973e57dfca73e4d4123e7\n7cee417674994a0c1c387d2b3b4af334304a8993e55fc2f688132c1b6860ac6e\n81538715609924902a292c7c514a2785b319c10153b3ac9aad4961c236e3f3f8\ne3745acfe7b016fe1782bca43c48e7a3a0f3b948d901ce600192e688aa13e9a5\n499e04f1ac1380a401f9b38de6cd4a137682fd1ce3557f59ed04cbdf5610b86c\n1620663c128aa210cea5a8e4f06ecdbedb7b4d4d15c7518771203485cf201808\n7537132ec47e75ab54c0acb327ae2c4a26dc4ef9c2f62fff2e4d610e998a6abd\n0fbbf5bca438574f5592ac1f548d5d460ddccb4ad6225087a770b47fb717c427\n7896090321f7e45882362aaf99b074f74d571ad8147c9f67de453bf2fde4ee60\n7ab1ddc92532d11b6d292e013f88e862dbf24f182c3cdbe836528e3a559096cc\na78251a90a67c766e187fb8978bbd58e981fd635e46935a23ad9ecd86695763a\n5daac5f8928f6b51a3a6c7dbc18da3d45ca7ae01462d6b405cc2d8aba9ff3a31\nd6389c46229e036547cec2f05e122b88f08ac1fb61703ee4e7c59544a72ef605\nf87ef459de739b61a3385f3f5d406d830a77b62aae63db147c0a0fb95b8700cd\nccb0c0019be923da82131df1e78897a5cd0d6b88e6d3953f46a70c9d43282af4\n09ef4ce410a10a5e412c05c9885a1d59192a318e42cb36a2ea6081c26de3126e\n893e083bc3cf54b64fa25d2b25443315c832f0e51de788ad79ad8f5f356540d9""".split()

NET_INDICATORS = [
    ("GuardZoo C2 domain (primary): wwwgoogl.zapto.org", "[domain-name:value = 'wwwgoogl.zapto.org']", "Primary GuardZoo command-and-control domain (Lookout 2024-07-09)."),
    ("GuardZoo C2 domain (backup): somrasdc.ddns.net", "[domain-name:value = 'somrasdc.ddns.net']", "Backup GuardZoo C2 domain; confirmed live contacting YemenNet IPs on VirusTotal sample behavior."),
    ("GuardZoo C2 IP (YemenNet): 134.35.5.242", "[ipv4-addr:value = '134.35.5.242']", "YemenNet IP contacted by published GuardZoo sample."),
    ("GuardZoo C2 IP (YemenNet): 134.35.9.243", "[ipv4-addr:value = '134.35.9.243']", "YemenNet IP contacted by published GuardZoo sample."),
    ("GuardZoo C2 self-signed TLS certificate (SHA-1)", "[x509-certificate:hashes.'SHA-1' = '51a35108b7a2c8d4a199d5c872927ee13d66b4a8']", "Self-signed TLS certificate fingerprint used by GuardZoo C2."),
    ("GuardZoo C2 request: function poll", "[url:value LIKE '%/getfunctions?UID=%']", "C2 polling request carrying UID (victim id) and Password (auth) parameters."),
    ("GuardZoo C2 request: victim registration / check-in", "[url:value LIKE '%/get?UID=%']", "Check-in request carrying UID, Provider, Phone_Number, Coordinates, Device, Sdk, Password."),
    ("GuardZoo C2 request: status message", "[url:value LIKE '%/message?UID=%']", "Status reporting request (Data=timestamp-status)."),
    ("GuardZoo DEX update URI", "[url:value LIKE '%/updateApp?dexfile=classes.dex%']", "Download-new-code-at-runtime update mechanism (ATT&CK Mobile T1407)."),
    ("GuardZoo delivery artifact (2022 lure)", "[url:value = 'https://www.mediafire.com/file/91cnzdjccttssmz/Alpin+Quest+Pro2022.apk/file']", "Trojanized AlpineQuest lure delivered over WhatsApp Business/Telegram from a Yemeni number, 2022 field observation."),
]


def sid5(obj_type, key):
    return f"{obj_type}--{uuid.uuid5(NS, obj_type + '|' + key)}"


def build_stix():
    identity = {"type": "identity", "spec_version": "2.1", "id": sid5("identity", "Screem500"),
        "created": NOW, "modified": NOW, "name": "Screem500", "identity_class": "individual",
        "description": "Independent security researcher; field evidence collector for the guardzoo-early-evidence repository.",
        "object_marking_refs": [TLP_CLEAR]}
    malware = {"type": "malware", "spec_version": "2.1", "id": sid5("malware", "GuardZoo"),
        "created": NOW, "modified": NOW, "is_family": True, "name": "GuardZoo",
        "aliases": ["trojan.dingwe (VirusTotal popular label)", "Dendroid-derived Android RAT"],
        "malware_types": ["spyware", "remote-access-trojan"],
        "description": "Android surveillanceware targeting military personnel in the Middle East; based on the leaked Dendroid RAT with a custom ASP.NET C2 backend on IIS. Primary collection objective: GPS and map files (KMZ, WPT, RTE, TRK). Publicly disclosed by Lookout (2024-07-09); field evidence in the guardzoo-early-evidence repository dates to 2022.",
        "object_marking_refs": [TLP_CLEAR]}
    intrusion_set = {"type": "intrusion-set", "spec_version": "2.1", "id": sid5("intrusion-set", "GuardZoo actor"),
        "created": NOW, "modified": NOW,
        "name": "GuardZoo threat actor (Houthi-aligned, as reported by Lookout)",
        "description": "Yemeni, Houthi-aligned threat actor attributed to the GuardZoo campaign by Lookout Threat Lab (July 2024). Included here as public-reporting attribution, not independent attribution by this repository.",
        "object_marking_refs": [TLP_CLEAR]}

    objects = [identity, malware, intrusion_set]
    indicator_ids = []

    def add_indicator(name, pattern, description=""):
        ind = {"type": "indicator", "spec_version": "2.1", "id": sid5("indicator", pattern),
            "created": NOW, "modified": NOW, "name": name, "description": description,
            "pattern": pattern, "pattern_type": "stix", "valid_from": NOW,
            "indicator_types": ["malicious-activity"], "object_marking_refs": [TLP_CLEAR]}
        objects.append(ind)
        indicator_ids.append(ind["id"])

    for name, pattern, desc in NET_INDICATORS:
        add_indicator(name, pattern, desc)
    for h in SHA256_HASHES:
        add_indicator(f"GuardZoo sample (SHA-256) {h[:12]}...", f"[file:hashes.'SHA-256' = '{h}']",
                      "Published GuardZoo sample hash (Lookout 2024-07-09), cross-referenced in guardzoo-early-evidence.")
    for iid in indicator_ids:
        objects.append({"type": "relationship", "spec_version": "2.1", "id": sid5("relationship", iid + "->" + malware["id"]),
            "created": NOW, "modified": NOW, "relationship_type": "indicates",
            "source_ref": iid, "target_ref": malware["id"], "object_marking_refs": [TLP_CLEAR]})
    objects.append({"type": "relationship", "spec_version": "2.1", "id": sid5("relationship", intrusion_set["id"] + "-uses-" + malware["id"]),
        "created": NOW, "modified": NOW, "relationship_type": "uses",
        "source_ref": intrusion_set["id"], "target_ref": malware["id"], "object_marking_refs": [TLP_CLEAR]})

    return {"type": "bundle", "id": sid5("bundle", "guardzoo-early-evidence"), "objects": objects}


def build_misp():
    def attr(category, type_, value, comment="", to_ids=True):
        a = {"category": category, "type": type_, "value": value, "to_ids": to_ids}
        if comment:
            a["comment"] = comment
        return a

    attributes = [
        attr("Network activity", "domain", "wwwgoogl.zapto.org", "GuardZoo primary C2 (Lookout 2024-07-09)"),
        attr("Network activity", "domain", "somrasdc.ddns.net", "GuardZoo backup C2; confirmed live on VirusTotal sample behavior"),
        attr("Network activity", "ip-dst", "134.35.5.242", "YemenNet IP contacted by published GuardZoo sample"),
        attr("Network activity", "ip-dst", "134.35.9.243", "YemenNet IP contacted by published GuardZoo sample"),
        attr("Network activity", "x509-fingerprint-sha1", "51a35108b7a2c8d4a199d5c872927ee13d66b4a8", "Self-signed TLS certificate on GuardZoo C2"),
        attr("Network activity", "uri", "/getfunctions", "C2 poll: ?UID=...&Password=..."),
        attr("Network activity", "uri", "/get", "Check-in: ?UID=...&Provider=...&Phone_Number=...&Coordinates=...&Device=...&Sdk=...&Password=..."),
        attr("Network activity", "uri", "/message", "Status report: ?UID=...&Password=...&Data=timestamp-status"),
        attr("Network activity", "uri", "/updateApp?dexfile=classes.dex", "DEX update mechanism (ATT&CK Mobile T1407)"),
        attr("Payload delivery", "link", "https://www.mediafire.com/file/91cnzdjccttssmz/Alpin+Quest+Pro2022.apk/file",
             "2022 delivery artifact: trojanized AlpineQuest lure via WhatsApp Business/Telegram (Yemeni number +967)", to_ids=False),
        attr("Other", "text", "+967 73x xxx xxx",
             "Attacker persona on WhatsApp Business (Yemen); number partially redacted, country code retained for attribution", to_ids=False),
    ]
    for h in SHA256_HASHES:
        attributes.append(attr("Payload delivery", "sha256", h, "Published GuardZoo sample (Lookout 2024-07-09)"))

    return {"Event": {
        "uuid": str(uuid.uuid5(NS, "misp-event|guardzoo-early-evidence")),
        "info": "GuardZoo Android surveillanceware - early field evidence and IOCs (Houthi-aligned campaign, Yemen)",
        "threat_level_id": "2", "analysis": "2", "date": "2026-07-22",
        "distribution": "3", "published": True,
        "Orgc": {"name": "Screem500", "uuid": str(uuid.uuid5(NS, "misp-orgc|Screem500"))},
        "Tag": [{"name": "tlp:clear"}, {"name": "misp:tool=\"guardzoo\""},
                {"name": "android"}, {"name": "surveillanceware"}, {"name": "yemen"}],
        "Attribute": attributes, "Object": [], "Galaxy": []}}


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(os.path.join(here, "stix"), exist_ok=True)
    os.makedirs(os.path.join(here, "misp"), exist_ok=True)
    stix_path = os.path.join(here, "stix", "guardzoo_iocs.json")
    misp_path = os.path.join(here, "misp", "guardzoo_event.json")
    with open(stix_path, "w") as f:
        json.dump(build_stix(), f, indent=2, ensure_ascii=False)
    with open(misp_path, "w") as f:
        json.dump(build_misp(), f, indent=2, ensure_ascii=False)
    print(f"[+] Wrote {stix_path}")
    print(f"[+] Wrote {misp_path}")


if __name__ == "__main__":
    main()
