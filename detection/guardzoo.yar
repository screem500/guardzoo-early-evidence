rule GuardZoo_Android_Surveillanceware
{
    meta:
        description = "Heuristic detection for GuardZoo Android surveillanceware, based on publicly documented indicators. Best run against the decompressed classes.dex or unpacked APK."
        author = "Screem500"
        reference = "Lookout Threat Lab GuardZoo report, 2024-07-09"
        date = "2026-06-28"
        malware_family = "GuardZoo"
        tlp = "CLEAR"

    strings:
        $cls1 = "GuardZoo" ascii wide nocase
        $cls2 = "AnimalCoop" ascii wide nocase
        $cls3 = "MainZoo" ascii wide nocase
        $c2a  = "wwwgoogl.zapto.org" ascii wide nocase
        $c2b  = "somrasdc.ddns.net" ascii wide nocase
        $dex  = "updateApp?dexfile=classes.dex" ascii wide nocase

    condition:
        2 of ($cls*) or any of ($c2a, $c2b) or $dex
}
