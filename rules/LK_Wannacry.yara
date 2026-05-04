rule WannaCry_LKBEatrice {
     meta: 
        description = "Detections for WannaCry using Beatrice.py, modifying Elastic YARA rule and DefenderCheck output" 
        author = "LainKusanagi Beatrice.py" 
        date = "2026-05-03"
    strings:
        $a1 = "@WanaDecryptor@.exe" wide fullword
        $a2 = ".WNCRY" wide fullword
        $a3 = "$%d worth of bitcoin" fullword
        $a4 = "%d%d.bat" fullword
        $a5 = "This folder protects against ransomware. Modifying it will reduce protection" wide fullword
        $a6 = "AVtype_info" fullword
        $b1 = { 53 55 56 57 FF 15 D0 70 00 10 8B E8 A1 8C DD 00 10 85 C0 75 6A 68 B8 0B 00 00 FF 15 70 70 00 10 }
        $b2 = { A1 90 DD 00 10 53 56 57 85 C0 75 3E 8B 1D 60 71 00 10 8B 3D 70 70 00 10 6A 00 FF D3 83 C4 04 A3 }
        $b3 = { 56 8B 74 24 08 57 8B 3D 70 70 00 10 56 E8 2E FF FF FF 83 C4 04 A3 8C DD 00 10 85 C0 75 09 68 88 }
        $c1 = { 08 ef bf bd 01 03 04 ?? ?? ?? ?? ?? 4c 36 4d 57 }
        $c2 = { 08 ef bf bd 01 03 04 ?? ?? ?? ?? ?? bf bd 01 03 }
        $c3 = { 06 07 08 ef bf bd 01 03 04 ?? ?? ?? ?? ?? bf bd }
        $c4 = { 01 03 04 ?? ?? ?? ?? ?? bf bd 01 03 04 05 06 07 }
        $c5 = { bf bd 01 03 04 ?? ?? ?? ?? ?? bf bd 01 03 04 05 }

    condition:
        4 of ($a*) or 1 of ($b*) or 3 of ($c*)
}
