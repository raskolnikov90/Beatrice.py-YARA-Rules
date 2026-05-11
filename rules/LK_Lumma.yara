rule Lumma_LKBEatrice {
     meta: 
        description = "Detections for Lumma using Beatrice.py, modifying Elastic rule and dubfib fule" 
        author = "LainKusanagi Beatrice.py" 
        date = "2026-05-10"

    strings:
        $r1_a1 = { 02 0F B7 16 83 C6 02 66 85 D2 75 EF 66 C7 00 00 00 0F B7 11 }
        $r1_a2 = { 0C 0F B7 4C 24 04 66 89 0F 83 C7 02 39 F7 73 0C 01 C3 39 EB }
        
        $r2_a = { 8B 4C 24 04 8B 14 24 31 CA F7 D2 21 CA 29 D0 }
        $r2_b = { 89 F1 C1 E9 0C 80 C9 E0 88 08 89 F1 C1 E9 06 80 E1 3F 80 C9 80 88 48 01 80 E2 3F }
        $r2_c = { 55 53 57 56 81 ?? ?? ?? ?? ?? ?? ?? ?? 03 00 }

        $r3_a = { 55 89 E5 83 E4 F8 83 EC 10 DD 45 08 DD 54 24 08 8B 4C 24 0C 89 CA C1 EA 14 81 E2 FF 07 00 00 81 FA FF 07 00 00 74 25 66 B8 FF FF 85 D2 75 31 DD 1C 24 B8 FF FF FF 7F 23 44 24 04 31 C9 0B 04 24 }

        $r4_crypto_setup = { B8 38 ?2 4? 00 B? [3] 00 B? [3] 00 96 F3 A5 }
        $r4_decryption_func = { 55 53 57 56 81 EC 1? 01 00 00 8B ?? 24 3? 01 00 00 85 ?? 0F 84 ?? 08 00 00 }
        $r4_c2_branch = { 8D 8? E0 ?2 4? 00 8D 74 24 ?? FF 3? 56 5? 68 ?? ?? 45 00 E8 ?? ?? FF FF }
    condition:
        (
            all of ($r1_*)
        ) or (
            any of ($r2_*)
        ) or (
            all of ($r3_*)
        ) or (
            2 of ($r4_*)
        )
}