rule Akira_LKBEatrice {
     meta: 
        description = "Detections for Akira using Beatrice.py, modifying Defende2Yara rule" 
        author = "LainKusanagi Beatrice.py" 
        date = "2026-05-03"

    strings:
        $akira1 = "akira_readme.txt" ascii wide
        $akira2 = ".akira" ascii
        $akira3 = "AKIRA_" wide
        $akira4 = "settings.dat.akira" wide

        $note1 = "internal infrastructure of your company is fully or partially dead" ascii
        $note2 = "all your backups - virtual, physical" ascii
        $note3 = "constructive dialogue" ascii
        $note4 = "Well, for now let's keep all the tears and resentment to ourselves and try to build a constructive dialogue" ascii
        $note5 = "all your backups - virtual, physical - everything that we managed to reach - are completely removed. Moreover, we have taken a great amount of your corporate data prior to encryption" ascii

        $misc1 = "README.txt" ascii
        $misc2 = "BEGIN PUBLIC KEY" ascii
        $misc3 = "recovery_support@protonmail" ascii
        $misc4 = "AV_Facet_base" ascii
        $misc5 = "Saturday"

        $b1 = {42 0f b6 4c 0d ?? 83 e9 ?? 44 6b c1 ?? b8 09 04 02 81 41 f7 e8 41 03 d0 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 44 2b c0 41 83 c0 7f b8 09 04 02 81 41 f7 e8 41 03 d0 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 44 2b c0 46 88 44 0d ?? 49 ff c1 49 83 f9 ?? 72}

        $b2 = {83 e9 08 44 6b c1 22 41 f7 e8 41 03 d0 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 44 2b c0 b8 ?? ?? ?? ?? 41 83 c0 7f 41 f7 e8 41 03 d0 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 44 2b c0}

        $b3 = {2b c1 6b c8 ?? b8 ?? ?? ?? ?? f7 e9 03 d1 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 83 c1 ?? b8 ?? ?? ?? ?? f7 e9 03 d1 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 42 88 4c 05 c1 49 ff c0 49 83 f8}

        $b4 = {4d 8b c3 4d 8b d5 41 83 e5 3f 49 c1 fa 06 4e 8d 1c ed 00 00 00 00 4d 03 dd 41 8a 04 38 41 ff c1 4b 8b 8c d7 10 55 0f 00 49 03 c8 49 ff c0 42 88 44 d9 3e 49 63 c1 48 3b c2}

        $b5 = {48 89 ca 48 83 e2 03 44 8a 04 14 44 30 c0 88 04 0e 48 ff c1 4c 39 d1}

        $b6 = {48 83 ec 78 48 89 d7 48 89 4c 24 38 48 8d 42 30 48 89 44 24 60 4c 8b 7a 10 48 8b 6a 28 48 8b 72 18 0f b6 5a 38 8a 42 40 88 44 24 2f 48 8b 0a 48 8b 42 08 48 89 44 24 40 4c 8b 72 20 8a 42 41 88 44 24 2e f6 44 24 2e 01}

        $b7 = {89 14 24 48 8b 94 24 18 01 00 00 8b 3c 24 03 7c 24 34 33 42 04 44 33 6a 0c 44 33 7a 14 44 33 72 18 33 6a 1c 33 72 20 33 7a 24 33 5a 28 44 33 5a 2c 44 33 42 38 33 4a 3c 89 44 24 70 8b 44 24 4c 41 03 c4 44 89 6c 24 58 33 42 08 44 8b 6c 24 18}

        $b8  = {2e 61 6b 69 72 61 00}
        $b9  = {2e 00 76 00 6d 00 65 00 6d 00 00 00 00 00 00 00 2e 00}
        $b10 = {2e 00 73 00 75 00 62 00 76 00 6f 00 6c 00 00 00 2e 00}
        $b11 = {2e 00 61 00 62 00 63 00 64 00 64 00 62 00 00 00 2e 00}

        $b12 = {86 55 20 43 e1 bb a6 41 20 42 e1 ba a0 4e 20 c4 90 c3 83 20 42 e1 bb 8a 20 4d c3 83 20 48 c3 93 41 20 21 21 21 0a 00 00 54 e1 ba a5 74 20 63 e1 ba a3 20 63 c3 a1 63 20 74 e1 bb 87 70 20 71 75 61 6e 20 74 72 e1 bb 8d 6e 67 20 63 e1 bb a7 61 20 62}
       
        $b13 = {0f 57 c9 ?? ?? 7f 8d c0 01 00 00 48 8d 45 59 4c}
    condition:
        (filesize < 20MB) and
        (
            (1 of ($akira*)) or

            (2 of ($note*)) or

            (any of ($b*)) or

            (2 of ($misc*) and 1 of ($akira*))
        )
}