rule Urelas_LKBEatrice {
     meta: 
        description = "Detections for Urelas using Beatrice.py, modifying Defende2Yara rule and DefenderCheck output" 
        author = "LainKusanagi Beatrice.py" 
        date = "2026-05-03"

    strings:
        // HEX STRINGS
        $hex_1 = {68 a4 1c 04 10 8d 55 ec 52 e8 00 dd fc ff 83 c4 10 c6 45 fc 00 8d 4d e8 e8 81 de fc ff 51 8b c4 89 65 e4 50 e8 55 03 00 00 83 c4 04 89 45 d4 8b 4d d4 89 4d d0 c6 45 fc 02 51 8b cc 89 65 e0 8d 55 ec 52 e8 16 d9 fc ff 89 45 cc c6 45 fc 00 e8 8a fd ff ff}
        $hex_2 = {09 5f 50 4d 4e 55 4d 42 45 52}
        $hex_3 = {4c 00 41 00 53 00 50 00 4f 00 4b 00 45 00 52 00 2e 00 65 00 78 00 65 00 00 00}
        $hex_4 = {70 00 6f 00 6b 00 65 00 72 00 37 00 2e 00 65 00 78 00 65 00 00 00}
        $hex_5 = {42 00 61 00 64 00 75 00 6b 00 69 00 2e 00 65 00 78 00 65 00 00 00}
        $hex_6 = {48 00 4f 00 4f 00 4c 00 41 00 33 00 2e 00 45 00 58 00 45 00 00 00}
        $hex_7 = {44 00 75 00 65 00 6c 00 50 00 6f 00 6b 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00}
        $hex_8 = {46 00 4e 00 46 00 2e 00 65 00 78 00 65 00 00 00}
        $hex_9 = {24 00 24 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 58 00 70 00 2e 00 62 00 61 00 74 00 00 00}
        $hex_10 = {52 00 65 00 73 00 6f 00 6c 00 76 00 69 00 6e 00 67 00 20 00 68 00 6f 00 73 00 74 00 6e 00 61 00 6d 00 65 00 20 00 25 00 73 00 2e 00 00 00}
        $hex_11 = {?? ?? ?? ?? ?? 01 00 00 00 e8 66 11 00 00 e9 6e}

        // WIDE STRINGS
        $w_1 = "LASPOKER.exe" wide
        $w_2 = "$$WindowsXp.bat" wide
        $w_3 = "golfinfo.ini" wide
        $w_4 = "golfset.ini" wide
        $w_5 = "_uninsep.bat" wide
        $w_6 = "systemkey" wide
        $w_7 = "\\HGDraw.dll" wide
        $w_8 = "Newbadugi.exe" wide
        $w_9 = "SeDebugPrivilege" wide
        $w_10 = "WriteProcessMemory" wide
        $w_11 = "DuelPoker.exe" wide
        $w_12 = "MyCom" wide
        $w_13 = "_MYDEBUG:" wide
        $w_14 = "%s%s.exe" wide
        $w_15 = "\\.\\PHYSICALDRIVE" wide
        $w_16 = "/model_type/AUTOFILL_WALLET" ascii

    condition:
(
    (2 of ($hex_*)) or
    ((1 of ($hex_*)) and (1 of ($w_*))) or
    (3 of ($w_*))
)
}
