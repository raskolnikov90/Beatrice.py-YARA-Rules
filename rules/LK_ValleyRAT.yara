rule ValleyRAT_LKBEatrice {
     meta: 
        description = "Detections for ValleyRat using Beatrice.py, modifying NDA0E rule and DefenderCheck output" 
        author = "LainKusanagi Beatrice.py" 
        date = "2026-05-10"

    strings:
        $byte1 = { 2E 65 78 65 [2-10] 25 73 25 73 }

        $byte2 = {
            4D 69 6E 69 44 75 6D 70 57 72 69 74 65 44 75 6D 70
            [2-10]
            21 00 61 00 6E 00 61 00 6C 00 79 00 7A 00 65 00 20 00 2D 00 76
        }

        $byte3 = {
            00 00 00 C7 ?? ?? ?? ?? ?? B0 C8 41 00 C7 05 B0
        }

        $string1 = "%s-%04d%02d%02d-%02d%02d%02d.dmp" fullword wide ascii
        $string2 = "operator" fullword wide ascii
        $string3 = "GetFileSizeEx" fullword wide ascii
        $string4 = "CompareStringW" fullword wide ascii
        $string5 = "LoadLibraryExW" fullword wide ascii

    condition:
        (1 of ($byte*)) and
        (1 of ($string*))
}