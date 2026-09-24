rule Process_Injection_APIs
{
    strings:
        $a = "VirtualAllocEx" ascii wide
        $b = "WriteProcessMemory" ascii wide
        $c = "CreateRemoteThread" ascii wide
        $d = "NtUnmapViewOfSection" ascii wide
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule UPX_Packed
{
    strings:
        $a = "UPX0" ascii
        $b = "UPX1" ascii
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule Ransom_Note_Keywords
{
    strings:
        $a = "your files have been encrypted" ascii wide nocase
        $b = "bitcoin" ascii wide nocase
        $c = ".onion" ascii wide nocase
    condition:
        2 of them
}
