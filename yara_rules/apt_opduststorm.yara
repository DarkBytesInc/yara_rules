/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Misdat_Backdoor_Packed
{
    
      meta:
    author = "Cylance SPEAR Team"
    note = "Probably Prone to False Positive"
    description = "Misdat_Backdoor_Packed"
    severity = "10"
    type = "Advanced Persistent Threat"

    strings:
        $upx = {33 2E 30 33 00 55 50 58 21}
        $send = {00 00 00 73 65 6E 64 00 00 00}
        $delphi_sec_pe = {50 45 00 00 4C 01 03 00 19 5E 42 2A}
        $shellexec = {00 00 00 53 68 65 6C 6C 45 78 65 63 75 74 65 57 00 00 00}
        
    condition:
        filesize < 100KB and $upx and $send and $delphi_sec_pe and $shellexec
}

rule MiSType_Backdoor_Packed
{
    
      meta:
    author = "Cylance SPEAR Team"
    note = "Probably Prone to False Positive"
    description = "Misdat_Backdoor_Packed"
    severity = "10"
    type = "Advanced Persistent Threat"

    strings:
        $upx = {33 2E 30 33 00 55 50 58 21}
        $send_httpquery = {00 00 00 48 74 74 70 51 75 65 72 79 49 6E 66 6F 41 00 00 73 65 6E 64 00 00}
        $delphi_sec_pe = {50 45 00 00 4C 01 03 00 19 5E 42 2A}
    
    condition:
        filesize < 100KB and $upx and $send_httpquery and $delphi_sec_pe
}

rule Misdat_Backdoor
{
   
     meta:
    author = "Cylance SPEAR Team"
    description = "Misdat_Backdoor"
    severity = "10"
    type = "Advanced Persistent Threat"
    
    strings:
        $imul = {03 45 F8 69 C0 D9 DB 00 00 05 3B DA 00 00}
        $delphi = {50 45 00 00 4C 01 08 00 19 5E 42 2A}
        
    condition:
        $imul and $delphi
}

rule SType_Backdoor
{
   
      meta:
    author = "Cylance SPEAR Team"
    description = "SType_Backdoor"
    severity = "10"
    type = "Advanced Persistent Threat"

    strings:
        $stype = "stype=info&data="
        $mmid = "?mmid="
        $status = "&status=run succeed"
        $mutex = "_KB10B2D1_CIlFD2C"
        $decode = {8B 1A 8A 1B 80 EB 02 8B 74 24 08 32 1E 8B 31 88 1E 8B 1A 43}
    
    condition:
        $stype or ($mmid and $status) or $mutex or $decode
}

rule Zlib_Backdoor
{
   
      meta:
    author = "Cylance SPEAR Team"
    description = "Zlib_Backdoor"
    severity = "10"
    type = "Advanced Persistent Threat"


    strings:
        $auth = {C6 45 D8 50 C6 45 D9 72 C6 45 DA 6F C6 45 DB 78 C6 45 DC 79 C6 45 DD 2D}
        $auth2 = {C7 45 FC 00 04 00 00 C6 45 ?? 50 C6 45 ?? 72 C6 45 ?? 6F}
        $ntlm = "NTLM" wide
    
    condition:
        ($auth or $auth2) and $ntlm
}
