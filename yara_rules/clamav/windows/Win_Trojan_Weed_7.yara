rule Win_Trojan_Weed_7
{
strings:
	$a0 = { d88ec033dbb403cd108916ffc35f01b400cd1a87c1a38401f382ffcf01fcb95100be0400bf025df3a4a1a1f44af453f4fe57f4a4a161f4fe62f4f5f4fe6ef4465e4343f4fd7af497f4fe80f4e8e170f4feafbf395ff4e8590f5eb0f18a5f9df809a0e5fc3e8215e5ff8eff91e5fc23e5 }

condition:
	$a0
}

        
