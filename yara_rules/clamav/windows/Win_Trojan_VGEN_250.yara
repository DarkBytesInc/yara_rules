rule Win_Trojan_VGEN_250
{
strings:
	$a0 = { ff04802801d4004445564943453d433a5c008bf30e560efc1f8ec6833e49040774096800b80726837c1cff068d }

condition:
	$a0
}

        
