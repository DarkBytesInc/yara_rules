rule Win_Trojan_Kermit_1
{
strings:
	$a0 = { ec04558bec508cc0051000894604c746027021061e5351565733c08ec026803e8f03ff75095f5e595b1f07585dcb26 }

condition:
	$a0
}

        
