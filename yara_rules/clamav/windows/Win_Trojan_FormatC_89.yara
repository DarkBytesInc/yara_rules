rule Win_Trojan_FormatC_89
{
strings:
	$a0 = { 696620657869737420633a5c77696e646f77735c73662e62617420676f746f2066696e }

condition:
	$a0
}

        
