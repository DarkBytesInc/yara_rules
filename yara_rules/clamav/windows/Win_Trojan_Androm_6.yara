rule Win_Trojan_Androm_6
{
strings:
	$a0 = { e8eb0d000033c0c30249088026008b7265005008220065a663c58b743102e83600bd0002525e00f08b8bc0ff800033b6 }

condition:
	$a0
}

        
