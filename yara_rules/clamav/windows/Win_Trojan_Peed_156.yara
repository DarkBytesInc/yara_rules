rule Win_Trojan_Peed_156
{
strings:
	$a0 = { e80000000029d287d15a8d1d30??400029d2528b3b89e353ffd769c90001000089c883c404eb1e5589e5890189d88b5d }

condition:
	$a0
}

        
