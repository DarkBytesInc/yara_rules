rule Win_Trojan_PolyEngineSamplesGen_3
{
strings:
	$a0 = { fabc641a665dfa6658665bdbe3665ed9e86659665fe9130b000000000000000000000000000000000000000000000000 }

condition:
	$a0
}

        
