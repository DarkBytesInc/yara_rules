rule Win_Trojan_Philis_116
{
strings:
	$a0 = { 5133c9eb01eb5960565ee8000000000f00e76081ebb162000061575f5ab80401000053435b434b03 }

condition:
	$a0
}

        
