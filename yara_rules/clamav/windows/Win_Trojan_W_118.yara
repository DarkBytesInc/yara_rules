rule Win_Trojan_W_118
{
strings:
	$a0 = { 7f340000f7bf7cca8b473489850204000033c0668b471403c783c018668b4f0681382e65646175 }

condition:
	$a0
}

        
