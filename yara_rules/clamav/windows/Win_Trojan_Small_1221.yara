rule Win_Trojan_Small_1221
{
strings:
	$a0 = { 5f626c612e6461740000000077696e73652e657865000000687474703a2f }

condition:
	$a0
}

        
