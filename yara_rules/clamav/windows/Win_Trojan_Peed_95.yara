rule Win_Trojan_Peed_95
{
strings:
	$a0 = { 682c0400006858204000e8fb000000c74594440000006a4033f6568d459850e8 }

condition:
	$a0
}

        
