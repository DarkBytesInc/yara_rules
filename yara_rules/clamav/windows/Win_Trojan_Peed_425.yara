rule Win_Trojan_Peed_425
{
strings:
	$a0 = { 9053[0-12]909090 }

condition:
	$a0
}

        
