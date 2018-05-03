rule Win_Trojan_Peed_424
{
strings:
	$a0 = { 909053[0-8]909090 }

condition:
	$a0
}

        
