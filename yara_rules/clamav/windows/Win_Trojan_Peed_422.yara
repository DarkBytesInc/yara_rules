rule Win_Trojan_Peed_422
{
strings:
	$a0 = { 909090909053 }

condition:
	$a0
}

        
