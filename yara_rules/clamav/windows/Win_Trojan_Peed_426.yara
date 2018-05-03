rule Win_Trojan_Peed_426
{
strings:
	$a0 = { 90909053 }

condition:
	$a0
}

        
