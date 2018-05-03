rule Win_Trojan_Peed_423
{
strings:
	$a0 = { 9090909053 }

condition:
	$a0
}

        
