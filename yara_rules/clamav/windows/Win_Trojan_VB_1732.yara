rule Win_Trojan_VB_1732
{
strings:
	$a0 = { 910000000000000000000000000000000000000069736f6d796172 }

condition:
	$a0
}

        
