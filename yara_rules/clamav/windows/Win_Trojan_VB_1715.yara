rule Win_Trojan_VB_1715
{
strings:
	$a0 = { 910000000000000000000000000000000000000054726f6d6f6d65 }

condition:
	$a0
}

        
