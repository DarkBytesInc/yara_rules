rule Win_Trojan_VB_1738
{
strings:
	$a0 = { 8d000000000000000000000000000000000000006f726f67726170 }

condition:
	$a0
}

        
