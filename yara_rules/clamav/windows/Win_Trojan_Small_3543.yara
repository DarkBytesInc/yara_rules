rule Win_Trojan_Small_3543
{
strings:
	$a0 = { e9fbefffff000000000000000000000000000000000000000000000000000000 }

condition:
	$a0
}

        
