rule Win_Trojan_AVKill_11
{
strings:
	$a0 = { 6e65742073746f702061766533320d0a6e65742073746f702061766763633332 }

condition:
	$a0
}

        
