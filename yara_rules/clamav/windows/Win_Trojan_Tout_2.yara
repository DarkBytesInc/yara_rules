rule Win_Trojan_Tout_2
{
strings:
	$a0 = { 8db6????56fc8b96????????008bfead33c2d2c2abe2f8c3 }

condition:
	$a0
}

        
