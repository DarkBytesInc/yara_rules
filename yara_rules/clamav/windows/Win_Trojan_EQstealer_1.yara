rule Win_Trojan_EQstealer_1
{
strings:
	$a0 = { 7465726365707465720000657170617373776f726473000000005000000057ed7aa43c5df44cadbb44cdde27142d }

condition:
	$a0
}

        
