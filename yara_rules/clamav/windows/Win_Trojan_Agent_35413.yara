rule Win_Trojan_Agent_35413
{
strings:
	$a0 = { 558bec6aff681f26400068d010400064a100000000506489250000000033d28bd068 }

condition:
	$a0
}

        
