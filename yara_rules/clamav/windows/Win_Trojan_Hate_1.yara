rule Win_Trojan_Hate_1
{
strings:
	$a0 = { b80058cd2180fc5875069090b44ccd21e800005e81ee15018a942e0380fa0074139090b9f801908dbc36018a0532 }

condition:
	$a0
}

        
