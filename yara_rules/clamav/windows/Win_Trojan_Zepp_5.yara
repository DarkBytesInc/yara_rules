rule Win_Trojan_Zepp_5
{
strings:
	$a0 = { c6058062400001e8cc040000c6058062400000e8c00400005589e581ec00010000c60580 }

condition:
	$a0
}

        
