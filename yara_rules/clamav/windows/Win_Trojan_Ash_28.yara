rule Win_Trojan_Ash_28
{
strings:
	$a0 = { e800005d81ed????8d9e????538a86????b99e02300743e2fbc3 }

condition:
	$a0
}

        
