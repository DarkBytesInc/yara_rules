rule Win_Trojan_CIA_2
{
strings:
	$a0 = { c31009432e492e41202d20437275656c20490ffe0fda2328697d7a2041646d696e69738f6174761b18ec6f72 }

condition:
	$a0
}

        
