rule Win_Trojan_L_38
{
strings:
	$a0 = { 87262d0c88264c01882b48018726310c88263101882b1c018726330c88263501 }

condition:
	$a0
}

        
