rule Win_Trojan_Milen_1
{
strings:
	$a0 = { e800000000f833c65ac1e05b81ea0a1040008bc2f5bb0903000033c0f58db24210400033c29081365a265a3433c4f583c60433c2f94b }

condition:
	$a0
}

        
