rule Win_Trojan_SdBot_2356
{
strings:
	$a0 = { 0200006a0168a4ab4200e8ba03000059596a006a0fff15e06843008985d0feffff83bdd0feffffff0f84fe010000c785d4feffff280100008d85d4feffff50ffb5d0feffffff15bc68430085c00f84cd0100008d85 }

condition:
	$a0
}

        
