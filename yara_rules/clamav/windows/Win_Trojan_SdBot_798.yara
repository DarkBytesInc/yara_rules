rule Win_Trojan_SdBot_798
{
strings:
	$a0 = { 6374726c2e6578650f20636f6e12edeefe6f6f20736b65776c65640931005b3b5d00a560f38100503fff6f62586b82e87603 }

condition:
	$a0
}

        
