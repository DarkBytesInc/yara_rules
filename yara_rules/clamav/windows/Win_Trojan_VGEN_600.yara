rule Win_Trojan_VGEN_600
{
strings:
	$a0 = { 04d3e82d10008cc903c150b8150150cb2eff261a01ca0146000706040071041800d2045500a3050c00af0506002b }

condition:
	$a0
}

        
