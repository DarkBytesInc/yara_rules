rule Win_Trojan_VGEN_130
{
strings:
	$a0 = { d3e82d10008cc903c150b8150150cb2eff261a01ce0146006c06040075041800d60455000a060c00160606002f }

condition:
	$a0
}

        
