rule Win_Trojan_VGEN_96
{
strings:
	$a0 = { 0300b104d3e82d10008ccb03c3508d06f6018d1e00012bc305000150cb002a2e434f4d0000000000000000000000 }

condition:
	$a0
}

        
