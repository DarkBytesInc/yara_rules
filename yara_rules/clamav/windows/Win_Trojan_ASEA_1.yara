rule Win_Trojan_ASEA_1
{
strings:
	$a0 = { 526564417263202f2f20544156439a00002a01c800010031c0a332036a10bf22031e579a2700 }

condition:
	$a0
}

        
