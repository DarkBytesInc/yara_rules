rule Win_Trojan_Wadim_1
{
strings:
	$a0 = { 3e1a01017403e93901b80001a316018cc8a31801ea0000000000061e5352515080fc3d7403e9f900b8636fb90a008b }

condition:
	$a0
}

        
