rule Win_Trojan_Small_3848
{
strings:
	$a0 = { c298db4d89537dd9e274dc25100bd455c9d8884f4cc400854eb47c55c1d88c3279cdbccaa39c20ca4cb4d64e0d0e8c4feeb57cca4cead0e38db4d3b2a7ee7ccaa6393d24c1cd7b0085cdbccaa39cc5044db4d54f0d0ef2d1b7 }

condition:
	$a0
}

        
