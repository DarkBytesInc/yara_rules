rule Win_Trojan_Alcaul_9
{
strings:
	$a0 = { e62d998bbeb912983905d2eceded68ae2410e62db599be8bd0eeec9875be6621bebcbebebe12981d05cdecededd39b386cb4e62d99d90edb55edefededd6259bec7cbe6639bebfbcba12981d0511ededed860c92a5e62db599fdbebdba129805052dededed899a94e3ad99bc067b12980587ec66218789beb9bebebc87 }

condition:
	$a0
}

        
