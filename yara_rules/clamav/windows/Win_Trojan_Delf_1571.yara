rule Win_Trojan_Delf_1571
{
strings:
	$a0 = { 6a00e860daffff6a00e8a1daffff6a006a00e8e0daffff68ec8640006a006a0068d06240006a006a00e8f9d9ffffb8c48d4000ba54684000e80ed0ffff680401000068bc8c4000a15086400050e8f5d9ffff }

condition:
	$a0
}

        
