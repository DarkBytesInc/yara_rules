rule Win_Trojan_Gen_203
{
strings:
	$a0 = { 9a00001f029a0d00bd019a8d0ae7009ace0679009aee0159005589e5b802029acd021f0281ec0202c606820000c60683 }

condition:
	$a0
}

        
