rule Win_Trojan_VB_1063
{
strings:
	$a0 = { 68d0114000e8eeffffff00000000000030000000400000000000000062030fbf0fbd7445b93cd3a89296c77e }

condition:
	$a0
}

        
