rule Win_Trojan_Tree_2
{
strings:
	$a0 = { 80009a00001e005589e5b800019a7c02800081ec0001bf00000e57bf44001e57b80400509a0c0780009ac0011e }

condition:
	$a0
}

        
