rule Win_Trojan_RickDogg97_1
{
strings:
	$a0 = { 9a00001f005589e5b800019a7c021f0081ec0001b00050bf14021e57b84200509a04091f00bf00000e57bf14021e579a }

condition:
	$a0
}

        
