rule Win_Trojan_Loulou_1
{
strings:
	$a0 = { 9a00006f005589e5b800039a30056f0081ec0003bf12271e57bf14271e57bf16271e57bf18271e579a00005600833e14 }

condition:
	$a0
}

        
