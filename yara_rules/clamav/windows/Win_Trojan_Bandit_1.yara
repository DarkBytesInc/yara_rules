rule Win_Trojan_Bandit_1
{
strings:
	$a0 = { ef058cd80e901f90bef7069081ee03019003f390890490bef90681ee030103f38cc089040e0753b8002fcd218bcb5bbe990a81ee030103f3890c83c6028cc0 }

condition:
	$a0
}

        
