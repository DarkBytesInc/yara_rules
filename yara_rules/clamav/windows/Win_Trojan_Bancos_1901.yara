rule Win_Trojan_Bancos_1901
{
strings:
	$a0 = { c084cf5b8a3cc419d559067230226365eb8ec8256bf4083555b19c1cfd2f0774304aa5f4a516a73ffc6fc1f13e37f4d79c3d71ab5f6def164498fd2c320e8957512b9b4cba03 }

condition:
	$a0
}

        
