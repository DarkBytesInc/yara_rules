rule Win_Trojan_Fakeav_36
{
strings:
	$a0 = { 83ec18e83f000000e8260000005983c404585aff8ab0000000750a8182b800000067000000525083 }

condition:
	$a0
}

        
