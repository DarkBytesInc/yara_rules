rule Win_Trojan_Philis_96
{
strings:
	$a0 = { 5603f35e6081f7713d000081f7713d0000e80000000056f7d65e6033f38bfe61608bf2615ab8ff00000050b83181 }

condition:
	$a0
}

        
