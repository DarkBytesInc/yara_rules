rule Win_Trojan_Lavi_1
{
strings:
	$a0 = { 80ed0083c10088e4268a0280ed0088d2346426880283c10083e900462d000080c500e2e289c9c3 }

condition:
	$a0
}

        
