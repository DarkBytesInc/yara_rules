rule Win_Trojan_CVE_2005_1342_1
{
strings:
	$a0 = { 782d6d616e2d706167653a2f2f[0-100]253162 }

condition:
	$a0
}

        
