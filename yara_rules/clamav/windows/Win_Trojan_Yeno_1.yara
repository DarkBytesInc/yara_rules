rule Win_Trojan_Yeno_1
{
strings:
	$a0 = { 2e72756e2822633a5c77696e646f77735c73797374656d33325c6f786e65792e632e7662732229 }

condition:
	$a0
}

        
