rule Win_Trojan_VBS_218
{
strings:
	$a0 = { 5c72756e5c77696e646f7773222c2873202620225c7662737379732e7662732229 }

condition:
	$a0
}

        
