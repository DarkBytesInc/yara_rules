rule Win_Trojan_VGEN_264
{
strings:
	$a0 = { 49dd0600071ccb251f050902000400a01000000000008bece814df81246d2de9b81613040000558bec55e90000bf4c }

condition:
	$a0
}

        
