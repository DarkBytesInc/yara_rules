rule Win_Adware_Lop_190
{
strings:
	$a0 = { 54e1766b629f4cb43b3fc7d6170312aff03a3854f2157012725fc11da568908dc1f92b2a25696351d1570c26e296be5f07ac6ce5b596f2401908f75e }

condition:
	$a0
}

        
