rule Win_Trojan_ExeInfector_2
{
strings:
	$a0 = { b44e[0-8]cd21[0-200]b43d[0-8]cd21[0-200]b440[0-8]cd21 }
	$a1 = { 2a2e45584500 }

condition:
	$a0 and $a1
}

        
