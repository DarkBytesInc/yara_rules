rule Win_Trojan_Alicia_3
{
strings:
	$a0 = { 776f72642e6f7074696f6e732e766972757370726f74656374696f6e203d2066616c7365 }

condition:
	$a0
}

        
