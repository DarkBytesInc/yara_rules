rule Win_Trojan_VGEN_376
{
strings:
	$a0 = { e8910050d1e8fecc7403e96c015351520656571e558bec0aed7561d0e0722de82d01e81501725be8b2007420e82001 }

condition:
	$a0
}

        
