rule Win_Trojan_VGEN_670
{
strings:
	$a0 = { e80000cc5eb94000b430cd210bc074598cdb4b8edb3ded0f744b53c60600006d8036000020812e03002701812e120027 }

condition:
	$a0
}

        
