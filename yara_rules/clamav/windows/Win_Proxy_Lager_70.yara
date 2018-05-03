rule Win_Proxy_Lager_70
{
strings:
	$a0 = { 20f1b72360a325a0b8eea7c78d2667998008cc9f8576a5a38a6ed260574ad91bf7b3a678a7fee37e881150f4f19e3c8de78ba74fd700552e12c2717f9fc677761182e99a62e4 }

condition:
	$a0
}

        
