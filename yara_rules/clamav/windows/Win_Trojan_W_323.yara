rule Win_Trojan_W_323
{
strings:
	$a0 = { 570f014c24fe5fdf2f500417abab58ff77028f47facd00df7ff88b784b909090c7470876f5ffff8bf066bf00086a2e9090909059f3a503065950cf663d4e7175 }

condition:
	$a0
}

        
