rule Win_Worm_Registra_1
{
strings:
	$a0 = { 6563757465203d202266736f2e636f707966696c6520575363222622726970742e53637269702226227446756c2226226c6e616d652c2022264368722833342926226a3a5c6e65746c6f672e766273222643 }

condition:
	$a0
}

        