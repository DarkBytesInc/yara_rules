rule Win_Proxy_Lager_41
{
strings:
	$a0 = { b40acbd3b174a2efbe6cd52c6348de57c3b1a13493fce432bc1357b8c59c3bc1d389a003e302526226c07633abc4703a2580eed656e6ebe47dcfbf1c93ff7a2fe1b48e467622 }

condition:
	$a0
}

        
