rule Win_Trojan_VGEN_356
{
strings:
	$a0 = { 81005589e5bfbf050e57bf5a001e57b8ff00509a9f068100b42acd218836560088165700803e560004751d803e }

condition:
	$a0
}

        
