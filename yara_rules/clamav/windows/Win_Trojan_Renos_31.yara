rule Win_Trojan_Renos_31
{
strings:
	$a0 = { 8de0feffffb9a0000000338d44ffffff039528feffffff45d0ff8560feffff21d14181f978030000722cba95000000139584fdffff098ddcfeffff81faf5050000761a4281ea0005000081c2f5000000298d9cfdffff4281c2a6000000318d04fdffff11 }

condition:
	$a0
}

        
