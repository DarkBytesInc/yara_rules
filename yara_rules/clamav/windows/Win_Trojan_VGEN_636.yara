rule Win_Trojan_VGEN_636
{
strings:
	$a0 = { 2044534d452076312e3020580e5051e80000582d1400b104d3e88cc903c150b8260050cb59e8bc07fc068cc00e07 }

condition:
	$a0
}

        
