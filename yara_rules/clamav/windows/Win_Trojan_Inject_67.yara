rule Win_Trojan_Inject_67
{
strings:
	$a0 = { 558bec6aff6840204000685011400064a100000000506489250000000083ec205356 }
	$a1 = { 006869000001 }

condition:
	$a0 and $a1
}

        
