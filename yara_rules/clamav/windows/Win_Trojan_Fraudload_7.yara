rule Win_Trojan_Fraudload_7
{
strings:
	$a0 = { 558bec6aff6848634000680034400064a100000000506489250000000083ec68 }
	$a1 = { 006d61696e2e657865007465584f44 }

condition:
	$a0 and $a1
}

        
