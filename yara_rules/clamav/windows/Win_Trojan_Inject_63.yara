rule Win_Trojan_Inject_63
{
strings:
	$a0 = { 558bec6aff68c070410068743c410064a1000000005064 }
	$a1 = { 2657333e2d3320702279496761772230242777433536 }

condition:
	$a0 and $a1
}

        
