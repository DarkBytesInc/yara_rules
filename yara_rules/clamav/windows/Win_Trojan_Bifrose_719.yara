rule Win_Trojan_Bifrose_719
{
strings:
	$a0 = { 66059900??83e8076683f0059066f7d06066c1c8049090909090909090909090909090e85bffffffc3 }

condition:
	$a0
}

        
