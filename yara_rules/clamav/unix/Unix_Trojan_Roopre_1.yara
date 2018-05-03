rule Unix_Trojan_Roopre_1
{
strings:
	$a0 = { 507261676d613a2031333337 }

condition:
	$a0
}

        
