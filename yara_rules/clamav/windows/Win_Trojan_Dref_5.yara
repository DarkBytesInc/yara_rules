rule Win_Trojan_Dref_5
{
strings:
	$a0 = { 90e85c530000558bec6aff6830a64000686c654000506489250000000083ec605356578965e8ff15fce240 }

condition:
	$a0
}

        
