rule Win_Trojan_Crypi_1
{
strings:
	$a0 = { 558bec6aff680059420068d437420064a100000000506489250000000083ec585356578965e8 }

condition:
	$a0
}

        
