rule Win_Worm_Mydoom_89
{
strings:
	$a0 = { 558bec6aff684320400068401e400064a100000000506489250000000081ec98 }

condition:
	$a0
}

        
