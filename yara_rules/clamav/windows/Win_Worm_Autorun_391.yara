rule Win_Worm_Autorun_391
{
strings:
	$a0 = { 558bec6aff68b020400068c018400064a100000000506489250000000083 }
	$a1 = { 095237522c522b557a252548 }

condition:
	$a0 and $a1
}

        
