rule Win_Worm_Agent_35762
{
strings:
	$a0 = { 558bec6aff682861400068c04e400064a100000000506489250000000083ec68 }

condition:
	$a0
}

        
