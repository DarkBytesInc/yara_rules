rule Win_Dropper_Agent_34724
{
strings:
	$a0 = { 558bec6aff6878204000687018400064a100000000506489250000000083ec68535657 }
	$a1 = { 5850565353ff15 }

condition:
	$a0 and $a1
}

        
