rule Win_Worm_Agent_35430
{
strings:
	$a0 = { 6801904000e801000000c3c382e6ae151aa2ce9b1e }
	$a1 = { 5745502f22 }
	$a2 = { 408057696e646f05774b73 }

condition:
	$a0 and $a1 and $a2
}

        
