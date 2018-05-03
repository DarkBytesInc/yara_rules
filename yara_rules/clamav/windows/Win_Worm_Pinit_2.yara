rule Win_Worm_Pinit_2
{
strings:
	$a0 = { 6081cf7adc873581cac60be70187d733f081d99346f2690fbdd266ba6ae266bfd348684b1040 }

condition:
	$a0
}

        
