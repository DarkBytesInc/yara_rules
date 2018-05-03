rule Win_Worm_Morb_1
{
strings:
	$a0 = { 5368006f400068106f400068c86e4000e889dbffff5368d06e400068146f400068c86e4000e874dbffff }

condition:
	$a0
}

        
