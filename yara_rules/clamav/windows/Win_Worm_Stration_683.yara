rule Win_Worm_Stration_683
{
strings:
	$a0 = { 5589e56aff6818??400068 }
	$a1 = { 803b227536eb1085c9740789c8418a1388108b4518ff004389d88038227405 }

condition:
	$a0 and $a1
}

        
