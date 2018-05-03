rule Win_Worm_Flame_6
{
strings:
	$a0 = { 8d481a83c0050fafc88bd1c1ea088bc233c1c1e81033c233c1c3 }

condition:
	$a0
}

        
