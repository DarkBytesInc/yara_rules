rule Win_Worm_Lite_1
{
strings:
	$a0 = { c7442404703340008d85a8fbffff890424e89ede00008d85e8faffff83c078890424e803f6ffff }

condition:
	$a0
}

        
