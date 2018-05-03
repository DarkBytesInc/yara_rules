rule Win_Worm_Delf_421
{
strings:
	$a0 = { ba485a4000e87fdcffff8d4314ba585a4000e872dcffff8d430cba785a4000e865dcffff }

condition:
	$a0
}

        
