rule Win_Worm_Delf_420
{
strings:
	$a0 = { ba545a4000e876dcffff8d430cba745a4000e869dcffff }

condition:
	$a0
}

        
