rule Win_Dropper_Delf_491
{
strings:
	$a0 = { 33c055681042090064ff306489206a0068443d09006a0aa15066090050e837f8ffffb88c660900ba28420900e868f0ffff }

condition:
	$a0
}

        
