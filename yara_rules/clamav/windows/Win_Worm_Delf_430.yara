rule Win_Worm_Delf_430
{
strings:
	$a0 = { 41540000ffffffff0100000041000000ffffffff0300000033353400ffffffff0e0000000d0a2d2d626c612d2d0d0a2e0d0a0000ffffffff06000000515549540d0a0000558bec33c055687156400064 }

condition:
	$a0
}

        