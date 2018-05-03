rule Win_Worm_Delf_1533
{
strings:
	$a0 = { 2a2e657865202f00ffffffff03000000203e3e00558bec33c055684557400064ff30648920ff05dcd64000750ab8a8704000e8c5c9ffff }

condition:
	$a0
}

        
