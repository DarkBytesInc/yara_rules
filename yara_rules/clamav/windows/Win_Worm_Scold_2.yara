rule Win_Worm_Scold_2
{
strings:
	$a0 = { c745fc1c00000068545d400068a85d4000ff15ac1040008bd08d8d34fdffffff152811400050ff1534104000 }

condition:
	$a0
}

        
