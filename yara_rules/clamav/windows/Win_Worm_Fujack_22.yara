rule Win_Worm_Fujack_22
{
strings:
	$a0 = { 33c05568ba8a410064ff306489208d55f48b45fce854fcffff8d4df8bad08a4100b8e08a4100e892e1feff8b55f48b45f8e8e7befeff }

condition:
	$a0
}

        
