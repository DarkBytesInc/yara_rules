rule Win_Worm_Autorun_269
{
strings:
	$a0 = { 6f70656e3d6175746f72756e2e6578652075736264726976657233322e766273 }

condition:
	$a0
}

        
