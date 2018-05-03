rule Win_Worm_Stration_764
{
strings:
	$a0 = { 746728b4e62ef41f9bf13bbd80dc6d7db5f2c2f8fbf60e997965478c7e5584bcfc42b0b1f619aa5d1d4f15f66e548e62429615d86d13830433ece181019c1c869d512be05d32cb7e2fcda6216f49c8a3e19fd5972c607c8f0e }

condition:
	$a0
}

        
