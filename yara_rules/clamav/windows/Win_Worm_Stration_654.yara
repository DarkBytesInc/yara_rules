rule Win_Worm_Stration_654
{
strings:
	$a0 = { 3720cfbffbde2e6578650b5c0f43531c1b0053436e097e8bffff2c383d28397c2f293f3f392f2f3a293030a235322f283d12ffdfde083938722d52757d7469767a }

condition:
	$a0
}

        
