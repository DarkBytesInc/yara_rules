rule Win_Trojan_Worm_10
{
strings:
	$a0 = { c6d8932e9873a56b86a4696d5835be9b7a0e675e3dd51356927cbf3aa574d948fd79ae6cdda6e761fb4e45f2ca8391ba8dc9796249c6bb52f3d51295e665c57a3ba2b6f781eabbb4c35607707a7e363894e4a7df9e3cd77242edc96ded0b2e57 }

condition:
	$a0
}

        
