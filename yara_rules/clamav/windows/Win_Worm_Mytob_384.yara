rule Win_Worm_Mytob_384
{
strings:
	$a0 = { 76616f2e6f72672f636f6e6669726d6174696f6e5f73686565742e706966223e687474703a2f2f }

condition:
	$a0
}

        
