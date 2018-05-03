rule Win_Worm_Stration_659
{
strings:
	$a0 = { 39202e6578650b5c0ff3e3acabb0e3f3feffff9fdee0c5d1d4c1d095c6c0d6d6d0c6c6d3c0d9d9cc95dcdbc6c1d47cffdbdf08d0d19bb500bf5399849b97829f9998f62f54f6c9ed45a8003600cdcbdda977cbffff8a96dcd4d4b8006b6f6c6e7572687a }

condition:
	$a0
}

        
