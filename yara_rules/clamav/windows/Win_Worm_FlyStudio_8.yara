rule Win_Worm_FlyStudio_8
{
strings:
	$a0 = { 505651f95253570f82a7fefffffcb575e204117ea846ca15e6cac3dac3eb7ba3d2bf3fdae69b9e2028d91e3666d82d1eae455a7d1c99c544f0e3d483c204e9a5feffff0c3ee3c828cebcc8d0221ec3bc0aa4bb743e30db0adb7fb84cc101d83f39e871c9dc7f72aeb0be81ee71000000e92800000025d9be931bd94c5e0f82e7 }

condition:
	$a0
}

        
