rule Win_Worm_Stration_357
{
strings:
	$a0 = { 1811169ccadf38282c6db53535e1fc4e3d33c1f11c8a2d7c46603334dd2b782439bf5af4941b0dcd8a39201dface05ae8d77c0dcd756dcc700d88fda4256791e0e6c5ee66d9b9fb068242d3af1e7106671bc54d88beaa5e95d6929cae3562b1d }

condition:
	$a0
}

        
