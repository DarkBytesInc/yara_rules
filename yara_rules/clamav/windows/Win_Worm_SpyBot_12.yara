rule Win_Worm_SpyBot_12
{
strings:
	$a0 = { 59802b29537231d853cb0e2dd3f67d9db9d8931d35650fd8c1e100c53e4db78eafcae93f8e2375943a1c50000e0d6ed6ad667ac6f3cfd782283ff6f71231f0de8e9c9bfc98796108bff7a4f514d95209 }

condition:
	$a0
}

        
