rule Win_Worm_Pinit_1
{
strings:
	$a0 = { 60f7dec1db0133df0fbede8d3dba61abc8f7de413e0f2a04248bd3ba3e7f[0-53]682e646c6c[0-27]686b65726e }

condition:
	$a0
}

        
