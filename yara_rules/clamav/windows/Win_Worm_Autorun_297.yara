rule Win_Worm_Autorun_297
{
strings:
	$a0 = { 6f70656e3d726573746f72655c732d[0-38]2d313031335c6d736e6d736e67722e657865 }

condition:
	$a0
}

        
