rule Win_Trojan_Dialer_746
{
strings:
	$a0 = { 636561726e792e636f6d00436f6e6e657373696f6e6520507265646566696e69746100dce8e4aa695ea6eeeea58fd3d5cbd1dfdfd8e2d8dda69cd3d9a39cd2d2cfc7d7e5a298d7d2c9ddaa609ed8d8afb1dbcda16e66 }

condition:
	$a0
}

        
