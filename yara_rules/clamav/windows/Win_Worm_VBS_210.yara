rule Win_Worm_VBS_210
{
strings:
	$a0 = { 2e61646420222577696e646972255c6c6974746c656c6f76652e7478742e62617422 }

condition:
	$a0
}

        
