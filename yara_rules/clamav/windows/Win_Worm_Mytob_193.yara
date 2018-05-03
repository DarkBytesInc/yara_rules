rule Win_Worm_Mytob_193
{
strings:
	$a0 = { 6e672048656c6c426f743a3a763320626574 }

condition:
	$a0
}

        
