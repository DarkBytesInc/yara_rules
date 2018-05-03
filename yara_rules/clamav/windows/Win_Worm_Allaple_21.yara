rule Win_Worm_Allaple_21
{
strings:
	$a0 = { c74424??????(40|41)00[0-10]8b4424[0-20]33c9[0-5]014c24[0-35]014c24[0-35]015424 }

condition:
	$a0
}

        
