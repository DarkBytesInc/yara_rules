rule Win_Worm_Allaple_73
{
strings:
	$a0 = { c74424??????(40|41)00[0-10]8b4c24[0-20]33c0[0-5]014424[0-35]014c24[0-35]015424 }

condition:
	$a0
}

        
