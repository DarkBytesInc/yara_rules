rule Win_Worm_Allaple_257
{
strings:
	$a0 = { c74424??????(40|41)00[0-10]8b7c24[0-20]33c0[0-5]014424[0-35]014424[0-35]014c24 }

condition:
	$a0
}

        
