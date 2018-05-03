rule Win_Worm_Allaple_14
{
strings:
	$a0 = { c74424??????(40|41)00[0-10]8b4424[0-20]33c9[0-5]014c24[0-35]015c24[0-35]014424 }

condition:
	$a0
}

        
