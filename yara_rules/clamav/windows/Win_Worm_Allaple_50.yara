rule Win_Worm_Allaple_50
{
strings:
	$a0 = { c74424??????(40|41)00[0-10]8b5424[0-20]33c9[0-5]014c24[0-35]014424[0-35]014424 }

condition:
	$a0
}

        
