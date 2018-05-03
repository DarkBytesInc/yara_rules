rule Win_Worm_Allaple_155
{
strings:
	$a0 = { c74424??????(40|41)00[0-10]8b4c24[0-20]33d2[0-5]015424[0-35]015424[0-35]014424 }

condition:
	$a0
}

        
