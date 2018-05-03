rule Win_Worm_Allaple_146
{
strings:
	$a0 = { c74424??????(40|41)00[0-10]8b5c24[0-20]33d2[0-5]015424[0-35]015c24[0-35]015c24 }

condition:
	$a0
}

        
