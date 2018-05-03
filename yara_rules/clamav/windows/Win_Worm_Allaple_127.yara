rule Win_Worm_Allaple_127
{
strings:
	$a0 = { c74424??????(40|41)00[0-10]8b4c24[0-20]33db[0-5]015c24[0-35]015424[0-35]015c24 }

condition:
	$a0
}

        
