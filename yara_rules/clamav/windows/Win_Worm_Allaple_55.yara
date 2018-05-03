rule Win_Worm_Allaple_55
{
strings:
	$a0 = { c74424??????(40|41)00[0-10]8b5c24[0-20]33db[0-5]015c24[0-35]014424[0-35]014424 }

condition:
	$a0
}

        
