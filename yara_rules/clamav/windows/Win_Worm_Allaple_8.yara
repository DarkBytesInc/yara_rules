rule Win_Worm_Allaple_8
{
strings:
	$a0 = { c74424??????(40|41)00[0-10]8b5424[0-20]33db[0-5]015c24[0-35]015c24[0-35]014424 }

condition:
	$a0
}

        