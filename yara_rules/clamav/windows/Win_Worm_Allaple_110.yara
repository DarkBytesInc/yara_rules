rule Win_Worm_Allaple_110
{
strings:
	$a0 = { c74424??????(40|41)00[0-10]8b5c24[0-20]33c9[0-5]0401(5c|4c|44|54)24[0-35]015c24[0-35]015c24 }

condition:
	$a0
}

        
