rule Win_Worm_Allaple_291
{
strings:
	$a0 = { c74424??????(40|41)00[0-10]8b7c24[0-20]33db[0-5]0401(5c|4c|44|54)24[0-35]015424[0-36]015c24 }

condition:
	$a0
}

        
