rule Win_Worm_Romeo_2
{
strings:
	$a0 = { c7ad193b3990f4a8100cd6f1c6e5895c895b6f1beb3acf4308d22dd4d1137e5ae32c373ce7edc1e07c0d250c1c843217a15c358381bd1d052d1709dbecb30a607e }

condition:
	$a0
}

        
