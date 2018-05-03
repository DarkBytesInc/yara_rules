rule Win_Worm_Mydoom_87
{
strings:
	$a0 = { e9db0200000d0a445341674446676466674024355977243553594835575e3372 }

condition:
	$a0
}

        
