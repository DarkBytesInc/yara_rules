rule Win_Worm_Locksky_43
{
strings:
	$a0 = { 68f01140008124240000f0ff0fdfcad9f08d00590fdbe49b31d20fd5e10fdbc8db042481c2001e00008d36da142401ca90 }

condition:
	$a0
}

        
