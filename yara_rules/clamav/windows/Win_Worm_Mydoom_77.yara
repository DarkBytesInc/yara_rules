rule Win_Worm_Mydoom_77
{
strings:
	$a0 = { 609ce8000000005db8070000002be88db506feffff8a063c0074128bf58db52efeffff8a063c010f844202 }

condition:
	$a0
}

        
