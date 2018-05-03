rule Win_Worm_Koobface_48
{
strings:
	$a0 = { 23424c616300000042656c }

condition:
	$a0
}

        
