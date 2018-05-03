rule Win_Worm_Koobface_45
{
strings:
	$a0 = { 23424c61634b000042656c }

condition:
	$a0
}

        
