rule Win_Worm_Koobface_35
{
strings:
	$a0 = { 23424c41434b4c4142454c }

condition:
	$a0
}

        
