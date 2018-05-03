rule Win_Worm_Koobface_40
{
strings:
	$a0 = { 424c41434b4c4142454c }

condition:
	$a0
}

        
