rule Win_Worm_Koobface_41
{
strings:
	$a0 = { 23426c41434b6c0062456c }

condition:
	$a0
}

        
