rule Win_Worm_Koobface_47
{
strings:
	$a0 = { 23626c416300000042654c }

condition:
	$a0
}

        
