rule Win_Worm_Koobface_46
{
strings:
	$a0 = { 23426c416300000042654c }

condition:
	$a0
}

        
