rule Win_Worm_Koobface_39
{
strings:
	$a0 = { 23426c41636b6c0062456c }

condition:
	$a0
}

        
