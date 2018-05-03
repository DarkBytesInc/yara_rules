rule Win_Worm_Koobface_32
{
strings:
	$a0 = { 23624c61636b6c0062456c }

condition:
	$a0
}

        
