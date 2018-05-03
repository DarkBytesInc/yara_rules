rule Win_Worm_Koobface_34
{
strings:
	$a0 = { 23624c61434b6c0062456c }

condition:
	$a0
}

        
