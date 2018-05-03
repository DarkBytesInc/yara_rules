rule Win_Worm_Koobface_31
{
strings:
	$a0 = { 25736162656c000023626c61636b6c }

condition:
	$a0
}

        
