rule Win_Worm_Koobface_42
{
strings:
	$a0 = { 23424c61634b6c }

condition:
	$a0
}

        
