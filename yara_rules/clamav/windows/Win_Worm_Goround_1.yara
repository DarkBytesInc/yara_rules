rule Win_Worm_Goround_1
{
strings:
	$a0 = { 8d45e8b9ecf541008b55fce85452feff8b45e8e8e4feffff }

condition:
	$a0
}

        
