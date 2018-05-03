rule Win_Tool_Nobuho_1
{
strings:
	$a0 = { b208bd1c02cd10b400cd1680fc017503e998001e06b82135cd212e891ee7012e8c06e901c51e }

condition:
	$a0
}

        
