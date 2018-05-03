rule Win_Worm_Hopalon_1
{
strings:
	$a0 = { 64656c20633a5c6c6f676f2e737973 }
	$a1 = { 6465627567203c20633a5c }
	$a2 = { 5c706b756e7a69702e646267 }

condition:
	$a0 and $a1 and $a2
}

        
