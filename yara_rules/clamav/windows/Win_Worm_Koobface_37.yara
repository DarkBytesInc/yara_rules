rule Win_Worm_Koobface_37
{
strings:
	$a0 = { 7477690074746572 }
	$a1 = { 6641436500000000626f }
	$a2 = { 504f5354 }
	$a3 = { 23426c41636b6c }
	$a4 = { 4700450054 }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}

        
