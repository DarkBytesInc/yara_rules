rule Win_Worm_Koobface_76
{
strings:
	$a0 = { 686b6c257366747761[0-16]6e74766525737663686f73257376 }
	$a1 = { 5c64722573735c25732e[0-16]732e6425730000006c6c }

condition:
	$a0 and $a1
}

        
