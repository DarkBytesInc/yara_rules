rule Win_Worm_Antinny_8
{
strings:
	$a0 = { b8447444008945e8b8887444008945ec8d45e88d4df0ba01000000e80ab4ffff }

condition:
	$a0
}

        
