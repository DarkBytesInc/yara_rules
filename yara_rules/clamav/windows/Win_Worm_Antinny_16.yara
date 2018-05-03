rule Win_Worm_Antinny_16
{
strings:
	$a0 = { 8d55d0b902000000b858754400e8171bfcff }

condition:
	$a0
}

        
