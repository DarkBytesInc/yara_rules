rule Win_Worm_Alcaul_22
{
strings:
	$a0 = { 7733322e6d696d6565004d494d452045646974000050726f6a6563743100 }

condition:
	$a0
}

        
