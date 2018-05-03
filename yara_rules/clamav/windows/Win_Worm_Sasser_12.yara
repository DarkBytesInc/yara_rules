rule Win_Worm_Sasser_12
{
strings:
	$a0 = { 5c0050004900500045005c }
	$a1 = { 633a5c77696e2e6c6f67[0-62]4a6f62616b61336c[0-49]5c52756e }

condition:
	$a0 and $a1
}

        
