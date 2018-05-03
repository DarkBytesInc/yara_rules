rule Win_Worm_Spth_7
{
strings:
	$a0 = { 2e636f707966696c65282267777277612e6a73222c66786d69772b225c5c676f646b6e6f772229 }

condition:
	$a0
}

        
