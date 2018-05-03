rule Win_Worm_Agent_35874
{
strings:
	$a0 = { e8040000000000000058833800751fff00ff742410ff742410ff742410ff742410e8f340fdff83 }

condition:
	$a0
}

        
