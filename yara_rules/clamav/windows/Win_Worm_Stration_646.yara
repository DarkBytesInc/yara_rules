rule Win_Worm_Stration_646
{
strings:
	$a0 = { 2f322f4a37272e6578650b5c0fffff3fff8898d7d0cb9888a51e3b2f2a3f2e6b383e28282e38382d3e272732f7ffbffd6b222538 }

condition:
	$a0
}

        
