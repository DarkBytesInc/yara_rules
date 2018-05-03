rule Win_Worm_Autorun_436
{
strings:
	$a0 = { 50535183c9865256570f85770100006d17dfe179c4dc1b7fdd56a537efae2c2f }

condition:
	$a0
}

        
