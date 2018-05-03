rule Win_Worm_Scano_56
{
strings:
	$a0 = { 2d625d122020da4c42ee9442e860b67cfc6b0ed4d74a3c86b5bddccaad2a1436f48a565022f21d88dfaf461593c8bda8861aa51647cf52ab2cfcc5da086d3ad420f5159e27cecae487de659ce8f47d97d6e117b8620838dbb6 }

condition:
	$a0
}

        
