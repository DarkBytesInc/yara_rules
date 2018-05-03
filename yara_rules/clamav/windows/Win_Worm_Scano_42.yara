rule Win_Worm_Scano_42
{
strings:
	$a0 = { a3f1c53db8eea9f1a7401f0c2d625d122020da4c42ee9442e860b67cfc6b0ed4d74a3c86b5bddccaad2a1436f48a565022f21d88dfaf461593c8bda8861aa51647cf52ab2cfcc5da086d3ad420f5159e27cecae487de659ce8 }

condition:
	$a0
}

        
