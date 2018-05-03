rule Win_Worm_Hybris_17
{
strings:
	$a0 = { bb5b3becc9d9cccda88d6aa841271b7a1bed2ccb19f92e4937c42ad7a668166277e0243de199a1e22e086d85e6de048aa1f7abc1d871380618581c11e5b96d4c1a8314d09132daf4951e9784d0fa7a84 }

condition:
	$a0
}

        
