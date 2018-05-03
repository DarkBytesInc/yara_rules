rule Win_Worm_Livra_1
{
strings:
	$a0 = { 83c40885c0741d8b45f86bc01c8b4df481bc886caa42001c7042007407c745fc01000000 }

condition:
	$a0
}

        
