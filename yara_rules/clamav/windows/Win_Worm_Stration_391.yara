rule Win_Worm_Stration_391
{
strings:
	$a0 = { 5dd9a554509c3c6c8c5b3c93ee3ad4f05747e4e81954047367783669c2088829533fcbb6399c8f83f29a0369f3c7b6a1a33739d9633cda7d4a83f9e3c84591f9 }

condition:
	$a0
}

        
