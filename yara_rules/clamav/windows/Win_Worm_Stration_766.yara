rule Win_Worm_Stration_766
{
strings:
	$a0 = { dd95655fc4bdcd7714da0d12c987d3bd8a882da03a98611cad6b57d84d9920f49c806bea37553fa3ab48e73ed0e889f961263fc3790fbb82e37e21e7a1529d2fadf37cb9e39342be6d8e4aa0b7ae57ae7491e8ba0a9adbd80a }

condition:
	$a0
}

        
