rule Win_Worm_Stration_341
{
strings:
	$a0 = { 11c6d9dc13913faef63e60d3ccb8537811b7a55d0957377034b40342426f9ccb75ffbf4fd3a3eb71ba918d636876528cd7da01437db76a5dbee4b87fff0e2cfcb28076ee62aaadffef0fd7e84ad1d54b }

condition:
	$a0
}

        
