rule Win_Worm_Downadup_1
{
strings:
	$a0 = { 8d3c9bc1e703897c2430ff15000040d08b0d0001339c01cf8b150000505401fa8b44242c03d08b44240c03c28b0d0001 }

condition:
	$a0
}

        
