rule Win_Worm_Stration_544
{
strings:
	$a0 = { 313a207d6a606b7d3c267c372a37520000007e0000008a8899ede8beed8599999de2fce3fcc0 }

condition:
	$a0
}

        
