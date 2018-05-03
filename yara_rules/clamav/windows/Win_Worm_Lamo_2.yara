rule Win_Worm_Lamo_2
{
strings:
	$a0 = { 687438410068f0e04000ff155c1040008bd08d4dccff1538124000 }

condition:
	$a0
}

        
