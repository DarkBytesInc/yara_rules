rule Win_Worm_Intix_1
{
strings:
	$a0 = { 696e6974782e64617400000068e4c14000ff1568424100e930d4ffff000000000000 }

condition:
	$a0
}

        
