rule Win_Worm_Caser_1
{
strings:
	$a0 = { 6f75746c6f6f6b656d61696c[0-12]2e6164642077696e646972202620225c22202620656d6c66696c65 }

condition:
	$a0
}

        
