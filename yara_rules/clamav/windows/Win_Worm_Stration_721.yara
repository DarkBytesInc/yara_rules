rule Win_Worm_Stration_721
{
strings:
	$a0 = { 8b44240883e8007414487529ff742404ff1524100010e8c3feffffeb18 }

condition:
	$a0
}

        
